/*
 * NanoDNS server
 * Copyright (C) 2020  Jan Klötzke
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "daemon.h"
#include "db.h"
#include "dns.h"
#include "list.h"
#include "log.h"
#include "pkt.h"
#include "poll.h"
#include "utils.h"

struct dns_tcp_client
{
	uint8_t qbuf[MAX_DGRAM_SIZE];
	uint8_t rbuf[MAX_DGRAM_SIZE];
	unsigned qlen, rlen;

	int fd;
	struct poll_source *io;
	struct poll_source *idle_timer;
	struct list_node server_node;
	struct dns_server *server;

	struct sockaddr_in6 addr;
};

struct dns_listen
{
	struct list_node server_node;
	struct poll_source *ps;
};

struct dns_server
{
	struct poll_set *ps;
	LIST_HEAD(struct dns_listen, server_node) listen_sources;
	LIST_HEAD(struct dns_tcp_client, server_node) clients;
	unsigned max_clients, num_clients;

        // RFC7873
	uint8_t cur_secret[16];
	uint8_t old_secret[16];
	bool old_secret_valid;
	struct poll_source *secret_rollover;
	struct poll_source *secret_invalidate;

        // rate limiting
	uint32_t rate_limit;
	uint32_t rate_last_hit;
	uint32_t rate_count[256];
	struct poll_source *rate_timer;
};


static const char *dns_rcode2str(enum rcode rcode)
{
        switch (rcode) {
	case RCODE_NO_ERROR: return "NOERROR";
	case RCODE_FORMAT_ERROR: return "FORMERR";
	case RCODE_SERVER_FAILURE: return "SERVFAIL";
	case RCODE_NAME_ERROR: return "NXDOMAIN";
	case RCODE_NOT_IMPLEMENTED: return "NOTIMP";
	case RCODE_REFUSED: return "REFUSED";
	case RCODE_BADVERS: return "BADVERS";
	case RCODE_BADCOOKIE: return "BADCOOKIE";
        }

        return "<invalid>";
}

static const char *dns_type2str(enum type type)
{
        switch (type) {
	case TYPE_A: return "A";
	case TYPE_NS: return "NS";
	case TYPE_CNAME: return "CNAME";
	case TYPE_SOA: return "SOA";
	case TYPE_MX: return "MX";
	case TYPE_TXT: return "TXT";
	case TYPE_AAAA: return "AAAA";
	case TYPE_OPT: return "OPT";
	case TYPE_Q_ALL: return "ALL";
        }

	static char tmp[16];
	snprintf(tmp, sizeof(tmp), "TYPE%d", type);
        return tmp;
}

static const char *dns_cls2str(enum cls cls)
{
        switch (cls) {
	case CLASS_IN: return "IN";
	case CLASS_Q_ANY: return "ANY";
	}

        return "<unsupported>";
}


struct dns_rr *dns_rr_new(char name[MAX_NAME_SIZE+1], enum type type, uint32_t ttl)
{
	struct dns_rr *ret = calloc(1, sizeof(struct dns_rr));
	if (ret) {
		strcpy(ret->name, name);
		ret->type = type;
		ret->ttl = ttl;
	}
	return ret;
}

void dns_rr_delete(struct dns_rr **r)
{
	struct dns_rr *d = *r;
	*r = NULL;

	while (d) {
		struct dns_rr *n = d->next;
		free(d);
		d = n;
	}
}

void dns_rr_add(struct dns_rr **anchor, struct dns_rr *n)
{
	if (n) {
		n->next = *anchor;
		*anchor = n;
	}
}

static uint16_t dns_rr_count(struct dns_rr *r)
{
	uint16_t ret = 0;

	while (r) {
		ret++;
		r = r->next;
	}

	return ret;
}

static int dns_rr_dump(struct dns_rr *r, struct pkt *pkt)
{
	int ret;

	for (; r; r = r->next) {
		if ((ret = pkt_put_name(pkt, r->name)) < 0)
			return ret;
		if ((ret = pkt_put_uint16(pkt, (uint16_t)r->type)) < 0)
			return ret;
		if ((ret = pkt_put_uint16(pkt, CLASS_IN)) < 0)
			return ret;
		if ((ret = pkt_put_uint32(pkt, r->ttl)) < 0)
			return ret;

		size_t rdlen_off = pkt->idx;
		if ((ret = pkt_put_uint16(pkt, 0)) < 0)
			return ret;

		switch (r->type) {
		case TYPE_A:
			if ((ret = pkt_put_blob(pkt, r->u.a, 4)) < 0)
				return ret;
			break;
		case TYPE_AAAA:
			if ((ret = pkt_put_blob(pkt, r->u.aaaa, 16)) < 0)
				return ret;
			break;
		case TYPE_NS:
			if ((ret = pkt_put_name(pkt, r->u.ns)) < 0)
				return ret;
			break;
		case TYPE_SOA:
			if ((ret = pkt_put_name(pkt, r->u.soa.mname)) < 0)
				return ret;
			if ((ret = pkt_put_name(pkt, r->u.soa.rname)) < 0)
				return ret;
			if ((ret = pkt_put_uint32(pkt, r->u.soa.serial)) < 0)
				return ret;
			if ((ret = pkt_put_uint32(pkt, r->u.soa.refresh)) < 0)
				return ret;
			if ((ret = pkt_put_uint32(pkt, r->u.soa.retry)) < 0)
				return ret;
			if ((ret = pkt_put_uint32(pkt, r->u.soa.expire)) < 0)
				return ret;
			if ((ret = pkt_put_uint32(pkt, r->u.soa.minimum)) < 0)
				return ret;
			break;
		default:
			return -EINVAL;
		}

		pkt_or_uint16(pkt, rdlen_off, pkt->idx - rdlen_off - 2);
	}

	return 0;
}


/**
 * Calculate server secret for client.
 *
 * Calculated according to RFC7873 B.1. but with SHA256 instead of FNV64. If
 * "old" is true then the old secret is used. This might fail with -ENOENT if
 * the old secret is not valid anymore.
 */
static int dns_cookie_generate(struct dns_server *server,
	struct dns_cookie *server_cookie, struct in6_addr *from,
	struct dns_cookie *client_cookie, bool old)
{
	SHA256_CTX ctx;
	unsigned char hash[32];

	if (old && !server->old_secret_valid)
		return -ENOENT;

	if (!SHA256_Init(&ctx))
		return -EIO;
	if (!SHA256_Update(&ctx, from, sizeof(*from)))
		return -EIO;
	if (!SHA256_Update(&ctx, client_cookie, sizeof(*client_cookie)))
		return -EIO;
	if (!SHA256_Update(&ctx, old ? server->old_secret : server->cur_secret,
	                   sizeof(server->cur_secret)))
		return -EIO;
	if (!SHA256_Final(hash, &ctx))
		return -EIO;

	memcpy(server_cookie, hash, sizeof(*server_cookie));
	return 0;
}

static void dns_cookie_copy(struct dns_cookie *dst, struct dns_cookie *src)
{
	memcpy(dst, src, sizeof(*dst));
}

static int dns_cookie_cmp(struct dns_cookie *lhs, struct dns_cookie *rhs)
{
	return memcmp(lhs, rhs, sizeof(*lhs));
}


static struct dns_query *dns_query_new(void)
{
	struct dns_query *q = calloc(1, sizeof(struct dns_query));
	q->udp_reply_size = 512;
	return q;
}

static void dns_query_delete(struct dns_query **q)
{
	if (*q)
		free(*q);
	*q = NULL;
}

static struct dns_query *dns_query_err(struct dns_query *q, enum rcode err)
{
	q->err = err;
	return q;
}

static int dns_query_parse_opt(struct pkt *pkt, struct dns_query *query,
        uint16_t class, uint32_t ttl, uint16_t rdlen)
{
        // The OPT wire format is described in RFC6891 6.1.2. There
        // must be at most one OPT-RR. Otherwise a FORMERR must be
        // returned (6.1.1.)
        if (query->edns)
                return -RCODE_FORMAT_ERROR;
        query->edns = 1U;

        // RFC6891 6.2.3.: Values lower than 512 MUST be treated as
        // equal to 512.
        query->udp_reply_size = (class > 512U) ? class : 512U;

        // We only support Version 0
        if (((ttl >> 16) & 0xffU) != 0U)
                return -RCODE_BADVERS;

        // Parse individual options
        int ret, remain = rdlen;
        while (remain > 0) {
                uint16_t code, len;
                if ((ret = pkt_get_uint16(pkt, &code)) < 0)
                        return -RCODE_FORMAT_ERROR;
                remain -= ret;
                if ((ret = pkt_get_uint16(pkt, &len)) < 0)
                        return -RCODE_FORMAT_ERROR;
                remain -= ret;

                switch (code) {
                case EDNS_OPT_COOKIE:
                        // Check for malformed cookie (RFC7873 5.2.2.)
                        if (len < 8 || (len > 8 && len < 16) || len > 40)
                                return -RCODE_FORMAT_ERROR;

                        query->cc_present = 1;
                        if ((ret = pkt_get_blob(pkt, &query->client_cookie, 8)) < 0)
                                return -RCODE_FORMAT_ERROR;
                        remain -= ret;
                        len -= 8;

                        if (len == 8U) {
                                query->sc_present = 1;
                                if ((ret = pkt_get_blob(pkt, &query->server_cookie, len)) < 0)
                                        return -RCODE_FORMAT_ERROR;
                        } else {
                                // Not our server cookie size -> invalid.
                                // Handle as if not present (RFC7873 5.2.4.)
                                if ((ret = pkt_skip_octets(pkt, len)) < 0)
                                        return -RCODE_FORMAT_ERROR;
                        }
                        remain -= ret;
                        break;
                default:
                        if ((ret = pkt_skip_octets(pkt, len)) < 0)
                                return -RCODE_FORMAT_ERROR;
                        remain -= ret;
                }
        }

        if (remain != 0)
                return -RCODE_FORMAT_ERROR;

        return 0;
}

// RFC1035 4.1.
static struct dns_query *dns_query_parse(struct pkt *query)
{
	uint16_t id = 0, flags;
	uint16_t qd_count, an_count, ns_count, ar_count;
	uint16_t qtype, qclass;
	int ret;

	// Essential headers that are required to send a reply at all
	if (pkt_get_uint16(query, &id) < 0)
		return NULL;
	if (pkt_get_uint16(query, &flags) < 0)
		return NULL;

	// Silently drop answers
	if (flags & (1u << 15))
		return NULL;

	// We have enough information to send at least an error response
	struct dns_query *q = dns_query_new();
	if (!q)
		return dns_query_err(q, RCODE_FORMAT_ERROR);
	q->id = id;
	q->opcode = (flags >> 11) & 0x0fu;
	q->rd = (flags >> 8) & 1u;

	// get section couters
	if (pkt_get_uint16(query, &qd_count) < 0)
		return dns_query_err(q, RCODE_FORMAT_ERROR);
	if (pkt_get_uint16(query, &an_count) < 0)
		return dns_query_err(q, RCODE_FORMAT_ERROR);
	if (pkt_get_uint16(query, &ns_count) < 0)
		return dns_query_err(q, RCODE_FORMAT_ERROR);
	if (pkt_get_uint16(query, &ar_count) < 0)
		return dns_query_err(q, RCODE_FORMAT_ERROR);

        // We're expecting zero or exactly one query. A zero query can be used
        // according to RFC7873 5.4 by a client to obtain just the server
        // cookie.
	if (qd_count > 1)
		return dns_query_err(q, RCODE_FORMAT_ERROR);

	// parse query
	if (qd_count == 1) {
		if (pkt_get_name(query, q->name) < 0)
			return dns_query_err(q, RCODE_FORMAT_ERROR);
		if (pkt_get_uint16(query, &qtype) < 0)
			return dns_query_err(q, RCODE_FORMAT_ERROR);
		q->type = (enum type)qtype;
		if (pkt_get_uint16(query, &qclass) < 0)
			return dns_query_err(q, RCODE_FORMAT_ERROR);
		q->cls = (enum cls)qclass;
		q->question = 1U;
	}

	// Skip any answer or authority records. They should not be in a query
	// but who knowns...
	for (unsigned i = 0; i < an_count+ns_count; i++) {
		if (pkt_skip_rr(query) < 0)
			return dns_query_err(q, RCODE_FORMAT_ERROR);
	}

	// Skim through additional RRs.
	for (unsigned i = 0; i < ar_count; i++) {
		uint16_t type, class, rdlen;
		uint32_t ttl;

		if (pkt_get_name(query, NULL) < 0)
			return dns_query_err(q, RCODE_FORMAT_ERROR);
		if (pkt_get_uint16(query, &type) < 0)
			return dns_query_err(q, RCODE_FORMAT_ERROR);
		if (pkt_get_uint16(query, &class) < 0)
			return dns_query_err(q, RCODE_FORMAT_ERROR);
		if (pkt_get_uint32(query, &ttl) < 0)
			return dns_query_err(q, RCODE_FORMAT_ERROR);
		if (pkt_get_uint16(query, &rdlen) < 0)
			return dns_query_err(q, RCODE_FORMAT_ERROR);

		// We are only interested in OPT pseudo RRs. Skip everything else.
		switch (type) {
	        case TYPE_OPT:
	                ret = dns_query_parse_opt(query, q, class, ttl, rdlen);
	                if (ret < 0)
				return dns_query_err(q, -ret);
			break;
	        default:
			if (pkt_skip_octets(query, rdlen) < 0)
				return dns_query_err(q, RCODE_FORMAT_ERROR);
		}
	}

	return q;
}

static int dns_query_dump(struct dns_query *query, struct pkt *pkt)
{
	int ret;

	if ((ret = pkt_put_name(pkt, query->name)) < 0)
		return ret;
	if ((ret = pkt_put_uint16(pkt, (uint16_t)query->type)) < 0)
		return ret;
	return pkt_put_uint16(pkt, (uint16_t)query->cls);
}

static struct dns_reply *dns_reply_new(enum rcode rcode, bool udp)
{
	struct dns_reply *ret = calloc(1, sizeof(struct dns_reply));
	if (ret) {
		ret->rcode = rcode;
		ret->rate_limit = udp ? 1U : 0U;
		ret->max_size = udp ? 512U : UINT16_MAX;
	}
	return ret;
}

static void dns_reply_delete(struct dns_reply **r)
{
	struct dns_reply *d = *r;
	*r = NULL;

	if (d) {
		dns_rr_delete(&d->answer);
		dns_rr_delete(&d->authority);
		free(d);
	}
}

static int dns_reply_dump_edns(struct dns_reply *reply, struct pkt *pkt)
{
	int ret;

	// RFC6891 6.1.2.
	if ((ret = pkt_put_name(pkt, ".")) < 0)
		return ret;
	if ((ret = pkt_put_uint16(pkt, 41)) < 0)
		return ret;
	if ((ret = pkt_put_uint16(pkt, MAX_DGRAM_SIZE)) < 0)
		return ret;

	// RFC6891 6.1.3.
	if ((ret = pkt_put_uint16(pkt, (reply->rcode >> 4) << 8)) < 0)
		return ret;
	if ((ret = pkt_put_uint16(pkt, 0)) < 0)
		return ret;

	// RFC6891 6.1.2.
	if ((ret = pkt_put_uint16(pkt, reply->cookies ? 4+16 : 0)) < 0)
		return ret;

	// RFC7873 4.
	if (reply->cookies) {
		if ((ret = pkt_put_uint16(pkt, 10)) < 0)
			return ret;
		if ((ret = pkt_put_uint16(pkt, 16)) < 0)
			return ret;
		if ((ret = pkt_put_blob(pkt, &reply->client_cookie, 8)) <  0)
			return ret;
		if ((ret = pkt_put_blob(pkt, &reply->server_cookie, 8)) <  0)
			return ret;
	}

	return 0;
}

static int dns_reply_dump(struct dns_query *query, struct dns_reply *reply,
		struct pkt *pkt)
{
	int ret;
	// RFC1035 4.1.1.
	uint16_t flags = (1u << 15) |
		((uint16_t)query->opcode << 11) |
		(uint16_t)(reply->rcode & 0x0f);

	if (query->opcode == OP_QUERY) {
		flags |= 1U << 10; // Authoritative Answer
		flags |= (uint16_t)query->rd << 8; // Recursion Desired
	}

	bool edns = reply->edns || reply->cookies || reply->rcode > 15;

	if ((ret = pkt_put_uint16(pkt, query->id)) < 0)
		return ret;
	if ((ret = pkt_put_uint16(pkt, flags)) < 0)
		return ret;
	if ((ret = pkt_put_uint16(pkt, query->question ? 1 : 0)) < 0)
		return ret;
	if ((ret = pkt_put_uint16(pkt, dns_rr_count(reply->answer))) < 0)
		return ret;
	if ((ret = pkt_put_uint16(pkt, dns_rr_count(reply->authority))) < 0)
		return ret;
	if ((ret = pkt_put_uint16(pkt, edns ? 1 : 0)) < 0)
		return ret;

	if (query->question) {
		if ((ret = dns_query_dump(query, pkt)) < 0)
			return ret;
	}

	int tc = 0;

	ret = dns_rr_dump(reply->answer, pkt);
	if (ret == -EFAULT)
		tc = 1;
	else if (ret < 0)
		return ret;

	ret = dns_rr_dump(reply->authority, pkt);
	if (ret == -EFAULT)
		tc = 1;
	else if (ret < 0)
		return ret;

	if (edns) {
		ret = dns_reply_dump_edns(reply, pkt);
		if (ret == -EFAULT)
			tc = 1;
		else if (ret < 0)
			return ret;
	}

	if (tc)
		pkt_or_uint16(pkt, 2, 1u << 9);

	return pkt->idx;
}

static int dns_process_edns(struct dns_query *query, struct dns_reply *reply, bool udp)
{
	if (!query->edns)
		return 0;

	reply->edns = 1;
	if (udp)
		reply->max_size = query->udp_reply_size;

	return 0;
}

static int dns_process_cookies(struct dns_server *server, struct dns_query *query,
	struct dns_reply *reply, struct in6_addr *from, bool udp)
{
	struct dns_cookie cookie;
	int ret;

	// RFC7873 5.2.1.
	if (!query->cc_present)
		return 0;

	// RFC7873 5.2.2. already handled by dns_query_parse()

	// generate our server cookie for this request
	ret = dns_cookie_generate(server, &cookie, from, &query->client_cookie, false);
	if (ret < 0)
		return 0; // Fall back to no cookie

	// Always reply with our cookies to establish trust
	dns_cookie_copy(&reply->client_cookie, &query->client_cookie);
	dns_cookie_copy(&reply->server_cookie, &cookie);
	reply->cookies = 1;

	if (!query->sc_present) {
		// RFC7873 5.2.3. Only a Client Cookie. We implement a strict
		// cookie policy. In case of UDP requests we always return a
		// BADCOOKIE error response. TCP requests will be processed
		// normally to prevent infinite request loops (see 5.3.).
		if (udp)
			reply->rcode = RCODE_BADCOOKIE;
	} else if (dns_cookie_cmp(&cookie, &query->server_cookie) == 0) {
		// RFC7873 5.2.5. A Client Cookie and a Valid Server Cookie
		reply->rate_limit = 0;
	} else {
		// RFC7873 5.2.4. A Client Cookie and an Invalid Server Cookie
		// Might be caused by a secret rollover. Retry with old secret
		// or treat as not present.
		ret = dns_cookie_generate(server, &cookie, from,
			&query->client_cookie, true);
		if (ret >= 0 && dns_cookie_cmp(&cookie, &query->server_cookie) == 0)
			reply->rate_limit = 0;
		else if (udp)
			reply->rcode = RCODE_BADCOOKIE;
	}

	return 0;
}

/**
 * 1s bucket refill timer.
 *
 * Rearms itself if there is at least one bucket that is still above the limit.
 * Otherwise it self destructs.
 */
static int dns_rate_limit_timer(void *ctx)
{
	struct dns_server *server = ctx;
	bool rearm = false;

	for (int i = 0; i < 256; i++) {
		if (server->rate_count[i] >= server->rate_limit)
			rearm = true;
	}

	memset(server->rate_count, 0, sizeof(server->rate_count));
	server->rate_last_hit = now_monotonic_ms();

	if (rearm) {
		log_warn("rate limit still active");
		poll_source_mod_timer(server->rate_timer, 1000);
	} else {
		poll_source_free(&server->rate_timer);
		log_warn("rate limit deactivated");
	}

	return 0;
}

/**
 * Apply rate limiting for non-authenticated requests.
 *
 * All clients are distributed to 256 buckets. The limit is counted within each
 * bucket individually.
 */
static int dns_process_ratelimit(struct dns_server *server, struct dns_reply *reply,
	struct sockaddr_in6 *from)
{
	if (!reply->rate_limit)
		return 0;

	uint8_t bucket = 0xaaU;
	for (int i = 0; i < 16; i++)
		bucket ^= from->sin6_addr.s6_addr[i];

	// assume that we never get more than 4 billion packets per second :)
	uint32_t rate = ++server->rate_count[bucket];
	if (rate < server->rate_limit)
		return 0;

	// Bucket is full. If the bucket-refill timer is already running then
	// we had hit a limit already before. Otherwise, if the last spill-over
	// happened more than one second ago we're good and just reset all
	// counters. Otherwise we drop the request and activate the 1s
	// bucket-refill timer with the remaining time.
	if (!server->rate_timer) {
		uint32_t now = now_monotonic_ms();
		if (time_before_eq(server->rate_last_hit + 1000U, now)) {
			memset(server->rate_count, 0, sizeof(server->rate_count));
			server->rate_last_hit = now;
			return 0;
		} else {
			poll_set_add_timer(server->ps, &server->rate_timer,
				server->rate_last_hit + 1000U - now,
				dns_rate_limit_timer, server);
			log_warn("%s: rate limit hit", log_ntop(from));
		}
	}

	return -EAGAIN;
}

/**
 * Process a request packet and generate a reply packet.
 *
 * @return  >0 Success - the size of the reply
 * @return ==0 Ignore request, no reply
 * @return  <0 Kick rogue client without reply
 */
static ssize_t dns_process_pkt(struct dns_server *server, uint8_t *qbuf,
	size_t qlen, uint8_t *rbuf, size_t rlen, struct sockaddr_in6 *from,
	bool udp)
{
	struct pkt qpkt, rpkt;
	ssize_t ret = 0;

	pkt_init(&qpkt, qbuf, qlen);
	struct dns_query *query = dns_query_parse(&qpkt);
	if (!query)
		return -EBADMSG; // Pure garbage

	struct dns_reply *reply = dns_reply_new(query->err, udp);
	if (!reply)
		return 0;
	if (reply->rcode != RCODE_NO_ERROR)
		goto query_reply;

	// only queries
	if (query->opcode != OP_QUERY) {
		reply->rcode = RCODE_NOT_IMPLEMENTED;
		goto query_reply;
	}

	// first process generic EDNS options
	ret = dns_process_edns(query, reply, udp);
	if (ret < 0)
		goto query_fail;
	if (reply->rcode != RCODE_NO_ERROR)
		goto query_reply;

	// handle EDNS cookies if present
	ret = dns_process_cookies(server, query, reply, &from->sin6_addr, udp);
	if (ret < 0)
		goto query_fail;
	if (reply->rcode != RCODE_NO_ERROR)
		goto query_reply;

	// Apply rate limiting
	ret = dns_process_ratelimit(server, reply, from);
	if (ret < 0)
		goto query_fail;
	if (reply->rcode != RCODE_NO_ERROR)
		goto query_reply;

	// finally query zone file
	if (query->question) {
		ret = db_query(query, reply);
		if (ret < 0)
			goto query_fail;
	} else if (!query->cc_present) {
		// RFC7873 5.4. It is permissible to send a request with an empty
		// question section but only if a client cookie was sent.
		reply->rcode = RCODE_REFUSED;
	}

query_reply:
        if (query->question)
                log_info("%s: query %c%c%c%c #%" PRIu16 " %s %s %s -> %s",
                        log_ntop(from), udp ? 'U' : 'T',
			reply->rate_limit ? 'R' : '.',
			query->cc_present ? 'C' : '.',
			query->sc_present ? 'S' : '.',
			query->id, query->name,
			dns_type2str(query->type), dns_cls2str(query->cls),
			dns_rcode2str(reply->rcode));
        else
                log_info("%s: %s query #%" PRIu16 " -> %s", log_ntop(from),
			udp ? "udp" : "tcp", query->id, dns_rcode2str(reply->rcode));
	pkt_init(&rpkt, rbuf, min(rlen, reply->max_size));
	ret = dns_reply_dump(query, reply, &rpkt);
	dns_reply_delete(&reply);

query_fail:
	dns_query_delete(&query);
	return ret;
}


static struct dns_tcp_client* dns_tcp_client_new(struct dns_server *srv)
{
	struct dns_tcp_client *client = calloc(1, sizeof(struct dns_tcp_client));
	if (!client)
		return NULL;
	list_node_init(&client->server_node);
	client->server = srv;
	client->fd = -1;

	srv->num_clients++;
	list_add_tail(&srv->clients, client);

	return client;
}

static void dns_tcp_client_delete(struct dns_tcp_client **client)
{
	if (!*client)
		return;

	if ((*client)->fd >= 0)
		shutdown((*client)->fd, SHUT_RDWR);
	poll_source_free(&(*client)->idle_timer);
	poll_source_free(&(*client)->io);
	list_node_del(&(*client)->server_node);
	(*client)->server->num_clients--;
	free(*client);
	*client = NULL;
}

static int dns_try_handle_tcp(struct dns_tcp_client *client)
{
	uint16_t len;
	int ret;

	while (client->qlen > 2 && client->rlen == 0) {
		len = peek_uint16(client->qbuf);
		if (len > MAX_DGRAM_SIZE) {
			log_warn("%s: oversized request: %" PRIu16 "B",
			        log_ntop(&client->addr), len);
			return -E2BIG;
		}
		if (client->qlen - 2 < len)
			break;

		ret = dns_process_pkt(client->server,
				client->qbuf + 2, len, client->rbuf + 2,
				sizeof(client->rbuf) - 2, &client->addr,
				false);
		client->qlen -= 2u + len;
		memmove(client->qbuf, &client->qbuf[len + 2], client->qlen);

		if (ret < 0)
			return ret;
		if (ret == 0)
			continue;

		poll_source_mod_timer(client->idle_timer, db_get_tcp_timeout());
		client->rlen = (unsigned)ret + 2u;
		poke_uint16(client->rbuf, ret);

		while (client->rlen > 0) {
			ssize_t written;
			do {
				written = write(client->fd, client->rbuf, client->rlen);
			} while (written < 0 && errno == EINTR);

			if (written < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					break;
				return -errno;
			} else if (written == 0)
				break;

			unsigned done = (unsigned)written;
			client->rlen -= done;
			memmove(client->rbuf, &client->rbuf[done], client->rlen);
		}
	}

	if (client->rlen)
		poll_source_mod_io_enable(client->io, POLL_EVENT_OUT);

	return 0;
}

static int dns_handle_tcp_client(void *ctx, int fd, poll_event_t events)
{
	struct dns_tcp_client *client = ctx;
	ssize_t len;

	if (events & (POLL_EVENT_ERR | POLL_EVENT_HUP)) {
                log_dbg("%s: disconnected", log_ntop(&client->addr));
		dns_tcp_client_delete(&client);
		return 0;
	}

	if (events & POLL_EVENT_OUT) {
		while (client->rlen > 0) {
			do {
				len = write(fd, client->rbuf, client->rlen);
			} while (len < 0 && errno == EINTR);

			if (len > 0) {
				unsigned done = (unsigned)len;
				client->rlen -= done;
				memmove(client->rbuf, &client->rbuf[done], client->rlen);
			} else if (len == 0) {
				break;
			} else if (errno == EAGAIN && errno == EWOULDBLOCK) {
				break;
			} else {
                                log_errno_warn("%s: dropped due to write fail",
                                        log_ntop(&client->addr));
				dns_tcp_client_delete(&client);
				return 0;
			}
		}

		if (client->rlen == 0)
			poll_source_mod_io_disable(client->io, POLL_EVENT_OUT);
	}

	if (events & POLL_EVENT_IN) {
		size_t avail;
		while ((avail = (sizeof(client->qbuf) - client->qlen)) > 0) {
			do {
				len = read(fd, &client->qbuf[client->qlen], avail);
			} while (len < 0 && errno == EINTR);

			if (len > 0) {
				client->qlen += (unsigned)len;
			} else if (len == 0) {
			        log_dbg("%s: disconnected",
                                        log_ntop(&client->addr));
				dns_tcp_client_delete(&client);
				return 0;
			} else if (errno == EAGAIN && errno == EWOULDBLOCK) {
				break;
			} else {
                                log_errno_warn("%s: dropped due to read fail",
                                        log_ntop(&client->addr));
				dns_tcp_client_delete(&client);
				return 0;
			}
		}

		if (client->qlen >= sizeof(client->qbuf))
			poll_source_mod_io_disable(client->io, POLL_EVENT_IN);
	}

	int ret = dns_try_handle_tcp(client);
	if (ret < 0) {
                log_warn("%s: dropped due to error: %s",
                        log_ntop(&client->addr), strerror(-ret));
		dns_tcp_client_delete(&client);
		return 0;
	}

	if (client->qlen < sizeof(client->qbuf))
		poll_source_mod_io_enable(client->io, POLL_EVENT_IN);

	return 0;
}

static int dns_handle_tcp_timeout(void *ctx)
{
	struct dns_tcp_client *client = ctx;

        log_info("%s: dropped due to idle timeout",
                log_ntop(&client->addr));
	dns_tcp_client_delete(&client);

	return 0;
}

static int dns_handle_tcp_listen(void *ctx, int listen_fd, poll_event_t events)
{
	struct dns_server *srv = ctx;
	int fd, ret;
	socklen_t addr_len;

	if (events & (POLL_EVENT_ERR | POLL_EVENT_HUP))
		return -EIO;

	while ((fd = accept(listen_fd, NULL, NULL)) >= 0) {
		if ((ret = set_non_block(fd)) < 0) {
			log_err("set_non_block failed: %d", ret);
			close(fd);
			continue;
		}

		struct dns_tcp_client *client = dns_tcp_client_new(srv);
		if (!client) {
			log_err("OOM when accepting tcp client!");
			close(fd);
			continue;
		}

		addr_len = sizeof(client->addr);
		ret = getpeername(fd, (struct sockaddr *)&client->addr, &addr_len);
		if (ret < 0) {
			log_errno_err("getpeername");
			close(fd);
			dns_tcp_client_delete(&client);
			continue;
		}

		log_dbg("%s: accepted connection", log_ntop(&client->addr));

		while (srv->num_clients > srv->max_clients) {
			struct dns_tcp_client *victim = list_pop_front(&srv->clients);
                        log_info("%s: dropped due to connection limit",
                                log_ntop(&victim->addr));
			dns_tcp_client_delete(&victim);
		}

		client->fd = fd;
		ret = poll_set_add_io(srv->ps, &client->io, fd, POLL_EVENT_IN,
			dns_handle_tcp_client, client);
		if (ret < 0) {
			log_err("poll_set_add_io failed for client: %d", ret);
			close(fd);
			dns_tcp_client_delete(&client);
			continue;
		}

		ret = poll_set_add_timer(srv->ps, &client->idle_timer, db_get_tcp_timeout(),
			dns_handle_tcp_timeout, client);
		if (ret < 0) {
			log_err("poll_set_add_timer failed: %d", ret);
			dns_tcp_client_delete(&client);
		}
	}

	if (errno != EAGAIN && errno != EWOULDBLOCK)
		log_errno_warn("accept(tcp) failed");

	return 0;
}

static int dns_create_tcp_socket(void)
{
	// create UDP IPv6 socket
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0)
		return log_errno_fatal("socket");

	// listen on IPv4 too
	int no = 0;
	int ret = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof(no));
	if (ret < 0) {
		close(fd);
		return log_errno_fatal("setsockopt(IPV6_V6ONLY)");
	}

	// bind to port
	struct sockaddr_in6 sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin6_family = AF_INET6;
	sa.sin6_port = htons(db_get_tcp_port());
	//sa.sin6_addr = IN6ADDR_ANY_INIT;
	ret = bind(fd, (struct sockaddr *)&sa, sizeof(sa));
	if (ret < 0) {
		close(fd);
		return log_errno_fatal("bind");
	}

	ret = listen(fd, 8);
	if (ret < 0) {
		close(fd);
		return log_errno_fatal("listen");
	}

	// print ephemeral port if we used one
	if (db_get_tcp_port() == 0) {
		struct sockaddr_in6 sa;
		socklen_t sa_len = sizeof(sa);
		ret = getsockname(fd, (struct sockaddr *)&sa, &sa_len);
		if (ret < 0) {
			close(fd);
			return log_errno_fatal("getsockname");
		}
		fprintf(stderr, "tcp %d\n", ntohs(sa.sin6_port));
	}

	return fd;
}

static int dns_handle_udp(void *ctx, int fd, poll_event_t events)
{
	struct dns_server *server = ctx;
	uint8_t qbuf[MAX_DGRAM_SIZE];
	uint8_t rbuf[MAX_DGRAM_SIZE];
	ssize_t ret;
	struct sockaddr_in6 from;
	socklen_t from_len;

	if (events & (POLL_EVENT_ERR | POLL_EVENT_HUP))
		return -EIO;

	for (;;) {
		do {
			from_len = sizeof(from);
			ret = recvfrom(fd, qbuf, sizeof(qbuf), MSG_TRUNC,
				(struct sockaddr *)&from, &from_len);
		} while (ret < 0 && errno == EINTR);

		if (ret < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			if (errno == ENOMEM) {
				log_warn("recvfrom oom");
				continue;
			}

			return log_errno_fatal("recvfrom");
		}

		if (ret == 0)
			continue;

		size_t len = (size_t)ret;
		if (len > sizeof(qbuf)) {
			log_dbg("truncated packet: %zu > %zu", len, sizeof(qbuf));
			continue;
		}

		ret = dns_process_pkt(server, qbuf, len, rbuf, sizeof(rbuf),
			&from, true);
		if (ret <= 0) {
			log_warn("%s: dropped due to error: %s",
				log_ntop(&from), strerror(-ret));
			continue;
		}

		len = (size_t)ret;
		do {
			ret = sendto(fd, rbuf, len, 0, (struct sockaddr *)&from,
				from_len);
		} while (ret < 0 && errno == EINTR);

		if (ret < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK ||
			    errno == EMSGSIZE || errno == ENOMEM) {
				log_errno_warn("reply dropped");
				continue;
			}
			return log_errno_fatal("sendto");
		} else if ((size_t)ret < len) {
			log_warn("reply truncated: %zd < %zu", ret, len);
		}
	}

	return 0;
}

static int dns_create_udp_socket(void)
{
	// create UDP IPv6 socket
	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0)
		return log_errno_fatal("socket");

	// listen on IPv4 too
	int no = 0;
	int ret = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof(no));
	if (ret < 0) {
		close(fd);
		return log_errno_fatal("setsockopt(IPV6_V6ONLY)");
	}

	// bind to port
	struct sockaddr_in6 sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin6_family = AF_INET6;
	sa.sin6_port = htons(db_get_udp_port());
	//sa.sin6_addr = IN6ADDR_ANY_INIT;
	ret = bind(fd, (struct sockaddr *)&sa, sizeof(sa));
	if (ret < 0) {
		close(fd);
		return log_errno_fatal("bind");
	}

	// print ephemeral port if we used one
	if (db_get_udp_port() == 0) {
		struct sockaddr_in6 sa;
		socklen_t sa_len = sizeof(sa);
		ret = getsockname(fd, (struct sockaddr *)&sa, &sa_len);
		if (ret < 0) {
			close(fd);
			return log_errno_fatal("getsockname");
		}
		fprintf(stderr, "udp %d\n", ntohs(sa.sin6_port));
	}

	return fd;
}

static struct dns_listen *dns_listen_new(struct dns_server *srv)
{
	struct dns_listen *l = calloc(1, sizeof(struct dns_listen));
	if (!l)
		return NULL;
	list_node_init(&l->server_node);
	list_add_tail(&srv->listen_sources, l);

	return l;
}

static void dns_listen_delete(struct dns_listen **l)
{
	if (!*l)
		return;
	list_node_del(&(*l)->server_node);
	poll_source_free(&(*l)->ps);
	free(*l);
	*l = NULL;
}

static int dns_server_secret_invalidate(void *ctx)
{
	struct dns_server *server = ctx;
	server->old_secret_valid = 0;
	memset(server->old_secret, 0, sizeof(server->old_secret));
	poll_source_free(&server->secret_invalidate);
        log_info("old cookie invalidated");
	return 0;
}

/**
 * Generate new server secret.
 *
 * The old secret is temporarily kept to authenticate requests that were still
 * sent with the old secret. The old secret is finally thrown away after
 * SECRET_INVALIDATE milliseconds.
 *
 * RFC7873 7.1.
 */
static int dns_server_secret_rollover(void *ctx)
{
	struct dns_server *server = ctx;
	int ret;

	memcpy(server->old_secret, server->cur_secret, sizeof(server->old_secret));
	server->old_secret_valid = 1;
	ret = poll_set_add_timer(server->ps, &server->secret_invalidate,
		SECRET_INVALIDATE, dns_server_secret_invalidate, server);
	if (ret < 0)
		return ret;

	if (RAND_bytes(server->cur_secret, sizeof(server->cur_secret)) <= 0) {
		log_err("Failed to fetch random data");
		return -EIO;
	}

        log_info("DNS server cookie secret refreshed");

	return poll_source_mod_timer(server->secret_rollover, SECRET_ROLLOVER);
}

struct dns_server* dns_server_new(struct poll_set *ps)
{
	int fd, ret;
	struct dns_server *srv;
	unsigned i;

	srv = calloc(1, sizeof(struct dns_server));
	if (!srv)
		return NULL;
	list_init(&srv->listen_sources);
	list_init(&srv->clients);
	srv->ps = ps;
	srv->max_clients = db_get_tcp_connections();

	/*
	 * DNS cookies. See RFC7873 7.
	 */
	if (RAND_bytes(srv->cur_secret, sizeof(srv->cur_secret)) <= 0) {
		log_err("Failed to fetch random data");
		goto fail;
	}
	if (poll_set_add_timer(srv->ps, &srv->secret_rollover, SECRET_ROLLOVER,
	                       dns_server_secret_rollover, srv) < 0) {
		log_err("secret timer");
		goto fail;
	}
	srv->rate_limit = db_get_rate_limit();
	srv->rate_last_hit = now_monotonic_ms();

	/*
	 * TCP
	 */
	i = 0;
	fd = daemon_get_dns_tcp_socket(i);
	if (fd < 0)
		fd = dns_create_tcp_socket();
	if (fd < 0)
		goto fail;

	do {
		struct dns_listen *lps = dns_listen_new(srv);
		if (!lps) {
			log_err("OOM");
			goto fail;
		}

		// make non-blocking
		ret = set_non_block(fd);
		if (ret < 0) {
			close(fd);
			goto fail;
		}

		// Add to event loop. Takes ownership of file descriptor.
		ret = poll_set_add_io(ps, &lps->ps, fd, POLL_EVENT_IN,
			dns_handle_tcp_listen, srv);
		if (ret < 0) {
			close(fd);
			log_fatal("poll_set_add_io(tcp) failed: %d", ret);
			goto fail;
		}
	} while ((fd = daemon_get_dns_tcp_socket(++i)) >= 0);

	/*
	 * UDP
	 */

	i = 0;
	fd = daemon_get_dns_udp_socket(i);
	if (fd < 0)
		fd = dns_create_udp_socket();
	if (fd < 0)
		goto fail;

	do {
		struct dns_listen *lps = dns_listen_new(srv);
		if (!lps) {
			log_err("OOM");
			goto fail;
		}

		// make non-blocking
		ret = set_non_block(fd);
		if (ret < 0) {
			close(fd);
			goto fail;
		}

		// Add to event loop. Takes ownership of file descriptor.
		ret = poll_set_add_io(ps, &lps->ps, fd, POLL_EVENT_IN,
			dns_handle_udp, srv);
		if (ret < 0) {
			close(fd);
			log_fatal("poll_set_add_io(udp) failed: %d", ret);
			goto fail;
		}
	} while ((fd = daemon_get_dns_udp_socket(++i)) >= 0);

	return srv;

fail:
	list_for_each_safe(srv->listen_sources, i)
		dns_listen_delete(&i);
	poll_source_free(&srv->secret_rollover);
	free(srv);
	return NULL;
}

void dns_server_delete(struct dns_server **srv)
{
	if (!*srv)
		return;

	list_for_each_safe((*srv)->clients, i)
		dns_tcp_client_delete(&i);
	list_for_each_safe((*srv)->listen_sources, i)
		dns_listen_delete(&i);
	poll_source_free(&(*srv)->rate_timer);
	poll_source_free(&(*srv)->secret_rollover);
	poll_source_free(&(*srv)->secret_invalidate);
	free(*srv);
	*srv = NULL;
}
