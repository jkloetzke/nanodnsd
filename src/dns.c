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
};

struct dns_server
{
	struct poll_set *ps;
	struct poll_source *listen_ps_udp;
	struct poll_source *listen_ps_tcp;
	LIST_HEAD(struct dns_tcp_client, server_node) clients;
	unsigned max_clients, num_clients;
};

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


static struct dns_query *dns_query_new(void)
{
	return calloc(1, sizeof(struct dns_query));
}

static void dns_query_delete(struct dns_query **q)
{
	if (*q)
		free(*q);
	*q = NULL;
}

static struct dns_query *dns_query_parse(struct pkt *query)
{
	uint16_t id = 0, flags;
	uint16_t qd_count, an_count, ns_count, ar_count;
	uint16_t qtype, qclass;

	if (pkt_get_uint16(query, &id) < 0)
		return NULL;
	if (pkt_get_uint16(query, &flags) < 0)
		return NULL;

	// verify that it's a standard QUERY
	if (flags & (1u << 15))
		return NULL;

	// get section couters
	if (pkt_get_uint16(query, &qd_count) < 0)
		return NULL;
	if (pkt_get_uint16(query, &an_count) < 0)
		return NULL;
	if (pkt_get_uint16(query, &ns_count) < 0)
		return NULL;
	if (pkt_get_uint16(query, &ar_count) < 0)
		return NULL;

	// We're expecting exactly one query. Additional
	// resource records, e.g. OPT are ignored ATM.
	if (qd_count != 1)
		return NULL;

	// parse query
	struct dns_query *q = dns_query_new();
	if (!q)
		return NULL;
	q->id = id;
	q->opcode = (flags >> 11) & 0x0fu;
	q->rd = (flags >> 8) & 1u;
	if (pkt_get_name(query, q->name) < 0)
		goto bad_query;
	if (pkt_get_uint16(query, &qtype) < 0)
		goto bad_query;
	q->type = (enum type)qtype;
	if (pkt_get_uint16(query, &qclass) < 0)
		goto bad_query;
	q->cls = (enum cls)qclass;

	return q;

bad_query:
	log_dbg("bad query, id %" PRIu16, id);
	dns_query_delete(&q);
	return NULL;
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

struct dns_reply *dns_reply_new(enum rcode rcode)
{
	struct dns_reply *ret = calloc(1, sizeof(struct dns_reply));
	if (ret)
		ret->rcode = rcode;
	return ret;
}

void dns_reply_delete(struct dns_reply **r)
{
	struct dns_reply *d = *r;
	*r = NULL;

	if (d) {
		dns_rr_delete(&d->answer);
		dns_rr_delete(&d->authority);
		free(d);
	}
}

static int dns_reply_dump(struct dns_query *query, struct dns_reply *reply,
		struct pkt *pkt)
{
	int ret;
	uint16_t flags = (1u << 15) |
		((uint16_t)query->opcode << 11) |
		(1u << 10) |
		((uint16_t)query->rd << 8) |
		(uint16_t)reply->rcode;

	if ((ret = pkt_put_uint16(pkt, query->id)) < 0)
		return ret;
	if ((ret = pkt_put_uint16(pkt, flags)) < 0)
		return ret;
	if ((ret = pkt_put_uint16(pkt, 1)) < 0)
		return ret;
	if ((ret = pkt_put_uint16(pkt, dns_rr_count(reply->answer))) < 0)
		return ret;
	if ((ret = pkt_put_uint16(pkt, dns_rr_count(reply->authority))) < 0)
		return ret;
	if ((ret = pkt_put_uint16(pkt, 0)) < 0)
		return ret;

	if ((ret = dns_query_dump(query, pkt)) < 0)
		return ret;

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

	if (tc)
		pkt_or_uint16(pkt, 2, 1u << 9);

	return pkt->idx;
}

static ssize_t dns_process_pkt(uint8_t *qbuf, size_t qlen, uint8_t *rbuf, size_t rlen)
{
	log_dbg("dns_process_pkt(qlen=%zu)", qlen);
	struct pkt qpkt, rpkt;
	ssize_t ret = 0;

	pkt_init(&qpkt, qbuf, qlen);
	struct dns_query *query = dns_query_parse(&qpkt);
	if (!query) {
		log_dbg("dns_process_pkt: invalid query");
		return 0;
	}

	struct dns_reply *reply = db_query(query);
	if (!reply)
		goto query_fail;

	pkt_init(&rpkt, rbuf, rlen);
	ret = dns_reply_dump(query, reply, &rpkt);

	dns_reply_delete(&reply);
query_fail:
	dns_query_delete(&query);
	log_dbg("dns_process_pkt: %zd", ret);
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
			log_warn("oversized request: %" PRIu16 "B", len);
			return -E2BIG;
		}
		if (client->qlen - 2 < len)
			break;

		ret = dns_process_pkt(client->qbuf + 2, len, client->rbuf + 2,
				sizeof(client->rbuf) - 2);
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
				log_errno_warn("client write failed");
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
				dns_tcp_client_delete(&client);
				return 0;
			} else if (errno == EAGAIN && errno == EWOULDBLOCK) {
				break;
			} else {
				log_errno_warn("client read failed");
				dns_tcp_client_delete(&client);
				return 0;
			}
		}

		if (client->qlen >= sizeof(client->qbuf))
			poll_source_mod_io_disable(client->io, POLL_EVENT_IN);
	}

	int ret = dns_try_handle_tcp(client);
	if (ret < 0) {
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

	log_dbg("client idle timeout");
	dns_tcp_client_delete(&client);

	return 0;
}

static int dns_handle_tcp_listen(void *ctx, int listen_fd, poll_event_t events)
{
	struct dns_server *srv = ctx;
	int fd, ret;

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

		while (srv->num_clients > srv->max_clients) {
			struct dns_tcp_client *victim = list_pop_front(&srv->clients);
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
	uint8_t qbuf[MAX_DGRAM_SIZE];
	uint8_t rbuf[MAX_DGRAM_SIZE];
	ssize_t ret;
	struct sockaddr_in6 from;
	socklen_t from_len;

	(void)ctx;
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

		ret = dns_process_pkt(qbuf, len, rbuf, sizeof(rbuf));
		if (ret < 0)
			return ret;
		if (ret == 0)
			continue;

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

struct dns_server* dns_server_new(struct poll_set *ps)
{
	int fd, ret;
	struct dns_server *srv;

	srv = calloc(1, sizeof(struct dns_server));
	if (!srv)
		return NULL;
	list_init(&srv->clients);
	srv->ps = ps;
	srv->max_clients = db_get_http_connections();

	/*
	 * TCP
	 */

	fd = daemon_get_dns_tcp_socket();
	if (fd < 0)
		fd = dns_create_tcp_socket();
	if (fd < 0)
		goto fail;

	// make non-blocking
	ret = set_non_block(fd);
	if (ret < 0) {
		close(fd);
		goto fail;
	}

	// Add to event loop. Takes ownership of file descriptor.
	ret = poll_set_add_io(ps, &srv->listen_ps_tcp, fd, POLL_EVENT_IN,
		dns_handle_tcp_listen, srv);
	if (ret < 0) {
		close(fd);
		log_fatal("poll_set_add_io(tcp) failed: %d", ret);
		goto fail;
	}

	/*
	 * UDP
	 */

	fd = daemon_get_dns_udp_socket();
	if (fd < 0)
		fd = dns_create_udp_socket();
	if (fd < 0)
		goto fail;

	// make non-blocking
	ret = set_non_block(fd);
	if (ret < 0) {
		close(fd);
		goto fail;
	}

	// Add to event loop. Takes ownership of file descriptor.
	ret = poll_set_add_io(ps, &srv->listen_ps_udp, fd, POLL_EVENT_IN,
		dns_handle_udp, NULL);
	if (ret < 0) {
		close(fd);
		log_fatal("poll_set_add_io(udp) failed: %d", ret);
		goto fail;
	}

	return srv;

fail:
	poll_source_free(&srv->listen_ps_udp);
	poll_source_free(&srv->listen_ps_tcp);
	free(srv);
	return NULL;
}

void dns_server_delete(struct dns_server **srv)
{
	if (!*srv)
		return;

	list_for_each_safe((*srv)->clients, i)
		dns_tcp_client_delete(&i);
	poll_source_free(&(*srv)->listen_ps_udp);
	poll_source_free(&(*srv)->listen_ps_tcp);
	free(*srv);
	*srv = NULL;
}
