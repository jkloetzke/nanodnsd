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
#include <grp.h>
#include <netinet/in.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>


#include "db.h"
#include "dns.h"
#include "log.h"
#include "utils.h"

struct db_entry
{
	struct db_entry *next;

	char *token;
	uint32_t expire;
	uint32_t timeout;
	char name[MAX_LABEL_SIZE+1];
	struct dns_rr *rr;
};

struct db
{
	struct db_entry *entries;
	struct dns_rr *soa;

	char origin[MAX_NAME_SIZE+1];
	size_t origin_len;

	uint16_t udp_port;

	uint16_t tcp_port;
	uint16_t tcp_connections;
	uint32_t tcp_timeout;

	uint16_t http_port;
	uint16_t http_connections;
	uint32_t http_timeout;

	uint32_t rate_limit;

	uid_t uid;
	gid_t gid;
};

static struct db db = {
	.udp_port = 53,

	.tcp_port = 53,
	.tcp_connections = DEFAULT_TCP_CONNECTIONS,
	.tcp_timeout = DEFAULT_TCP_LINGER_TIME,

	.http_port = 80,
	.http_connections = DEFAULT_TCP_CONNECTIONS,
	.http_timeout = DEFAULT_TCP_LINGER_TIME,

	.rate_limit = DEFAULT_RATE_LIMIT,
};
static int (*parser)(const char *key, const char *value);
static struct db_entry *parser_entry;


static int strlcpylower(char *dst, const char *src, size_t n)
{
	if (n == 0)
		return -ENOSPC;

	while (--n && *src) {
		if (*src >= 0x41 && *src <= 0x5A)
			*dst++ = (char)(*src++ + 0x20);
		else
			*dst++ = *src++;
	}
	*dst = '\0';

	return (n == 0 && *src != '\0') ? -ENOSPC : 0;
}

static int strlcpydomain(char *dst, const char *src, size_t sz)
{
	if (sz < 3)
		return -ENOSPC;
	if (*src == '.')
		return -EINVAL;

	// validate all labels except the last one
	const char *l, *n;
	for (l = src; (n = strchr(l, '.')); l = n+1) {
		if (utils_validate_label(l, (size_t)(n-l)) <= 0)
			return -EINVAL;
	}

	/*
	 * Copy the domain name with a leading dot in lower case. There must be
	 * enough room at the end to add a trailing dot for the implicit root
	 * label.
	 */
	*dst++ = '.';
	sz--;
	if (strlcpylower(dst, src, sz-2) < 0)
		return -ENOSPC;

	/*
	 * The last label must either be empty (root label) or must be valid
	 * and we have to add the root label.
	 */
	if (*l != '\0') {
		if (utils_validate_label(l, strlen(l)) <= 0)
			return -EINVAL;
		strcat(dst, ".");
	}

	return 0;
}

static int strlcpyrname(char *dst, const char *src, size_t sz)
{
	if (sz < 2)
		return -ENOSPC;

	// must be an email address
	const char *at = strchr(src, '@');
	if (!at)
		return -EINVAL;

	*dst++ = '.';
	sz--;

	// Escape any dots before the @. See RFC 1912 2.2
	const char *dot = strchr(src, '.');
	while (dot && dot < at) {
		size_t len = (size_t)(dot - src);
		if (len + 2u > sz)
			return -ENOSPC;
		memcpy(dst, src, len);
		dst += len;
		*dst++ = '\\';
		*dst++ = '.';

		sz -= len;
		src = dot + 1;
		dot = strchr(src, '.');
	}

	// copy remaining name part
	size_t len = (size_t)(at - src);
	if (len > sz)
		return -ENOSPC;
	memcpy(dst, src, len);
	src = at + 1;
	dst += len;
	sz -= len;

	// copy domain part
	return strlcpydomain(dst, src, sz);
}

static int strcmp_consttime(const char *s1, const char *s2)
{
	size_t l1 = strlen(s1);
	size_t l2 = strlen(s2);
	if (l1 != l2)
		return 0;

	char res = 0;
	while (l1--)
		res |= (char)(*s1++ ^ *s2++);

	return res == 0;
}

static int strtouint16(const char *s, uint16_t *v)
{
	char *end;

	if (*s == '\0')
		return -EINVAL;

	unsigned long ret = strtoul(s, &end, 10);
	if (*end != '\0')
		return -EINVAL;

	if (ret > UINT16_MAX)
		return -ERANGE;

	*v = (uint16_t)ret;
	return 0;
}

static int strtouint32(const char *s, uint32_t *v)
{
	char *end;

	if (*s == '\0')
		return -EINVAL;

	unsigned long long ret = strtoull(s, &end, 10);
	if (*end != '\0')
		return -EINVAL;

	if (ret > UINT32_MAX)
		return -ERANGE;

	*v = (uint32_t)ret;
	return 0;
}

static int strtotime(const char *s, uint32_t *v, uint32_t factor)
{
	char *end;

	if (*s == '\0')
		return -EINVAL;

	unsigned long ret = strtoul(s, &end, 10);
	if (*end != '\0') {
		if (strcmp(end, "m") == 0)
			factor *= 60u;
		else if (strcmp(end, "h") == 0)
			factor *= 60u*60u;
		else if (strcmp(end, "d") == 0)
			factor *= 24u*60u*60u;
		else if (strcmp(end, "s") != 0)
			return -EINVAL;
	}

	if (ret > TIMEOUT_MAX / factor)
		return -ERANGE;

	*v = (uint32_t)ret * factor;
	return 0;
}


static struct db_entry *db_entry_new(uint32_t expire, const char name[MAX_LABEL_SIZE+1])
{
	struct db_entry *ret = calloc(1, sizeof(struct db_entry));
	if (ret) {
		if (name) {
			ret->name[0] = '.';
			strlcpylower(ret->name + 1, name, sizeof(ret->name)-1);
		} else {
			strcpy(ret->name, "");
		}
		ret->timeout = expire;
		ret->expire = now_monotonic() + expire;
	}
	return ret;
}

static void db_entry_add(struct db_entry *e)
{
	if (e) {
		e->next = db.entries;
		db.entries = e;
	}
}

static struct dns_rr *db_rr_cpy(struct dns_rr *r)
{
	struct dns_rr *ret = dns_rr_new(r->name, r->type, r->ttl);
	if (!ret)
		return NULL;
	strcat(ret->name, db.origin);
	memcpy(&ret->u, &r->u, sizeof(r->u));
	return ret;
}

static struct dns_rr *db_get_soa_rr(void)
{
	return db_rr_cpy(db.soa);
}

static int db_in_zone(char name[MAX_NAME_SIZE+1])
{
	size_t qlen = strlen(name);

	if (qlen < db.origin_len)
		return 0;

	// suffix must match
	return strcmp(name + qlen - db.origin_len, db.origin) == 0 ? 1 : 0;
}

static struct db_entry *db_find(char name[MAX_NAME_SIZE+1])
{
	size_t qlen = strlen(name);
	if (qlen < db.origin_len)
		return NULL;

	size_t len = qlen - db.origin_len;
	struct db_entry *ret = db.entries;

	while (ret && (strlen(ret->name) != len || memcmp(name, ret->name, len) != 0))
		ret = ret->next;

	return ret;
}

int db_query(struct dns_query *query, struct dns_reply *reply)
{
	// we're only answering IN class requests
	if (query->cls != CLASS_IN && query->cls != CLASS_Q_ANY) {
		log_dbg("invalid class #%d, id #%" PRIu16, query->cls, query->id);
		reply->rcode = RCODE_REFUSED;
		return 0;
	}

	// Is this even managed by us? We are just an authorative server and
	// refuse to recursively lookup other names.
	char name[MAX_NAME_SIZE+1];
	if (strlcpylower(name, query->name, sizeof(name)) < 0) {
		log_err("query name too long: %zu", strlen(query->name));
		reply->rcode = RCODE_SERVER_FAILURE;
		return 0;
	}
	if (db_in_zone(name) <= 0) {
		log_dbg("unmanaged name '%s', id #%" PRIu16, query->name, query->id);
		reply->rcode = RCODE_REFUSED;
		return 0;
	}

	// find entry
	struct db_entry *entry = db_find(name);
	if (!entry) {
		reply->rcode = RCODE_NAME_ERROR;
		dns_rr_add(&reply->authority, db_get_soa_rr());
		return 0;
	}

	// prune RRs if expired
	if (time_after(now_monotonic(), entry->expire))
		dns_rr_delete(&entry->rr);

	// add matching RRs
	for (struct dns_rr *rr = entry->rr; rr; rr = rr->next) {
		if (query->type == rr->type || query->type == TYPE_Q_ALL) {
			dns_rr_add(&reply->answer, db_rr_cpy(rr));
		}
	}

	// If nothing was found we again add our SOA record to enable negative
	// caching.
	if (!reply->answer)
		dns_rr_add(&reply->authority, db_get_soa_rr());

	return 1;
}

int db_update(const char *hostname, const char *token, struct in_addr *ipv4,
		struct in6_addr *ipv6)
{
	char name[MAX_NAME_SIZE+1];
	if (strlcpydomain(name, hostname, sizeof(name)) < 0)
		return -EINVAL;

	if (db_in_zone(name) <= 0)
		return -ENOENT;

	name[strlen(name) - db.origin_len] = '\0'; // cut domain name
	struct db_entry *e = db.entries;
	while (e && strcmp(e->name, name) != 0)
		e = e->next;
	if (!e)
		return -ENOENT;

	if (!e->token)
		return -EACCES;
	if (!strcmp_consttime(e->token, token))
		return -EACCES;

	dns_rr_delete(&e->rr);
	if (ipv4) {
		struct dns_rr *a = dns_rr_new(name, TYPE_A, DEFAULT_ENTRY_TTL);
		if (!a)
			return -ENOMEM;
		memcpy(a->u.a, ipv4, 4);
		dns_rr_add(&e->rr, a);
	}
	if (ipv6) {
		struct dns_rr *aaaa = dns_rr_new(name, TYPE_AAAA, DEFAULT_ENTRY_TTL);
		if (!aaaa)
			return -ENOMEM;
		memcpy(aaaa->u.aaaa, ipv6, 16);
		dns_rr_add(&e->rr, aaaa);
	}

	// refresh expire time
	e->expire = now_monotonic() + e->timeout;

	return 0;
}


static int db_parse_server(const char *key, const char *value)
{
	if (strcmp(key, "domain") == 0) {
		if (strlcpydomain(db.origin, value, sizeof(db.origin)) < 0) {
			log_err("Invalid domain: '%s'", value);
			return -EINVAL;
		}
		db.origin_len = strlen(db.origin);
	} else if (strcmp(key, "nameserver") == 0) {
		if (strlcpydomain(db.soa->u.soa.mname, value, sizeof(db.soa->u.soa.mname)) < 0) {
			log_err("Invalid nameserver: '%s'", value);
			return -EINVAL;
		}
	} else if (strcmp(key, "email") == 0) {
		if (strlcpyrname(db.soa->u.soa.rname, value, sizeof(db.soa->u.soa.rname)) < 0) {
			log_err("Invalid email: '%s'", value);
			return -EINVAL;
		}
	} else if (strcmp(key, "user") == 0) {
		errno = 0;
		struct passwd *u = getpwnam(value);
		if (!u) {
			if (errno == 0) {
				log_err("Unkown user: '%s'", value);
				return -ENOENT;
			}
			return log_errno_err("getpwnam");
		}
		db.uid = u->pw_uid;
	} else if (strcmp(key, "group") == 0) {
		struct group *g = getgrnam(value);
		if (!g) {
			if (errno == 0) {
				log_err("Unkown group: '%s'", value);
				return -ENOENT;
			}
			return log_errno_err("getgrnam");
		}
		db.gid = g->gr_gid;
	} else if (strcmp(key, "rate_limit") == 0) {
		if (strtouint32(value, &db.rate_limit) < 0) {
			log_err("Invalid rate limit: '%s'", value);
			return -EINVAL;
		}
	} else {
		log_err("Unknown [server] key: '%s'", key);
		return -EINVAL;
	}

	return 0;
}

static int db_parse_udp(const char *key, const char *value)
{
	if (strcmp(key, "port") == 0) {
		if (strtouint16(value, &db.udp_port) < 0) {
			log_err("Invalid UDP port: '%s'", value);
			return -EINVAL;
		}
	} else {
		log_err("Unknown [udp] key: '%s'", key);
		return -EINVAL;
	}

	return 0;
}

static int db_parse_tcp(const char *key, const char *value)
{
	if (strcmp(key, "port") == 0) {
		if (strtouint16(value, &db.tcp_port) < 0) {
			log_err("Invalid TCP port: '%s'", value);
			return -EINVAL;
		}
	} else if (strcmp(key, "connections") == 0) {
		if (strtouint16(value, &db.tcp_connections) < 0) {
			log_err("Invalid TCP connections: '%s'", value);
			return -EINVAL;
		}
	} else if (strcmp(key, "timeout") == 0) {
		if (strtotime(value, &db.tcp_timeout, 1000) < 0) {
			log_err("Invalid TCP timeout: '%s'", value);
			return -EINVAL;
		}
	} else {
		log_err("Unknown [tcp] key: '%s'", key);
		return -EINVAL;
	}

	return 0;
}

static int db_parse_http(const char *key, const char *value)
{
	if (strcmp(key, "port") == 0) {
		if (strtouint16(value, &db.http_port) < 0) {
			log_err("Invalid HTTP port: '%s'", value);
			return -EINVAL;
		}
	} else if (strcmp(key, "connections") == 0) {
		if (strtouint16(value, &db.http_connections) < 0) {
			log_err("Invalid HTTP connections: '%s'", value);
			return -EINVAL;
		}
	} else if (strcmp(key, "timeout") == 0) {
		if (strtotime(value, &db.http_timeout, 1000) < 0) {
			log_err("Invalid HTTP timeout: '%s'", value);
			return -EINVAL;
		}
	} else {
		log_err("Unknown [http] key: '%s'", key);
		return -EINVAL;
	}

	return 0;
}

static int db_parse_a(struct db_entry *entry, const char *value)
{
	struct in_addr ipv4;
	int ret = inet_pton(AF_INET, value, &ipv4);
	if (ret <= 0) {
		log_err("Invalid a= key: '%s'", value);
		return -EINVAL;
	}

	struct dns_rr *a = dns_rr_new(entry->name, TYPE_A, DEFAULT_ENTRY_TTL);
	if (!a)
		return -ENOMEM;
	memcpy(a->u.a, &ipv4, 4);
	dns_rr_add(&entry->rr, a);

	return 0;
}

static int db_parse_aaaa(struct db_entry *entry, const char *value)
{
	struct in6_addr ipv6;
	int ret = inet_pton(AF_INET6, value, &ipv6);
	if (ret <= 0) {
		log_err("Invalid aaaa= key: '%s'", value);
		return -EINVAL;
	}

	struct dns_rr *aaaa = dns_rr_new(entry->name, TYPE_AAAA,
			DEFAULT_ENTRY_TTL);
	if (!aaaa)
		return -ENOMEM;
	memcpy(aaaa->u.aaaa, &ipv6, 16);
	dns_rr_add(&entry->rr, aaaa);

	return 0;
}

static int db_parse_host(const char *key, const char *value)
{
	if (strcmp(key, "token") == 0) {
		free(db.entries->token);
		db.entries->token = strdup(value);
		if (!db.entries->token)
			return -ENOMEM;
	} else if (strcmp(key, "expire") == 0) {
		if (strtotime(value, &db.entries->timeout, 1) < 0) {
			log_err("Invalid expire= timeout: '%s'", value);
			return -EINVAL;
		}
		db.entries->expire = now_monotonic() + db.entries->timeout;
	} else if (strcmp(key, "a") == 0) {
		return db_parse_a(db.entries, value);
	} else if (strcmp(key, "aaaa") == 0) {
		return db_parse_aaaa(db.entries, value);
	} else {
		log_err("Unknown [@...] key: '%s'", key);
		return -EINVAL;
	}

	return 0;
}

static int db_parsed_section(const char *section)
{
	if (strcmp(section, "server") == 0)
		parser = db_parse_server;
	else if (strcmp(section, "udp") == 0)
		parser = db_parse_udp;
	else if (strcmp(section, "tcp") == 0)
		parser = db_parse_tcp;
	else if (strcmp(section, "http") == 0)
		parser = db_parse_http;
	else if (section[0] == '@') {
		if (utils_validate_label(section + 1, strlen(section+1)) <= 0) {
			log_err("Invalid host name: '%s'", section + 1);
			return -EINVAL;
		}
		struct db_entry *e = db_entry_new(DEFAULT_ENTRY_EXPIRE, section + 1);
		if (!e)
			return -ENOMEM;

		db_entry_add(e);
		parser = db_parse_host;
	} else {
		log_err("Invalid cfg section: '%s'", section);
		parser = NULL;
		return -EINVAL;
	}

	return 0;
}

static int db_parsed_key(const char *key, const char *value)
{
	if (!parser) {
		log_err("Malformed cfg file");
		return -EINVAL;
	}

	return parser(key, value);
}


static int db_state_parse_host(const char *key, const char *value)
{
	if (!parser_entry)
		return 0;

	if (strcmp(key, "expire") == 0) {
		uint32_t expire;
		if (strtouint32(value, &expire) < 0) {
			log_err("Invalid expire= timeout: '%s'", value);
			return -EINVAL;
		}
		uint32_t now = now_monotonic();
		parser_entry->expire = realime_to_monotonic(expire);
		if (time_after(parser_entry->expire, now + parser_entry->timeout)) {
			// expiration time shortened
			parser_entry->expire = now + parser_entry->timeout;
		} else if (time_after(now, expire)) {
			// has expired meanwhile
			dns_rr_delete(&parser_entry->rr);
			parser_entry = NULL;
		}
	} else if (strcmp(key, "a") == 0) {
		return db_parse_a(parser_entry, value);
	} else if (strcmp(key, "aaaa") == 0) {
		return db_parse_aaaa(parser_entry, value);
	} else {
		log_err("Unknown [@...] key: '%s'", key);
		return -EINVAL;
	}

	return 0;
}

static int db_state_parsed_section(const char *section)
{
	if (section[0] == '@') {
		parser = db_state_parse_host;
		parser_entry = db.entries;
		while (parser_entry && strcmp(parser_entry->name, section+1))
			parser_entry = parser_entry->next;

		if (!parser_entry)
			log_info("State entry '%s' not matched in cfg", section+1);
		else if (!parser_entry->token) {
			log_dbg("Ignore state of static entry '%s'", section+1);
			parser_entry = NULL;
		} else
			dns_rr_delete(&parser_entry->rr);
	} else {
		log_err("Invalid state section: '%s'", section);
		parser = NULL;
		return -EINVAL;
	}

	return 0;
}

static int db_state_parsed_key(const char *key, const char *value)
{
	if (parser)
		return parser(key, value);
	else
		return 0;
}

/*****************************************************************************/

uint16_t db_get_udp_port(void)
{
	return db.udp_port;
}

uint16_t db_get_tcp_port(void)
{
	return db.tcp_port;
}

uint16_t db_get_tcp_connections(void)
{
	return db.tcp_connections;
}

uint32_t db_get_tcp_timeout(void)
{
	return db.tcp_timeout;
}

uint16_t db_get_http_port(void)
{
	return db.http_port;
}

uint16_t db_get_http_connections(void)
{
	return db.http_connections;
}

uint32_t db_get_http_timeout(void)
{
	return db.http_timeout;
}

uint32_t db_get_rate_limit(void)
{
	return db.rate_limit;
}

void db_get_user(uid_t *uid, gid_t *gid)
{
	*uid = db.uid;
	*gid = db.gid;
}

int db_init(const char *cfg)
{
	// keep uid/gid in nothing else is specified
	db.uid = getuid();
	db.gid = getgid();

	// $ORIGIN never expires
	struct db_entry *origin = db_entry_new(TIMEOUT_MAX, NULL);
	if (!origin)
		return -ENOMEM;

	/*
	 * Create the SOA record immediately. The mname and rname fields are
	 * read from the cfg file. Their presence is checked afterwards.
	 */
	struct dns_rr *soa = dns_rr_new("", TYPE_SOA, DEFAULT_ORIGIN_TTL);
	if (!soa) {
		free(origin);
		return -ENOMEM;
	}

	soa->u.soa.serial = now_realtime();
	soa->u.soa.refresh = 600; // 10 minutes
	soa->u.soa.retry = 300; // 5 minutes
	soa->u.soa.expire = 604800; // 1 week
	soa->u.soa.minimum = 600; // 10 minutes

	origin->rr = soa;

	db.entries = origin;
	db.soa = soa;

	// parse other settings from file
	int ret = parse_ini_file(cfg, db_parsed_section, db_parsed_key);
	if (ret < 0) {
		log_err("Could not parse %s: %s", cfg, strerror(-ret));
		return ret;
	}

	// make sure the user supplied vital information
	if (db.origin_len == 0) {
		log_err("No domain= configured");
		return -EINVAL;
	}
	if (db.soa->u.soa.mname[0] == '\0') {
		log_err("No nameserver= configured");
		return -EINVAL;
	}
	if (db.soa->u.soa.rname[0] == '\0') {
		log_err("No email= configured");
		return -EINVAL;
	}

	// add required NS-record of $ORIGIN
	struct dns_rr *ns = dns_rr_new("", TYPE_NS, DEFAULT_ORIGIN_TTL);
	if (!ns)
		return -ENOMEM;
	strcpy(ns->u.ns, soa->u.soa.mname);
	dns_rr_add(&origin->rr, ns);

	log_info("cfg: domain='%s' mname='%s' rname='%s'", db.origin,
		db.soa->u.soa.mname, db.soa->u.soa.rname);
	for (struct db_entry *e = db.entries; e; e = e->next) {
		if (e->name[0])
			log_info("cfg: hostname=%s", e->name);
	}

	return 0;
}

int db_load_state(const char *cfg)
{
	int ret = parse_ini_file(cfg, db_state_parsed_section,
		db_state_parsed_key);
	if (ret < 0)
		log_err("Could not parse %s: %s", cfg, strerror(-ret));

	return ret;
}

int db_save_state(const char *cfg)
{
	FILE *f = fopen(cfg, "w");
	if (!f)
		return log_errno_err("cannot create '%s'", cfg);

	int ret = 0;
	for (struct db_entry *e = db.entries; e; e = e->next) {
		if (!e->token)
			continue;
		if (time_after(now_monotonic(), e->expire))
			continue;

		ret = fprintf(f, "[@%s]\n", e->name);
		if (ret < 0)
			goto out;
		ret = fprintf(f, "expire=%" PRIu32 "\n",
			monotonic_to_realime(e->expire));
		if (ret < 0)
			goto out;

		for (struct dns_rr *rr = e->rr; rr; rr = rr->next) {
			switch (rr->type) {
			case TYPE_A: {
				struct in_addr ipv4;
				char buf[INET_ADDRSTRLEN];
				memcpy(&ipv4, rr->u.a, 4);
				if (!inet_ntop(AF_INET, &ipv4, buf, sizeof(buf))) {
					ret = log_errno_err("inet_ntop");
					goto out;
				}
				ret = fprintf(f, "a=%s\n", buf);
				if (ret < 0)
					goto out;
				break;
			}
			case TYPE_AAAA: {
				struct in6_addr ipv6;
				char buf[INET6_ADDRSTRLEN];
				memcpy(&ipv6, rr->u.aaaa, 16);
				if (!inet_ntop(AF_INET6, &ipv6, buf, sizeof(buf))) {
					ret = log_errno_err("inet_ntop");
					goto out;
				}
				ret = fprintf(f, "aaaa=%s\n", buf);
				if (ret < 0)
					goto out;
				break;
			}
			default:
				break;
			}
		}
	}

out:
	if (fclose(f) < 0)
		ret = log_errno_err("close '%s' failed", cfg);

	if (ret < 0) {
		log_err("Remove state file '%s' due to write errors", cfg);
		unlink(cfg);
	}

	return ret;
}
