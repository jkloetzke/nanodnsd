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
#ifndef DNS_H
#define DNS_H

#include <inttypes.h>
#include <stddef.h>
#include <unistd.h>

#include "defs.h"

struct poll_set;
struct dns_server;

enum opcode
{
	OP_QUERY = 0,
	OP_IQUERY = 1,
	OP_STATUS = 2,
};

enum rcode
{
	RCODE_NO_ERROR = 0,
	RCODE_FORMAT_ERROR = 1,
	RCODE_SERVER_FAILURE = 2,
	RCODE_NAME_ERROR = 3,
	RCODE_NOT_IMPLEMENTED = 4,
	RCODE_REFUSED = 5,

	// Extended-RCODEs. Implies an OPT RR in the response.
	RCODE_BADVERS = 16,	// RFC6891 9.
	RCODE_BADCOOKIE = 23,	// RFC7873 8.
};

enum type
{
	TYPE_A = 1,
	TYPE_NS = 2,
	TYPE_CNAME = 5,
	TYPE_SOA = 6,
	TYPE_MX = 15,
	TYPE_TXT = 16,
	TYPE_AAAA = 28,
	TYPE_OPT = 41,

	TYPE_Q_ALL = 255,
};

enum cls
{
	CLASS_IN = 1,

	CLASS_Q_ANY = 255,
};

enum edns
{
	EDNS_OPT_COOKIE = 10,	// RFC7873 8.
};

struct dns_rr
{
	struct dns_rr *next;

	char name[MAX_NAME_SIZE+1];
	enum type type;
	uint32_t ttl;

	union {
		uint8_t a[4];
		uint8_t aaaa[16];
		char ns[MAX_NAME_SIZE+1];
		struct soa {
			char mname[MAX_NAME_SIZE+1];
			char rname[MAX_NAME_SIZE+1];
			uint32_t serial;
			uint32_t refresh;
			uint32_t retry;
			uint32_t expire;
			uint32_t minimum;
		} soa;
	} u;
};

/**
 * DNS client or server cookie.
 *
 * Our server cookie has the same length as the client cookie to simplify the
 * implementation.
 */
struct dns_cookie
{
	uint8_t cookie[8];
};

struct dns_query
{
	uint16_t id;                    // transaction id
	enum opcode opcode;             // should be OP_QUERY
	enum rcode err;                 // Error response if query is wrong

	uint16_t question : 1;          // question present (QDCOUNT == 1)
	uint16_t rd : 1;                // RFC1035 4.1.1 recursion desired
	uint16_t edns : 1;              // RFC6891 OPT Pseudo-RR received
	uint16_t cc_present : 1;        // RFC7873 Client DNS cookie received
	uint16_t sc_present : 1;        // RFC7873 Server DNS cookie received

	// Question fields. Only valid if question is set.
	char name[MAX_NAME_SIZE+1];
	enum type type;
	enum cls cls;

	uint16_t udp_reply_size;         // standard 512 or EDNS announced size
	struct dns_cookie client_cookie; // RFC7873 4., valid if cc_present set
	struct dns_cookie server_cookie; // RFC7873 4., valid if sc_present set
};

struct dns_reply
{
	enum rcode rcode;
	uint16_t max_size;               // Maximum reply size

	struct dns_rr *answer;
	struct dns_rr *authority;

	uint16_t rate_limit : 1;        // apply rate limiting
	uint16_t edns : 1;              // RFC6891 OPT Pseudo-RR required
	uint16_t cookies : 1;           // Send RFC7873 client+server cookie

	struct dns_cookie client_cookie; // RFC7873 4., valid if cookie set
	struct dns_cookie server_cookie; // RFC7873 4., valid if cookie set
};

struct dns_rr *dns_rr_new(char name[MAX_NAME_SIZE+1], enum type type, uint32_t ttl);
void dns_rr_delete(struct dns_rr **r);
void dns_rr_add(struct dns_rr **anchor, struct dns_rr *n);

struct dns_server* dns_server_new(struct poll_set *ps);
void dns_server_delete(struct dns_server **srv);

#endif
