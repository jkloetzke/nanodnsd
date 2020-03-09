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
};

enum type
{
	TYPE_A = 1,
	TYPE_NS = 2,
	TYPE_SOA = 6,
	TYPE_AAAA = 28,

	TYPE_Q_ALL = 255,
};

enum cls
{
	CLASS_IN = 1,

	CLASS_Q_ANY = 255,
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

struct dns_query
{
	uint16_t id;
	enum opcode opcode;
	uint16_t rd : 1;
	char name[MAX_NAME_SIZE+1];
	enum type type;
	enum cls cls;
};

struct dns_reply
{
	enum rcode rcode;

	struct dns_rr *answer;
	struct dns_rr *authority;
};

struct dns_rr *dns_rr_new(char name[MAX_NAME_SIZE+1], enum type type, uint32_t ttl);
void dns_rr_delete(struct dns_rr **r);
void dns_rr_add(struct dns_rr **anchor, struct dns_rr *n);

struct dns_reply *dns_reply_new(enum rcode rcode);
void dns_reply_delete(struct dns_reply **r);

int dns_create_server(struct poll_set *ps);

#endif
