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
#ifndef DB_H
#define DB_H

#include <inttypes.h>
#include <sys/types.h>

struct in_addr;
struct in6_addr;

struct dns_reply;
struct dns_query;

int db_query(struct dns_query *query, struct dns_reply *reply);
int db_update(const char *hostname, const char *token, struct in_addr *ipv4,
		struct in6_addr *ipv6);

uint16_t db_get_udp_port(void);
uint16_t db_get_tcp_port(void);
uint16_t db_get_tcp_connections(void);
uint32_t db_get_tcp_timeout(void);
uint16_t db_get_http_port(void);
uint16_t db_get_http_connections(void);
uint32_t db_get_http_timeout(void);
uint32_t db_get_rate_limit(void);
uint32_t db_get_stats_interval(void);

void db_get_user(uid_t *uid, gid_t *gid);

int db_init(const char *cfg);
int db_load_state(const char *cfg);
int db_save_state(const char *cfg);

#endif
