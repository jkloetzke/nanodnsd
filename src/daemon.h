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
#ifndef DAEMON_H
#define DAEMON_H

#include <errno.h>

#include "poll.h"

#if HAVE_SD_DAEMON
int daemon_init(void);
int daemon_ready(struct poll_set *ps);
int daemon_get_http_socket(void);
int daemon_get_dns_udp_socket(void);
int daemon_get_dns_tcp_socket(void);
#else
static inline int daemon_init(void)
{
	return 0;
}

static inline int daemon_ready(struct poll_set *ps)
{
	(void)ps;
	return 0;
}

static inline int daemon_get_http_socket(void)
{
	return -ENOSYS;
}

static inline int daemon_get_dns_udp_socket(void)
{
	return -ENOSYS;
}

static inline int daemon_get_dns_tcp_socket(void)
{
	return -ENOSYS;
}
#endif

#endif
