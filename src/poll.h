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
#ifndef POLL_H
#define POLL_H

#include <inttypes.h>
#include <poll.h>

typedef short poll_event_t;
#define POLL_EVENT_IN (POLLIN)
#define POLL_EVENT_OUT (POLLOUT)
#define POLL_EVENT_ERR (POLLERR)
#define POLL_EVENT_HUP (POLLHUP)

struct poll_set;
struct poll_source;

typedef int (*poll_set_io_cb)(void *ctx, int fd, poll_event_t events);
typedef int (*poll_set_timer_cb)(void *ctx);
typedef int (*poll_set_signal_cb)(void *ctx, int sig);

void poll_source_free(struct poll_source **src);
int poll_source_mod_io_enable(struct poll_source *src, poll_event_t events);
int poll_source_mod_io_disable(struct poll_source *src, poll_event_t events);
int poll_source_mod_timer(struct poll_source *src, uint32_t timeout);

struct poll_set *poll_set_new(void);
void poll_set_delete(struct poll_set **s);
void poll_set_interrupt(struct poll_set *s);
int poll_set_dispatch(struct poll_set *s);

int poll_set_add_io(struct poll_set *s, struct poll_source **src, int fd,
		poll_event_t events, poll_set_io_cb cb, void *ctx);
int poll_set_add_timer(struct poll_set *s, struct poll_source **src,
		uint32_t timeout, poll_set_timer_cb cb, void *ctx);
int poll_set_add_signal(struct poll_set *s, struct poll_source **src,
		int sig, poll_set_signal_cb cb, void *ctx);

#endif
