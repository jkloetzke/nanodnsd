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

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include "list.h"
#include "poll.h"
#include "utils.h"

enum poll_source_type {
	POLL_SOURCE_IO,
	POLL_SOURCE_TIMER,
};

struct poll_source
{
	struct list_node set;
	struct list_node pending;

	enum poll_source_type type;

	union {
		struct poll_source_io {
			int fd;
			poll_event_t events;
			poll_event_t revents;
			poll_set_io_cb cb;
			void *ctx;
		} io;
		struct poll_source_timer {
			uint32_t timeout;
			poll_set_timer_cb cb;
			void *ctx;
		} timer;
	} u;
};

struct poll_set
{
	LIST_HEAD(struct poll_source, set) sources;
	int running;
};


static struct poll_source *poll_source_new(enum poll_source_type type)
{
	struct poll_source *ret = calloc(1, sizeof(struct poll_source));
	if (!ret)
		return NULL;

	ret->type = type;
	list_node_init(&ret->set);
	list_node_init(&ret->pending);

	return ret;
}

void poll_source_free(struct poll_source **src)
{
	if (!*src)
		return;

	list_node_del(&(*src)->set);
	list_node_del(&(*src)->pending);
	if ((*src)->type == POLL_SOURCE_IO)
		close((*src)->u.io.fd);

	free(*src);
	*src = NULL;
}

int poll_source_mod_io_enable(struct poll_source *src, poll_event_t events)
{
	if (src->type != POLL_SOURCE_IO)
		return -EINVAL;
	src->u.io.events |= events;
	return 0;
}

int poll_source_mod_io_disable(struct poll_source *src, poll_event_t events)
{
	if (src->type != POLL_SOURCE_IO)
		return -EINVAL;

	src->u.io.events &= ~events;
	src->u.io.revents &= src->u.io.events|POLL_EVENT_ERR|POLL_EVENT_HUP;

	// remove from pending list if no events left
	if (!src->u.io.revents)
		list_node_del(&src->pending);

	return 0;
}

int poll_source_mod_timer(struct poll_source *src, uint32_t timeout)
{
	if (src->type != POLL_SOURCE_TIMER)
		return -EINVAL;

	uint32_t now = now_monotonic_ms();
	src->u.timer.timeout = now + timeout;
	list_node_del(&src->pending);

	return 0;
}

static int poll_source_dispatch(struct poll_source *src)
{
	int ret = -EINVAL;

	switch (src->type) {
	case POLL_SOURCE_IO:
		ret = src->u.io.cb(src->u.io.ctx, src->u.io.fd, src->u.io.revents);
		break;
	case POLL_SOURCE_TIMER:
		ret = src->u.timer.cb(src->u.timer.ctx);
		break;
	}

	return ret;
}


struct poll_set *poll_set_new(void)
{
	struct poll_set *s = calloc(1, sizeof(struct poll_set));
	if (!s)
		return NULL;

	list_init(&s->sources);

	return s;
}

void poll_set_delete(struct poll_set **s)
{
	if (*s == NULL)
		return;

	assert(!(*s)->running);

	list_for_each_safe((*s)->sources, i)
		poll_source_free(&i);
	free(*s);
	*s = NULL;
}

void poll_set_interrupt(struct poll_set *s)
{
	s->running = 0;
}

int poll_set_dispatch(struct poll_set *s)
{
	nfds_t sz = 8;
	struct pollfd *pfd = calloc(sz, sizeof(struct pollfd));
	if (!pfd)
		return -ENOMEM;

	LIST_HEAD(struct poll_source, pending) pending;
	list_init(&pending);

	int ret = 0;
	s->running = 1;
	while (s->running) {
		uint32_t now = now_monotonic_ms();
		uint32_t timeout = now + TIMEOUT_MAX;
		nfds_t len = 0;

		list_for_each(s->sources, src) {
			switch (src->type) {
			case POLL_SOURCE_IO:
				if (len >= sz) {
					sz = len + 4u;
					void *new = realloc(pfd,
							sizeof(struct pollfd) * sz);
					if (!new) {
						ret = -ENOMEM;
						goto out;
					}
					pfd = new;
				}
				pfd[len].fd = src->u.io.fd;
				pfd[len].events = src->u.io.events;
				pfd[len].revents = 0;
				len++;
				break;
			case POLL_SOURCE_TIMER:
				if (time_before_eq(src->u.timer.timeout, timeout))
					timeout = src->u.timer.timeout;
				break;
			}
		}

		do {
			ret = poll(pfd, len, timeout - now);
		} while (ret < 0 && errno == EINTR);

		if (ret < 0) {
			ret = -errno;
			goto out;
		}

		nfds_t i = 0;
		now = now_monotonic_ms();
		assert(list_empty(pending));
		list_for_each(s->sources, src) {
			if (ret == 0 && time_after(timeout, now))
				break;

			switch (src->type) {
			case POLL_SOURCE_IO:
				assert(pfd[i].fd == src->u.io.fd);
				if (pfd[i].revents) {
					src->u.io.revents = pfd[i].revents;
					list_add_tail(&pending, src);
					ret--;
				}
				i++;
				break;
			case POLL_SOURCE_TIMER:
				if (time_before_eq(src->u.timer.timeout, now))
					list_add_tail(&pending, src);
				break;
			}
		}

		while (!list_empty(pending) && s->running) {
			struct poll_source *src = list_pop_front(&pending);
			ret = poll_source_dispatch(src);
			if (ret < 0)
				goto out;
		}
	}
out:
	while (!list_empty(pending))
		list_pop_front(&pending);
	free(pfd);
	s->running = 0;

	return ret;
}

int poll_set_add_io(struct poll_set *s, struct poll_source **src, int fd,
		poll_event_t events, poll_set_io_cb cb, void *ctx)
{
	struct poll_source *ret = poll_source_new(POLL_SOURCE_IO);
	if (!ret)
		return -ENOMEM;

	ret->u.io.fd = fd;
	ret->u.io.events = events;
	ret->u.io.cb = cb;
	ret->u.io.ctx = ctx;
	list_add_tail(&s->sources, ret);

	if (src)
		*src = ret;
	return 0;
}

int poll_set_add_timer(struct poll_set *s, struct poll_source **src,
		uint32_t timeout, poll_set_timer_cb cb, void *ctx)
{
	struct poll_source *ret = poll_source_new(POLL_SOURCE_TIMER);
	if (!ret)
		return -ENOMEM;

	ret->u.timer.timeout = now_monotonic_ms() + timeout;
	ret->u.timer.cb = cb;
	ret->u.timer.ctx = ctx;
	list_add_tail(&s->sources, ret);

	if (src)
		*src = ret;
	return 0;
}
