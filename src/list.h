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
#ifndef LIST_H
#define LIST_H

#include <inttypes.h>
#include <stddef.h>

struct list_node
{
	struct list_node *prev;
	struct list_node *next;
};

#define LIST_HEAD(type__, anchor__) \
	struct { \
		struct list_node head; \
		type__ typevar[0]; \
		struct { \
			char off[offsetof(type__, anchor__)]; \
		} offsetvar[0]; \
	}


static inline void list_node_init(struct list_node *n)
{
	n->next = n->prev = n;
}

static inline void list_node_append(struct list_node *l, struct list_node *e)
{
	e->next = l;
	e->prev = l->prev;
	l->prev->next = e;
	l->prev = e;
}

static inline void list_node_del(struct list_node *e)
{
	e->prev->next = e->next;
	e->next->prev = e->prev;
	e->next = e->prev = e;
}


#define list_init(l) \
	do { \
		(l)->head.prev = (struct list_node *)(l); \
		(l)->head.next = (struct list_node *)(l); \
	} while (0)

#define list_empty(l) \
	((l).head.next == &(l).head)

#define list_add_tail(head__, elem__) \
	do { \
		list_node_append(&((head__)->head), (struct list_node *)((uintptr_t)(elem__) + sizeof((head__)->offsetvar[0].off))); \
	} while (0)

#define list_element_type(head__) \
	typeof((head__).typevar[0])*

#define list_front(head__) \
	((list_element_type((head__)))((uintptr_t)(head__).head.next - sizeof((head__).offsetvar[0].off)))

#define list_pop_front(head__) \
	({ \
		list_element_type(*head__) n = list_front(*head__); \
		list_node_del((head__)->head.next); \
		n; \
	})


#define list_for_each(head__, var__) \
	for (typeof((head__).typevar[0]) *var__ = (void*)((uintptr_t)(head__).head.next - sizeof((head__).offsetvar[0].off)); \
	     ((uintptr_t)var__ + sizeof((head__).offsetvar[0].off)) != (uintptr_t)&(head__).head; \
	     var__ = (typeof((head__).typevar[0]) *)((uintptr_t)((struct list_node *)((uintptr_t)var__ + sizeof((head__).offsetvar[0].off)))->next - sizeof((head__).offsetvar[0].off)))

#define list_for_each_safe(head__, var__) \
	for (typeof((head__).typevar[0]) *var__ = (void*)((uintptr_t)(head__).head.next - sizeof((head__).offsetvar[0].off)), *var__##_next; \
	     (((uintptr_t)var__ + sizeof((head__).offsetvar[0].off)) != (uintptr_t)&(head__).head) && (var__##_next = (typeof((head__).typevar[0]) *)((uintptr_t)((struct list_node *)((uintptr_t)var__ + sizeof((head__).offsetvar[0].off)))->next - sizeof((head__).offsetvar[0].off)), 1); \
	     var__ = var__##_next)


static inline void list_head_move__(struct list_node *dst, struct list_node *src)
{
	src->prev->next = dst;
	src->next->prev = dst->prev;
	dst->prev->next = src->next;
	dst->prev = src->prev;

	list_node_init(src);
}

#define list_move_tail(dst_head__, src_head__) \
	do { \
		if (!list_empty(src_head__)) \
			list_head_move__(&(dst_head__).head, &(src_head__).head); \
	} while (0)

#endif
