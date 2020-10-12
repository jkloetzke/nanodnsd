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
#ifndef PKT_H
#define PKT_H

#include <inttypes.h>

#include "defs.h"

struct pkt
{
	uint8_t *buf;
	size_t len;
	size_t idx;
};


static inline void pkt_init(struct pkt *pkt, uint8_t *buf, size_t len)
{
	pkt->buf = buf;
	pkt->len = len;
	pkt->idx = 0;
}

static inline size_t pkt_remain(struct pkt *pkt)
{
	return pkt->len - pkt->idx;
}

int pkt_skip_octets(struct pkt *pkt, size_t num);
int pkt_skip_rr(struct pkt *pkt);

int pkt_get_uint16(struct pkt *pkt, uint16_t *out);
int pkt_get_uint32(struct pkt *pkt, uint32_t *out);
int pkt_get_name(struct pkt *pkt, char name[MAX_NAME_SIZE+1]);
int pkt_get_blob(struct pkt *pkt, void *buf, size_t len);

int pkt_put_uint16(struct pkt *pkt, uint16_t val);
int pkt_put_uint32(struct pkt *pkt, uint32_t val);
int pkt_put_name(struct pkt *pkt, char name[MAX_NAME_SIZE+1]);
int pkt_put_blob(struct pkt *pkt, void *buf, size_t len);

int pkt_or_uint16(struct pkt *pkt, size_t off, uint16_t val);

uint16_t peek_uint16(uint8_t *buf);
void poke_uint16(uint8_t *buf, uint16_t val);

#endif
