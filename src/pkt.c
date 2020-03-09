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
#include <string.h>

#include "pkt.h"
#include "utils.h"

int pkt_get_uint16(struct pkt *pkt, uint16_t *out)
{
	uint16_t tmp;

	if ((pkt->idx + sizeof(uint16_t)) >= pkt->len)
		return -EFAULT;

	memcpy(&tmp, pkt->buf + pkt->idx, sizeof(uint16_t));
	pkt->idx += 2u;
	*out = ntohs(tmp);

	return sizeof(uint16_t);
}

int pkt_get_name(struct pkt *pkt, char name[MAX_NAME_SIZE+1])
{
	int ret;
	size_t hdr = 0, len = 0;
	size_t idx = pkt->idx;
	int i;

	// We have to be careful because of message compression that could lead
	// to endless cycles.
	i = MAX_NAME_SIZE/2u;
	do {
		if (idx >= pkt->len)
			return -EFAULT;

		hdr = pkt->buf[idx++];
		if (hdr <= MAX_LABEL_SIZE) {
			if ((len+hdr+1u) >= MAX_NAME_SIZE)
				return -EINVAL;
			if (idx+hdr >= pkt->len)
				return -EFAULT;
			if ((ret = utils_validate_label((char *)(pkt->buf + idx), hdr)) < 0)
				return ret;

			name[len++] = '.';
			memcpy(name + len, pkt->buf + idx, hdr);
			len += hdr;
			idx += hdr;
		} else if (hdr >= 0xC0u) {
			// Only backward references are supported. What should
			// we do with the parsing position on forward
			// references?
			if ((hdr & 0x3fu) >= idx)
				return -ENOTSUP;
			idx = hdr & 0x3fu;
		} else
			return -EINVAL;

		if (idx > pkt->idx)
			pkt->idx = idx;
	} while (hdr != 0 && --i > 0);

	if (i == 0u)
		return -EINVAL;

	name[len] = '\0';
	return len;
}

int pkt_put_uint16(struct pkt *pkt, uint16_t val)
{
	uint16_t tmp = htons(val);

	if ((pkt->idx + sizeof(uint16_t)) >= pkt->len)
		return -EFAULT;

	memcpy(pkt->buf + pkt->idx, &tmp, sizeof(uint16_t));
	pkt->idx += sizeof(uint16_t);

	return sizeof(uint16_t);
}

int pkt_put_uint32(struct pkt *pkt, uint32_t val)
{
	uint32_t tmp = htonl(val);

	if ((pkt->idx + sizeof(uint32_t)) >= pkt->len)
		return -EFAULT;

	memcpy(pkt->buf + pkt->idx, &tmp, sizeof(uint32_t));
	pkt->idx += sizeof(uint32_t);

	return sizeof(uint32_t);
}

int pkt_put_name(struct pkt *pkt, char name[MAX_NAME_SIZE+1])
{
	char *s = name;

	while (*s) {
		if (*s++ != '.')
			return -EINVAL;

		char *n = strchr(s, '.');
		if (n) {
			size_t len = (size_t)(n - s);
			assert(len <= MAX_LABEL_SIZE);
			if ((pkt->idx + len + 1u) > pkt->len)
				return -EFAULT;
			pkt->buf[pkt->idx++] = (uint8_t)len;
			memcpy(pkt->buf + pkt->idx, s, len);
			pkt->idx += len;
			s = n;
		} else {
			// Must be the end because no dot follows. Make sure
			// that it's the root label.
			if (*s != '\0')
				return -EINVAL;

			if (pkt->idx >= pkt->len)
				return -EFAULT;
			pkt->buf[pkt->idx++] = 0u;
		}
	}

	return s - name;
}

int pkt_put_blob(struct pkt *pkt, void *buf, size_t len)
{
	if (pkt->idx + len > pkt->len)
		return -EFAULT;
	memcpy(pkt->buf + pkt->idx, buf, len);
	pkt->idx += len;

	return len;
}

int pkt_or_uint16(struct pkt *pkt, size_t off, uint16_t val)
{
	uint16_t tmp;

	if ((off + sizeof(uint16_t)) >= pkt->idx)
		return -EFAULT;

	memcpy(&tmp, pkt->buf + off, sizeof(uint16_t));
	tmp |= htons(val);
	memcpy(pkt->buf + off, &tmp, sizeof(uint16_t));

	return sizeof(uint16_t);
}

uint16_t peek_uint16(uint8_t *buf)
{
	uint16_t tmp;
	memcpy(&tmp, buf, sizeof(uint16_t));
	return ntohs(tmp);
}

void poke_uint16(uint8_t *buf, uint16_t val)
{
	uint16_t tmp = htons(val);
	memcpy(buf, &tmp, sizeof(uint16_t));
}
