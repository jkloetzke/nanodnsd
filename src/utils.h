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
#ifndef UTILS_H
#define UTILS_H

#include <inttypes.h>

#include "defs.h"

#define TIMEOUT_MAX (UINT32_MAX / 2 - 1)

uint32_t now_monotonic(void);
uint32_t now_monotonic_ms(void);
uint32_t now_realtime(void);
uint32_t monotonic_to_realime(uint32_t t);
uint32_t realime_to_monotonic(uint32_t t);

static inline int time_after_eq(uint32_t lhs, uint32_t rhs)
{
	return (lhs - rhs) < (UINT32_MAX / 2);
}

static inline int time_after(uint32_t lhs, uint32_t rhs)
{
	return (lhs != rhs) && time_after_eq(lhs, rhs);
}

static inline int time_before_eq(uint32_t lhs, uint32_t rhs)
{
	return (rhs - lhs) < (UINT32_MAX / 2);
}

static inline int time_before(uint32_t lhs, uint32_t rhs)
{
	return (lhs != rhs) && time_before_eq(lhs, rhs);
}

int set_non_block(int fd);

int parse_ini_file(const char *fn,
		int (*section_cb)(const char *section),
		int (*key_cb)(const char *key, const char *value));

int utils_validate_label(const char *buf, size_t len);

#endif
