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

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "log.h"
#include "utils.h"

uint32_t now_monotonic(void)
{
	struct timespec ts;

	int ret = clock_gettime(CLOCK_MONOTONIC, &ts);
	if (ret != 0) {
		log_errno_fatal("clock_gettime(CLOCK_MONOTONIC)");
		abort();
	}

	return (uint32_t)ts.tv_sec;
}

uint32_t now_monotonic_ms(void)
{
	struct timespec ts;

	int ret = clock_gettime(CLOCK_MONOTONIC, &ts);
	if (ret != 0) {
		log_errno_fatal("clock_gettime(CLOCK_MONOTONIC)");
		abort();
	}

	return (uint32_t)ts.tv_sec * 1000u + (uint32_t)(ts.tv_nsec / 1000000l);
}

uint32_t now_realtime(void)
{
	struct timespec ts;

	int ret = clock_gettime(CLOCK_REALTIME, &ts);
	if (ret != 0) {
		log_errno_fatal("clock_gettime(CLOCK_REALTIME)");
		abort();
	}

	return (uint32_t)ts.tv_sec;
}

int set_non_block(int fd)
{
	int ret = fcntl(fd, F_GETFL);
	if (ret < 0)
		return -errno;

	ret = fcntl(fd, F_SETFL, ret | O_NONBLOCK);
	if (ret < 0)
		return -errno;

	return 0;
}

int parse_ini_file(const char *fn,
		int (*section_cb)(const char *section),
		int (*key_cb)(const char *key, const char *value))
{
	FILE *f = fopen(fn, "r");
	if (!f)
		return -ENOENT;

	unsigned line = 0;
	int ret = 0;
	char buf[1024];
	while (ret >= 0 && fgets(buf, sizeof(buf), f) != NULL) {
		char *s = buf;
		char *e = s + strlen(s);
		line++;

		// verify that we got a whole line
		if (e-- == s)
			continue;
		if (*e != '\n') {
			ret = -ENOSPC;
			break;
		}
		*e-- = '\0';

		// skip leading blank
		while (*s && isblank((unsigned char)*s))
			s++;

		// skip empty lines or comments
		if (*s == '\0' || *s == ';' || *s == '#')
			continue;

		// section?
		if (*s == '[') {
			// cut trailing whitespace
			while (s < e && isblank((unsigned char)*e))
				*e-- = '\0';

			// section name must be terminated with ']'
			if (*e != ']') {
				log_err("Missing closing bracket in %s at line %u",
					fn, line);
				ret = -EINVAL;
				break;
			}

			*e = '\0';
			ret = section_cb(s+1);
		} else {
			char *eq = strchr(s, '=');
			if (!eq) {
				log_err("Missing = in %s at line %u",
					fn, line);
				ret = -EINVAL;
				break;
			}

			*eq = '\0';
			ret = key_cb(s, eq+1);
		}
	}

	fclose(f);
	return ret;
}

static int utils_is_letter(char c)
{
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

static int utils_is_let_dig(char c)
{
	return (c >= '0' && c <= '9') || utils_is_letter(c);
}

static int utils_is_let_dig_hyp(char c)
{
	return c == '-' || utils_is_let_dig(c);
}

// RFC 1035 2.3.1.
int utils_validate_label(const char *buf, size_t len)
{
	if (len == 0u)
		return 0;
	if (len > MAX_LABEL_SIZE)
		return -EINVAL;

	// first character must be a letter
	if (!utils_is_letter(*buf))
		return -EINVAL;
	buf++;
	len--;

	// middle characters may be letters, digits and hyphens
	while (len > 1u) {
		if (!utils_is_let_dig_hyp(*buf))
			return -EINVAL;
		buf++;
		len--;
	}

	// last character must be a letter or digit
	if (len && !utils_is_let_dig(*buf))
		return -EINVAL;

	return 1;
}
