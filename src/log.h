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
#ifndef LOG_H
#define LOG_H

#include <errno.h>
#include <stdio.h>
#include <string.h>

#define LOG_LEVEL_FATAL 0
#define LOG_LEVEL_ERR   1
#define LOG_LEVEL_WARN  2
#define LOG_LEVEL_INFO  3
#define LOG_LEVEL_DBG   4

int log_level;

#define log_fatal(fmt, ...) do { \
		if (log_level >= LOG_LEVEL_FATAL) \
			fprintf(stderr, "%s:%d fatal: " fmt "\n", __func__, \
			        __LINE__, ##__VA_ARGS__); \
	} while (0)

#define log_errno_fatal(fmt, ...) ({ \
		int err = errno; \
		log_fatal(fmt ": %s (%d)", ##__VA_ARGS__, strerror(err), err); \
		-err; \
	})

#define log_err(fmt, ...) do { \
		if (log_level >= LOG_LEVEL_ERR) \
			fprintf(stderr, "%s:%d error: " fmt "\n", __func__, \
			        __LINE__, ##__VA_ARGS__); \
	} while (0)

#define log_errno_err(fmt, ...) ({ \
		int err = errno; \
		log_err(fmt ": %s (%d)", ##__VA_ARGS__, strerror(err), err); \
		-err; \
	})

#define log_warn(fmt, ...) do { \
		if (log_level >= LOG_LEVEL_WARN) \
			fprintf(stderr, "%s:%d warning: " fmt "\n", __func__, \
			        __LINE__, ##__VA_ARGS__); \
	} while (0)

#define log_errno_warn(fmt, ...) ({ \
		int err = errno; \
		log_warn(fmt ": %s (%d)", ##__VA_ARGS__, strerror(err), err); \
		-err; \
	})

#define log_info(fmt, ...) do { \
		if (log_level >= LOG_LEVEL_INFO) \
			fprintf(stderr, "%s:%d info: " fmt "\n", __func__, \
			        __LINE__, ##__VA_ARGS__); \
	} while (0)

#define log_dbg(fmt, ...) do { \
		if (log_level >= LOG_LEVEL_DBG) \
			fprintf(stderr, "%s:%d dbg: " fmt "\n", __func__, \
			        __LINE__, ##__VA_ARGS__); \
	} while (0)

struct sockaddr_storage;
const char *log_ntop(struct sockaddr_storage *addr);

#endif
