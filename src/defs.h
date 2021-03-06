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
#ifndef DEFS_H
#define DEFS_H

#define MAX_DGRAM_SIZE (1232u)  // draft-fujiwara-dnsop-avoid-fragmentation-03
#define MAX_STREAM_SIZE (4096u)	// arbitrary but we should never have that much anyway
#define MAX_LABEL_SIZE (63u)    // RFC1035 2.3.4.
#define MAX_NAME_SIZE (255u)    // RFC1035 2.3.4.

#define DEFAULT_TCP_LINGER_TIME (3000u) // ms
#define DEFAULT_TCP_CONNECTIONS 16

#define DEFAULT_ENTRY_TTL 60 // s
#define DEFAULT_ORIGIN_TTL 86400 // s
#define DEFAULT_ENTRY_EXPIRE (60u*60u*24u) // s

#define DEFAULT_RATE_LIMIT 1000 // requests per second

#define DEFAULT_STATS_INTERVAL (24U*60U*60U*1000U) // ms

#define SECRET_ROLLOVER (24U*60U*60U*1000U) // ms, secret rollover time
#define SECRET_INVALIDATE (60U*1000U) // ms, invalidation timeout of old secret

#endif
