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
#include <inttypes.h>

#include "log.h"

int log_level = LOG_LEVEL_ERR;

const char *log_ntop(struct sockaddr_storage *addr)
{
        static char tmp[INET6_ADDRSTRLEN + 16];

	switch (addr->ss_family) {
	case AF_INET6:
	{
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)addr;
		tmp[0] = '[';
		if (!inet_ntop(AF_INET6, &in6->sin6_addr, tmp+1, sizeof(tmp)-1U))
			return "<err>";
		size_t e = strlen(tmp);
		snprintf(tmp + e, sizeof(tmp) - e, "]:%" PRIu16, ntohs(in6->sin6_port));
		break;
	}
	case AF_INET:
	{
		struct sockaddr_in *in = (struct sockaddr_in *)addr;
		if (!inet_ntop(AF_INET, &in->sin_addr, tmp, sizeof(tmp)))
			return "<err>";
		size_t e = strlen(tmp);
		snprintf(tmp + e, sizeof(tmp) - e, ":%" PRIu16, ntohs(in->sin_port));
		break;
	}
	default:
		return "<unknown>";
	}

        return tmp;
}
