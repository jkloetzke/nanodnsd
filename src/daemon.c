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

#include <stdio.h>
#include <stdlib.h>
#include <systemd/sd-daemon.h>

#include "daemon.h"
#include "log.h"

enum socket_type
{
	SOCK_TYPE_INVALID = 0,
	SOCK_TYPE_HTTP,
	SOCK_TYPE_DNS_UDP,
	SOCK_TYPE_DNS_TCP,
};

struct daemon_socket
{
	int fd;
	enum socket_type type;
};

static unsigned daemon_sockets_num;
static struct daemon_socket *daemon_sockets;

static int daemon_socket_get(unsigned idx, enum socket_type type)
{
	for (unsigned i = 0; i < daemon_sockets_num; i++) {
		if (daemon_sockets[i].type != type)
			continue;
		if (idx == 0U)
			return daemon_sockets[i].fd;
		idx--;
	}

	return -ENOENT;
}

static int daemon_wd_timer(void *ctx)
{
	(void)ctx;

	sd_notify(0, "WATCHDOG=1");

	return 0;
}

int daemon_init(void)
{
	/*
	 * Make sure stdout is line buffered. On glibc it is block buffered if
	 * it is not connected to a tty which is the typical case when running
	 * as a daemon.
	 */
	setlinebuf(stdout);

	/*
	 * Let's see if we got sockets passed by systemd.
	 */

	char **names = NULL;
	int nfds = sd_listen_fds_with_names(1, &names);
	if (nfds < 0)
		return nfds;

	if (nfds) {
		if (!names) {
			log_fatal("No FileDescriptorName= available to passed sockets!");
			return -EINVAL;
		}

		daemon_sockets_num = (unsigned)nfds;
		daemon_sockets = calloc(daemon_sockets_num, sizeof(daemon_sockets[0]));
		if (!daemon_sockets)
			return -ENOMEM;
	}

	for (int i = 0; i < nfds; i++) {
		int fd = SD_LISTEN_FDS_START + i;

		daemon_sockets[i].fd = fd;
		if (strcmp(names[i], "dns") == 0) {
			if (sd_is_socket(fd, AF_UNSPEC, SOCK_STREAM, 1) > 0)
				daemon_sockets[i].type = SOCK_TYPE_DNS_TCP;
			else if (sd_is_socket(fd, AF_UNSPEC, SOCK_DGRAM, -1) > 0)
				daemon_sockets[i].type = SOCK_TYPE_DNS_UDP;
			else
				log_err("Unknown dns socket passsed! Ignoring.");
		} else if (strcmp(names[i], "http") == 0) {
			if (sd_is_socket(fd, AF_UNSPEC, SOCK_STREAM, 1) > 0)
				daemon_sockets[i].type = SOCK_TYPE_HTTP;
			else
				log_err("Unknown http socket passsed! Ignoring.");
		} else {
			log_err("Ignoring unkown socket '%s'", names[i]);
		}

		free(names[i]);
	}
	free(names);

	return 0;
}

int daemon_ready(struct poll_set *ps)
{
	uint64_t wd_usec = 0;
	int ret = sd_watchdog_enabled(0, &wd_usec);
	if (ret < 0)
		return ret;

	if (ret > 0 && wd_usec > 0) {
		ret = poll_set_add_timer(ps, NULL, (uint32_t)(wd_usec / 1000u / 2u),
			daemon_wd_timer, NULL);
		if (ret < 0)
			return ret;
	}

	sd_notify(0, "READY=1");

	return 0;
}

int daemon_get_http_socket(unsigned idx)
{
	return daemon_socket_get(idx, SOCK_TYPE_HTTP);
}

int daemon_get_dns_udp_socket(unsigned idx)
{
	return daemon_socket_get(idx, SOCK_TYPE_DNS_UDP);
}

int daemon_get_dns_tcp_socket(unsigned idx)
{
	return daemon_socket_get(idx, SOCK_TYPE_DNS_TCP);
}
