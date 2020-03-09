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

#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "daemon.h"
#include "db.h"
#include "dns.h"
#include "http.h"
#include "log.h"
#include "poll.h"

// see LSB core init script actions chapter
// http://refspecs.linuxbase.org/LSB_3.1.1/LSB-Core-generic/LSB-Core-generic/iniscrptact.html
#define EXIT_INVALID_ARGS 2
#define EXIT_NOT_CONFIGURED 6

static void help(FILE *stream, bool full)
{
	fprintf(stream, "usage: nanodnsd [-c CFG] [-h] [-v]\n");
	if (full) {
		fprintf(stream, "\noptions\n");
		fprintf(stream, "    -c CFG      Read config from CFG. Default: " CMAKE_INSTALL_FULL_SYSCONFDIR "/nanodnsd.conf\n");
		fprintf(stream, "    -h          Show this help\n");
		fprintf(stream, "    -v          Increase log verbosity\n");
	}
}

int main(int argc, char **argv)
{
	const char *cfg = CMAKE_INSTALL_FULL_SYSCONFDIR "/nanodnsd.conf";
	int ret;

	/*
	 * Parse options
	 */
	int opt;
	while ((opt = getopt(argc, argv, "c:fhp:v")) != -1) {
		switch (opt) {
		case 'c':
			cfg = optarg;
			break;
		case 'h':
			help(stdout, true);
			return EXIT_SUCCESS;
		case 'v':
			log_level++;
			break;
		default: /* '?' or ':' */
			help(stderr, false);
			return EXIT_INVALID_ARGS;
		}
	}

	/*
	 * Init
	 */

	ret = daemon_init();
	if (ret < 0)
		return EXIT_FAILURE;

	ret = db_init(cfg);
	if (ret < 0)
		return ret == -EINVAL ? EXIT_NOT_CONFIGURED : EXIT_FAILURE;

	struct poll_set *ps = poll_set_new();
	if (!ps)
		return EXIT_FAILURE;

	ret = dns_create_server(ps);
	if (ret < 0)
		goto out;

	ret = http_create_server(ps);
	if (ret < 0)
		goto out;

	/*
	 * Run
	 */

	/*
	 * Drop privileges in case we're setuid root. Or switch to other user
	 * from config.
	 */
	uid_t uid;
	gid_t gid;
	db_get_user(&uid, &gid);
	if ((ret = setgid(gid)) < 0) {
		log_errno_fatal("cannot set group");
		goto out;
	}
	if ((ret = setuid(uid)) < 0) {
		log_errno_fatal("cannot set user");
		goto out;
	}

	if ((ret = daemon_ready(ps)) < 0) {
		log_fatal("Failed to talk to service manager: %s", strerror(-ret));
		goto out;
	}

	signal(SIGPIPE, SIG_IGN);
	ret = poll_set_dispatch(ps);

out:
	poll_set_delete(&ps);
	return ret >= 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
