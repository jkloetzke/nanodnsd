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
#include <string.h>
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

#define STATE_FILE "nanodnsd.state"

static const char *default_cfg = CMAKE_INSTALL_FULL_SYSCONFDIR "/nanodnsd.conf";
static const char *default_state = CMAKE_INSTALL_FULL_LOCALSTATEDIR "/lib/nanodnsd/" STATE_FILE;

static void help(FILE *stream, bool full)
{
	fprintf(stream, "usage: nanodnsd [-c CFG] [-h] [-s STATE] [-v]\n");
	if (full) {
		fprintf(stream, "\noptions\n");
		fprintf(stream, "    -c CFG      Read config from CFG. Default: %s\n", default_cfg);
		fprintf(stream, "    -h          Show this help\n");
		fprintf(stream, "    -s STATE    Database state. Default: %s\n", default_state);
		fprintf(stream, "    -v          Increase log verbosity\n");
	}
}

static int handle_sigterm(void *ctx, int sig)
{
	(void)sig;
	struct poll_set *ps = ctx;
	poll_set_interrupt(ps);
	return 0;
}

int main(int argc, char **argv)
{
	struct http_server *http_server = NULL;
	struct dns_server *dns_server = NULL;
	int ret;

#ifdef HAVE_SD_DAEMON
	char *systemd_state = NULL;
	{
		char *e = getenv("STATE_DIRECTORY");
		if (e) {
			systemd_state = malloc(strlen(e) + strlen(STATE_FILE) + 2U);
			if (!systemd_state)
				return EXIT_FAILURE;
			strcpy(systemd_state, e);
			strcat(systemd_state, "/");
			strcat(systemd_state, STATE_FILE);
			default_state = systemd_state;
		}
	}
#endif

	/*
	 * Parse options
	 */
	int opt;
	const char *cfg = default_cfg;
	const char *state = default_state;
	while ((opt = getopt(argc, argv, "c:hs:v")) != -1) {
		switch (opt) {
		case 'c':
			cfg = optarg;
			break;
		case 'h':
			help(stdout, true);
			return EXIT_SUCCESS;
		case 's':
			state = optarg;
			break;
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

	ret = db_load_state(state);
	if (ret < 0 && ret != -ENOENT)
		return EXIT_FAILURE;

	struct poll_set *ps = poll_set_new();
	if (!ps)
		return EXIT_FAILURE;

	dns_server = dns_server_new(ps);
	if (!dns_server) {
		ret = -ENOMEM;
		goto out;
	}

	http_server = http_server_new(ps);
	if (!http_server) {
		ret = -ENOMEM;
		goto out;
	}

	/*
	 * Run
	 */
	signal(SIGPIPE, SIG_IGN);
	ret = poll_set_add_signal(ps, NULL, SIGINT, handle_sigterm, ps);
	if (ret < 0)
		goto out;
	ret = poll_set_add_signal(ps, NULL, SIGTERM, handle_sigterm, ps);
	if (ret < 0)
		goto out;

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

	ret = poll_set_dispatch(ps);
	if (ret >= 0)
		ret = db_save_state(state);
	else
		log_err("Not saving state due to previous errors");

out:
	http_server_delete(&http_server);
	dns_server_delete(&dns_server);
	poll_set_delete(&ps);
#ifdef HAVE_SD_DAEMON
	if (systemd_state)
		free(systemd_state);
#endif
	return ret >= 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
