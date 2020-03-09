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
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "daemon.h"
#include "defs.h"
#include "db.h"
#include "log.h"
#include "poll.h"
#include "utils.h"

enum http_state
{
	STATE_START = 0,
	STATE_SKIP_HEADERS,
	STATE_DONE,
};

enum http_result
{
	HTTP_CODE_INVALID = 0,

	HTTP_CODE_OK = 200,
	HTTP_CODE_BAD_REQUEST = 400,
	HTTP_CODE_FORBIDDEN = 403,
	HTTP_CODE_NOT_FOUND = 404,
	HTTP_CODE_SERVER_ERROR = 500,
	HTTP_CODE_NOT_IMPLEMENTED = 501,
	HTTP_CODE_VERSION_NOT_SUPPORTED = 505,
};

static struct http_message {
	enum http_result code;
	char *message;
} CODE2MESSAGE[] = {
	{ HTTP_CODE_OK, "OK" },
	{ HTTP_CODE_BAD_REQUEST, "Bad request" },
	{ HTTP_CODE_FORBIDDEN, "Forbidden" },
	{ HTTP_CODE_NOT_FOUND, "Not found" },
	{ HTTP_CODE_SERVER_ERROR, "Internal server error" },
	{ HTTP_CODE_NOT_IMPLEMENTED, "Not implemented" },
	{ HTTP_CODE_VERSION_NOT_SUPPORTED, "Version not supported" },

	/* catch all must be last */
	{ HTTP_CODE_INVALID, "UNKNOWN" }
};

struct http_client
{
	char buf[8192];
	unsigned len;
	enum http_state state;
	enum http_result result;

	struct {
		char *hostname;
		char *token;
		char *ipv4;
		char *ipv6;
	} update;

	int fd;
	struct poll_source *io;
	struct poll_source *idle_timer;
};

static const char *code2message(enum http_result code)
{
	struct http_message *m = CODE2MESSAGE;
	while (m->code != HTTP_CODE_INVALID && m->code != code)
		m++;
	return m->message;
}

static char *strdupdecode(const char *s)
{
	// TODO
	return strdup(s);
}

static void http_free_client(struct http_client *client)
{
	free(client->update.hostname);
	free(client->update.token);
	free(client->update.ipv4);
	free(client->update.ipv6);

	shutdown(client->fd, SHUT_RDWR);
	poll_source_free(&client->idle_timer);
	poll_source_free(&client->io);
	free(client);
}

static enum http_result http_parse_request(struct http_client *client, char *line)
{
	char *method = line;
	char *url = strchr(method, ' ');
	if (!url)
		return HTTP_CODE_BAD_REQUEST;
	*url++ = '\0';
	char *version = strchr(url, ' ');
	if (!version)
		return HTTP_CODE_BAD_REQUEST;
	*version++ = '\0';

	if (strcmp(version, "HTTP/1.1") != 0 && strcmp(version, "HTTP/1.0") != 0)
		return HTTP_CODE_VERSION_NOT_SUPPORTED;

	if (strcmp(method, "GET") != 0 && strcmp(method, "POST") != 0)
		return HTTP_CODE_NOT_IMPLEMENTED;

	/*
	 * Ok, the request looks legit. Parse the URL. Schema:
	 *    "/api/update?hostname=home&ipv4=1.2.3.4&ipv6=1:2::7:8&token=secret
	 */

	char *fragment = strchr(url, '#');
	if (fragment)
		fragment = '\0';
	char *query = strchr(url, '?');
	if (query)
		*query++ = '\0';

	// we only support one path
	if (strcmp("/api/update", url) != 0)
		return HTTP_CODE_NOT_FOUND;

	// we're expecting a query
	if (!query)
		return HTTP_CODE_BAD_REQUEST;

	// walk query fragments
	for (char *f = query, *n = NULL; f != NULL; f = n) {
		// find next fragment
		n = strchr(f, '&');
		if (n)
			*n++ = '\0';

		char *key = f;
		char *val = strchr(key, '=');
		if (!val)
			return HTTP_CODE_BAD_REQUEST;
		*val++ = '\0';

		if (strcmp(key, "ipv4") == 0) {
			client->update.ipv4 = strdupdecode(val);
		} else if (strcmp(key, "ipv6") == 0) {
			client->update.ipv6 = strdupdecode(val);
		} else if (strcmp(key, "token") == 0) {
			client->update.token = strdupdecode(val);
		} else if (strcmp(key, "hostname") == 0) {
			client->update.hostname = strdupdecode(val);
		} else {
			// TODO: really log untrusted data?
			log_info("excessive parameter %s=%s ignored", key, val);
		}
	}

	return HTTP_CODE_OK;
}

static int http_handle_request(struct http_client *client)
{
	enum http_result result = client->result;
	char *response = NULL;

	// did we fail already prematurely?
	if (result != HTTP_CODE_OK)
		goto reply;

	if (!client->update.hostname) {
		response = "hostname required";
		result = HTTP_CODE_BAD_REQUEST;
		goto reply;
	}

	if (!client->update.token) {
		response = "authorization required";
		result = HTTP_CODE_FORBIDDEN;
		goto reply;
	}

	struct in_addr ipv4;
	struct in6_addr ipv6;

	if (client->update.ipv4) {
		int ret = inet_pton(AF_INET, client->update.ipv4, &ipv4);
		if (ret <= 0) {
			result = HTTP_CODE_BAD_REQUEST;
			response = "bad ipv4 address";
			goto reply;
		}
	}

	if (client->update.ipv6) {
		int ret = inet_pton(AF_INET6, client->update.ipv6, &ipv6);
		if (ret <= 0) {
			result = HTTP_CODE_BAD_REQUEST;
			response = "bad ipv6 address";
			goto reply;
		}
	}

	int ret = db_update(client->update.hostname,
		client->update.token,
		client->update.ipv4 ? &ipv4 : NULL,
		client->update.ipv6 ? &ipv6 : NULL);
	if (ret < 0) {
		if (ret == -EACCES) {
			response = "forbidden";
			result = HTTP_CODE_FORBIDDEN;
		} else {
			result = HTTP_CODE_SERVER_ERROR;
			response = "update failed";
		}
	}

reply:
	if (!response)
		response = result == HTTP_CODE_OK ? "ok" : "error";
	size_t content_length = strlen(response);

	log_info("req: hostname=%s, ipv4=%s, ipv6=%s -> %zu [%03d]",
		client->update.hostname ?: "<null>",
		client->update.ipv4 ?: "<null>",
		client->update.ipv6 ?: "<null>",
		content_length, result);

	char buf[1024];
	int len = snprintf(buf, sizeof(buf),
		"HTTP/1.1 %03d %s\r\n"
		"Content-Type: text/plain\r\n"
		"Content-Length: %zu\r\n"
		"Server: dynano/0.1.0\r\n"
		"Connection: close\r\n"
		"\r\n"
		"%s",
		result, code2message(result),
		content_length, response);

	if (len < 0)
		return log_errno_warn("snprintf");
	if ((size_t)len >= sizeof(buf)) {
		log_warn("oversized response: %d", len);
		len = sizeof(buf)-1;
	}

	ssize_t written;
	unsigned off = 0;
	while (len > 0) {
		do {
			written = write(client->fd, &buf[off], len);
		} while (written < 0 && errno == EINTR);

		if (written < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				log_warn("short reply");
				break;
			}
			return log_errno_warn("http reply write");
		} else if (written == 0) {
			log_warn("short reply");
			break;
		} else {
			len -= (int)written;
			off += (unsigned)written;
		}
	}

	return 0;
}

static int http_handle_data(struct http_client *client)
{
	while (client->len > 0) {
		if (client->state == STATE_DONE) {
			client->len = 0;
			break;
		}

		char *eol = strstr(client->buf, "\r\n");
		if (!eol)
			break;

		*eol = '\0';
		switch (client->state) {
		case STATE_START:
			client->result = http_parse_request(client, client->buf);
			client->state = STATE_SKIP_HEADERS;
			break;
		case STATE_SKIP_HEADERS:
			if (client->buf[0] == '\0') {
				int ret = http_handle_request(client);
				if (ret < 0)
					return ret;
				client->state = STATE_DONE;
			}
			break;
		default:
			break;
		}

		client->len -= eol - client->buf + 2;
		memmove(client->buf, eol+2, client->len + 1);
	}

	return 0;
}

static int http_handle_client(void *ctx, int fd, poll_event_t events)
{
	struct http_client *client = ctx;
	ssize_t len;

	if (events & (POLL_EVENT_ERR | POLL_EVENT_HUP)) {
		http_free_client(client);
		return 0;
	}

	if (events & POLL_EVENT_IN) {
		size_t avail;
		while ((avail = (sizeof(client->buf) - client->len - 1u)) > 0) {
			do {
				len = read(fd, &client->buf[client->len], avail);
			} while (len < 0 && errno == EINTR);

			if (len > 0) {
				client->len += (unsigned)len;
				client->buf[client->len] = '\0';
			} else if (len == 0) {
				http_free_client(client);
				return 0;
			} else if (errno == EAGAIN && errno == EWOULDBLOCK) {
				break;
			} else {
				log_errno_warn("client read failed");
				http_free_client(client);
				return 0;
			}
		}

		if (!avail)
			poll_source_mod_io_disable(client->io, POLL_EVENT_IN);
	}

	int ret = http_handle_data(client);
	if (ret < 0 || client->state == STATE_DONE) {
		http_free_client(client);
		return 0;
	}

	if (client->len < sizeof(client->buf)-1u)
		poll_source_mod_io_enable(client->io, POLL_EVENT_IN);

	return 0;
}

static int http_handle_timeout(void *ctx)
{
	struct http_client *client = ctx;

	log_dbg("client idle timeout");
	http_free_client(client);

	return 0;
}

static int http_handle_listen(void *ctx, int listen_fd, poll_event_t events)
{
	struct poll_set *ps = ctx;
	int fd, ret;

	if (events & (POLL_EVENT_ERR | POLL_EVENT_HUP))
		return -EIO;

	while ((fd = accept(listen_fd, NULL, NULL)) >= 0) {
		if ((ret = set_non_block(fd)) < 0) {
			log_err("set_non_block failed: %d", ret);
			close(fd);
			continue;
		}

		struct http_client *client = calloc(1, sizeof(struct http_client));
		if (!client) {
			log_err("OOM when accepting http client!");
			close(fd);
			continue;
		}

		client->fd = fd;
		ret = poll_set_add_io(ps, &client->io, fd, POLL_EVENT_IN,
			http_handle_client, client);
		if (ret < 0) {
			log_err("poll_set_add_io failed for client: %d", ret);
			close(fd);
			free(client);
			continue;
		}

		ret = poll_set_add_timer(ps, &client->idle_timer, db_get_http_timeout(),
			http_handle_timeout, client);
		if (ret < 0) {
			log_err("poll_set_add_timer failed: %d", ret);
			poll_source_free(&client->io);
			free(client);
		}
	}

	if (errno != EAGAIN && errno != EWOULDBLOCK)
		log_errno_warn("accept(tcp) failed");

	return 0;
}

static int http_create_socket(void)
{
	// create UDP IPv6 socket
	int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0)
		return log_errno_fatal("socket");

	// listen on IPv4 too
	int no = 0;
	int ret = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof(no));
	if (ret < 0) {
		close(fd);
		return log_errno_fatal("setsockopt(IPV6_V6ONLY)");
	}

	// bind to port
	struct sockaddr_in6 sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin6_family = AF_INET6;
	sa.sin6_port = htons(db_get_http_port());
	//sa.sin6_addr = IN6ADDR_ANY_INIT;
	ret = bind(fd, (struct sockaddr *)&sa, sizeof(sa));
	if (ret < 0) {
		close(fd);
		return log_errno_fatal("bind");
	}

	ret = listen(fd, 8);
	if (ret < 0) {
		close(fd);
		return log_errno_fatal("listen");
	}

	return fd;
}

int http_create_server(struct poll_set *ps)
{
	int fd, ret;

	fd = daemon_get_http_socket();
	if (fd < 0)
		fd = http_create_socket();
	if (fd < 0)
		return fd;

	// make non-blocking
	ret = set_non_block(fd);
	if (ret < 0) {
		close(fd);
		return ret;
	}

	// Add to event loop. Takes ownership of file descriptor.
	ret = poll_set_add_io(ps, NULL, fd, POLL_EVENT_IN, http_handle_listen, ps);
	if (ret < 0) {
		close(fd);
		log_fatal("poll_set_add_io failed: %d", ret);
		return ret;
	}

	return 0;
}
