#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "daemon.h"
#include "db.h"
#include "dns.h"
#include "poll.h"
#include "log.h"

static struct poll_set *ps;

static int dns_udp_fd = -1;
static int dns_udp_feed = -1;
static int dns_tcp_fd = -1;
static int dns_tcp_feed = -1;
static int http_fd = -1;
static int http_feed = -1;

int daemon_get_dns_tcp_socket(void) { return dns_tcp_fd; }
int daemon_get_dns_udp_socket(void) { return dns_udp_fd; }
int daemon_get_http_socket(void) { return http_fd; }

int listen(int sockfd, int backlog)
{
	(void)sockfd;
	(void)backlog;
	return 0;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	(void)sockfd;
	(void)addr;
	(void)addrlen;
	return dup(1);
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
	struct sockaddr *src_addr, socklen_t *addrlen)
{
	(void)flags;
	memset(src_addr, 0, *addrlen);
	poll_set_interrupt(ps);
	return read(sockfd, buf, len);
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
	const struct sockaddr *dest_addr, socklen_t addrlen)
{
	(void)sockfd;
	(void)flags;
	(void)dest_addr;
	(void)addrlen;
	poll_set_interrupt(ps);
	return write(1, buf, len);
}

int shutdown(int sockfd, int how)
{
	(void)sockfd;
	(void)how;
	poll_set_interrupt(ps);
	return 0;
}

/*****************************************************************************/

static void init_fds(void)
{
	int pfds[2];

	pipe(pfds);
	dns_udp_fd = pfds[0];
	dns_udp_feed = pfds[1];

	pipe(pfds);
	dns_tcp_fd = pfds[0];
	dns_tcp_feed = pfds[1];

	pipe(pfds);
	http_fd = pfds[0];
	http_feed = pfds[1];
}

static void fuzz_dns_udp(void)
{
	init_fds();

	char buf[4096];
	write(dns_udp_feed, buf, read(0, buf, sizeof(buf)));

	struct dns_server *s = dns_server_new(ps);
	poll_set_dispatch(ps);
	dns_server_delete(&s);
}

static void usage(void)
{
	fprintf(stderr, "usage: nanodnsd-fuzz <cfg> <dns-udp|dns-tcp|http>\n");
	exit(1);
}

int main(int argc, char **argv)
{
	log_level = -1;
	if (argc != 3)
		usage();

	if (db_init(argv[1]) < 0) {
		fprintf(stderr, "error reading cfg!\n");
		return 1;
	}

	ps = poll_set_new();

	if (strcmp(argv[2], "dns-udp") == 0)
		fuzz_dns_udp();

	poll_set_delete(&ps);

	return 0;
}
