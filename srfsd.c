/*
 * BSD 2-Clause License
 * 
 * Copyright (c) 2022, Khamba Staring <staring@blingbsd.org>
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * 
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <poll.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

#include "srfs_config.h"
#include "srfs_protocol.h"
#include "srfsd.h"
#include "srfs_exports.h"
#include "srfs_server.h"
#include "srfs_sock.h"

static int main_daemon = 1;

static void sigint(int signal);

static void server_exit(void);
static void client_handle(short revents);
static void server_accept(void);
static void server_accept_loop(void);
static void usage(char *prog);

static void
sigint(int signal)
{
	srfs_exports_load();
}

static void
server_exit(void)
{
	srfs_sock_close();
	exit(0);
}

static void
client_handle(short revents)
{
	srfs_request_t req;
	int hdrsize;

	if (revents & POLLERR || revents & POLLHUP)
		server_exit();

	hdrsize = sizeof(srfs_request_t);

	if (srfs_sock_read_sync((char *)&req, hdrsize) < hdrsize)
		server_exit();

	srfs_request_handle(&req);
}

static void
server_accept(void)
{
	if (fork() == 0) {
		main_daemon = 0;
		srfs_accept_client();

		setproctitle("handler");
	}
}

static void
server_accept_loop(void)
{
	struct pollfd pollfds[2];
	time_t tm;
	int n;

	for (;;) {
		pollfds[0].fd = srfs_sock_fd();
		pollfds[0].events = POLLIN;

		if ((n = poll(pollfds, 1, 10000)) > 0) {
			if (main_daemon) {
				server_accept();
				waitpid(-1, NULL, WNOHANG);
			} else {
				client_handle(pollfds[0].revents);
			}
		}
		tm = time(NULL);
		if (tm % 10 == 0)
			srfs_server_periodic_cleanup();
	}
}

static void
usage(char *prog)
{
	printf("Usage: %s [-f] [-d] [-p port]\n\n", prog);
	exit(1);
}

int
main(int argc, char *argv[])
{
	//char *config = SRFS_CONFIG_FILE;
	uint64_t port = SRFS_PORT;
	char *endptr = NULL;
	int daemonize = 1;
	int debug = 0;
	int ch;

	while ((ch = getopt(argc, argv, "fdp:c:")) != -1) {
		switch (ch) {
		case 'f': daemonize = 0; break;
		case 'd': debug = 1; break;
		case 'p':
			port = strtol(optarg, &endptr, 10);
			if (endptr == NULL || *endptr != '\0' || port == 0 ||
			    port >= IPPORT_MAX)
				err(1, "illegal port: %s\n\n", optarg);
			break;
		default: usage(argv[0]); break;
		}
	}
	argc -= optind;
	argv += optind;

	srfs_server_init();

	if (!srfs_sock_server_init())
		exit(1);

	srfs_exports_load();
	srfs_server_listen(port);

	if (daemonize) {
		if (daemon(0, 0) != 0)
			err(1, "Couldn't daemonize");
		signal(SIGINT, sigint);
		signal(SIGQUIT, SIG_IGN);
		signal(SIGHUP, SIG_IGN);
	}
if (debug) { }
	setproctitle("listener");

	server_accept_loop();

	return (0);
}
