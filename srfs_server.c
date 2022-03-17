/*
 * BSD 2-Clause License
 * 
 * Copyright (c) 2022, Khamba Staring <qdk@quickdekay.net>
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

static int main_daemon = 1;
static int sock_fd;

static SSL_CTX *ctx = NULL;
static SSL *ssl = NULL;

static char *peername(struct sockaddr_storage *addr);
static void server_listen(in_port_t port);
static void server_accept(void);
static void server_accept_loop(void);
static void usage(char *prog);
static void ssl_init(void);

static char *
peername(struct sockaddr_storage *addr)
{
	static char res[INET6_ADDRSTRLEN + 1];
	struct sockaddr_in6 *a6;
	struct sockaddr_in *a4;
	void *p;

	switch (addr->ss_family) {
	case AF_INET:
		a4 = (struct sockaddr_in *)addr;
		p = &a4->sin_addr;
		break;
	case AF_INET6:
		a6 = (struct sockaddr_in6 *)addr;
		p = &a6->sin6_addr;
		break;
	default:
		snprintf(res, INET6_ADDRSTRLEN, "ss_family unsupported: %d",
			addr->ss_family);
		return (res);
	}
	inet_ntop(addr->ss_family, p, res, INET6_ADDRSTRLEN);

	return (res);
}

static void
server_listen(in_port_t port)
{
	struct sockaddr_in6 addr;
	int addrlen;
	int opt;

	if ((sock_fd = socket(AF_INET6, SOCK_STREAM, 0)) == -1)
		err(1, "Couldn't create socket");

	opt = 1;
	setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	addrlen = sizeof(struct sockaddr_in6);
	bzero(&addr, addrlen);
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(port);
	addr.sin6_addr = in6addr_any;

	if (bind(sock_fd, (struct sockaddr *)&addr, addrlen) == -1) {
		perror("bind() failed");
		exit(1);
	}

	if (listen(sock_fd, 10) == -1) {
		perror("listen() failed");
		exit(1);
	}
}

static void
client_handle(void)
{
	char buf[1024];
	int r;

	if ((r = read(sock_fd, buf, 1024)) <= 0) {
		close(sock_fd);
		exit(0);
	}
}

static void
server_accept(void)
{
	struct sockaddr_storage a;
	socklen_t len;
	int fd;

	// check config + pubkey

	// then fork
	if (fork() == 0) {
		if ((fd = accept(sock_fd, (struct sockaddr *)&a, &len)) == -1) {
			perror("accept() failed");
			exit(1);
		}
		main_daemon = 0;
		close(sock_fd);
		sock_fd = fd;

		setproctitle("handler %s", peername(&a));
		printf("gotten connection from %s\n", peername(&a));

		ssl = SSL_new(ctx);
		SSL_set_fd(ssl, sock_fd);

		if (SSL_accept(ssl) != 1) {
			ERR_print_errors_fp(stdout);
			exit(1);
		}

		SSL_write(ssl, SRFS_IDENT, strlen(SRFS_IDENT));
	}
}

static void
server_accept_loop(void)
{
	struct pollfd pollfds[2];
	int n;

	for (;;) {
		pollfds[0].fd = sock_fd;
		pollfds[0].events = POLLIN;

		if ((n = poll(pollfds, 1, 1000)) > 0) {
			if (main_daemon) {
				server_accept();
				waitpid(-1, NULL, WNOHANG);
			} else {
				client_handle();
			}
		}
	}
}

static void
usage(char *prog)
{
	printf("Usage: %s [-f] [-d] [-p port]\n\n", prog);
	exit(1);
}

static void
ssl_init(void)
{
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();
	ERR_load_crypto_strings();
	SSL_load_error_strings();

	if (SSL_library_init() < 0) {
		printf("Couldn't init SSL\n");
		exit(1);
	}

	ctx = SSL_CTX_new(TLS_server_method());
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
			    SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_BOTH);

	if (SSL_CTX_use_certificate_file(ctx, SRFS_SERVER_PUBKEY,
					 SSL_FILETYPE_PEM) != 1) {
		printf("Couldn't read %s\n", SRFS_SERVER_PUBKEY);
		exit(1);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, SRFS_SERVER_PRIVKEY,
					SSL_FILETYPE_PEM) != 1) {
		printf("Couldn't read %s\n", SRFS_SERVER_PRIVKEY);
		exit(1);
	}
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

	ssl_init();
	server_listen(port);

	if (daemonize) {
		if (daemon(0, 0) != 0)
			err(1, "Couldn't daemonize");
		signal(SIGINT, SIG_IGN);
		signal(SIGQUIT, SIG_IGN);
		signal(SIGHUP, SIG_IGN);
	}
if (debug) { }
	setproctitle("listener");

	server_accept_loop();

	return (0);
}
