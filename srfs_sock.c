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
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <signal.h>
#include <syslog.h>
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

#include "srfs_pki.h"
#include "srfs_sock.h"
#include "srfs_config.h"
#include "srfs_protocol.h"

static int sock_fd;
static SSL_CTX *ctx = NULL;
static SSL *ssl = NULL;

static char challenge[SRFS_CHALLENGE_SZ];

static char remote_peer[INET6_ADDRSTRLEN];

static int srfs_sock_generic_init(const SSL_METHOD *method);

char *
sign_challenge(void)
{
	return (challenge);
}

char *
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

void
srfs_server_listen(in_port_t port)
{
	struct sockaddr_in6 addr;
	int addrlen;
	int opt;

	if ((sock_fd = socket(AF_INET6, SOCK_STREAM, 0)) == -1)
		err(1, "Couldn't create socket");

	opt = 1;
	setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	opt = 0;
	if (setsockopt(sock_fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt,
		       sizeof(opt)) == -1)
		printf("setsockopt: failed setting IPV6_V6ONLY to 0\n");

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

void
srfs_accept_client(void)
{
	struct sockaddr_storage a;
	socklen_t len;
	int fd, rd, r;

	len = sizeof(struct sockaddr_storage);
	if ((fd = accept(sock_fd, (struct sockaddr *)&a, &len)) == -1) {
		perror("accept() failed");
		exit(1);
	}
	close(sock_fd);
	sock_fd = fd;

	strcpy(remote_peer, peername(&a));

	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, sock_fd);

	if (SSL_accept(ssl) != 1) {
		ERR_print_errors_fp(stdout);
		exit(1);
	}

	srfs_sock_write_sync(SRFS_IDENT, strlen(SRFS_IDENT));

	if ((fd = open("/dev/urandom", O_RDONLY)) == -1) {
		perror("open(/dev/urandom)");
		exit(1);
	}
	for (r = 0; r != SRFS_CHALLENGE_SZ; r += rd) {
		if ((rd = read(fd, challenge, SRFS_CHALLENGE_SZ)) == -1) {
			perror("read(/dev/urandom)");
			exit(1);
		}
	}
	close(fd);

	srfs_sock_write_sync(challenge, SRFS_CHALLENGE_SZ);

	syslog(LOG_DAEMON | LOG_INFO, "%s: connected", srfs_remote_ipstr());
}

static int
srfs_sock_generic_init(const SSL_METHOD *method)
{
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();
	ERR_load_crypto_strings();
	SSL_load_error_strings();

	if (SSL_library_init() < 0) {
		printf("Couldn't init SSL\n");
		return (0);
	}

	ctx = SSL_CTX_new(method);
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
			    SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_BOTH);

	return (1);
}

int
srfs_sock_client_init(void)
{
	return (srfs_sock_generic_init(TLS_client_method()));
}

int
srfs_sock_server_init(void)
{
	if (!srfs_sock_generic_init(TLS_server_method()))
		return (0);

	if (SSL_CTX_use_certificate_file(ctx, SRFS_HOST_CERT,
					 SSL_FILETYPE_PEM) != 1) {
		printf("Couldn't read %s\n", SRFS_HOST_CERT);
		return (0);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, SRFS_HOST_PRIVKEY,
					SSL_FILETYPE_PEM) != 1) {
		printf("Couldn't read %s\n", SRFS_HOST_PRIVKEY);
		return (0);
	}

	return (1);
}

ssize_t
srfs_sock_read_sync(char *buf, size_t size)
{
	ssize_t res, r;

	if (!ssl)
		return (-1);

	for (res = 0; res < size; res += r) {
		r = SSL_read(ssl, buf, size);
		if (r <= 0 && r != EINTR)
			return (-1);

		buf += r;
	}

	return (res);
}

ssize_t
srfs_sock_write_sync(char *buf, size_t size)
{
	ssize_t res, w;

	if (!ssl)
		return (-1);

	for (res = 0; res < size; res += w) {
		w = SSL_write(ssl, buf, size);
		if (w <= 0 && w != EINTR)
			return (-1);

		buf += w;
	}

	return (res);
}

int
srfs_sock_fd(void)
{
	return (sock_fd);
}

size_t
srfs_sock_pending(void)
{
	return (SSL_peek(ssl, NULL, INT_MAX));
}

void
srfs_sock_close(void)
{
	if (ssl) {
		SSL_shutdown(ssl);
		SSL_free(ssl);
		ssl = NULL;
	}
	if (sock_fd > 0) {
		close(sock_fd);
		sock_fd = 0;
	}
}

int
srfs_sock_connect(char *server)
{
	struct addrinfo hints, *res, *i;
	struct sockaddr_storage sa;
	socklen_t len;
	char port[6];
	char buf[9];
	int fd;

	snprintf(port, 6, "%d", SRFS_PORT);

	bzero(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(server, port, &hints, &res) != 0)
		return (0);

	for (fd = -1, i = res; i; i = i->ai_next) {
		fd = socket(i->ai_family, i->ai_socktype, i->ai_protocol);
		if (fd < 0)
			continue;

		if (connect(fd, i->ai_addr, i->ai_addrlen) == -1) {
			close(fd);
			continue;
		}

		len = sizeof(struct sockaddr_storage);
		bzero(&sa, len);
		if (getpeername(fd, (struct sockaddr *)&sa, &len) == 0)
			strcpy(remote_peer, peername(&sa));
		else
			strcpy(remote_peer, "unknown");
		break;
	}
	freeaddrinfo(res);

	if (fd == -1)
		return (0);

	ssl = SSL_new(ctx);
	SSL_set_tlsext_host_name(ssl, server);
	SSL_set_fd(ssl, fd);

	if (SSL_connect(ssl) <= 0) {
		srfs_sock_close();
		return (0);
	}

	bzero(buf, 8);
	srfs_sock_read_sync(buf, 7);

	if (strcmp(buf, SRFS_IDENT) != 0) {
		srfs_sock_close();
		return (0);
	}

	srfs_sock_read_sync(challenge, SRFS_CHALLENGE_SZ);

	return (1);
}

char *
srfs_remote_ipstr(void)
{
	if (strncmp(remote_peer, "::ffff:", 7) == 0)
		return (remote_peer + 7);

	return (remote_peer);
}
