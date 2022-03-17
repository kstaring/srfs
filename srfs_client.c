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

#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include "srfs_client.h"

SSL_CTX *ctx = NULL;
SSL *ssl = NULL;

void
srfs_client_init(void)
{
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();
	SSL_load_error_strings();

	if (SSL_library_init() < 0) {
		printf("couldn't init SSL\n");
		exit(1);
	}

	ctx = SSL_CTX_new(TLS_client_method());
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
			    SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_BOTH);
}

int
srfs_connect(char *server_path)
{
	struct addrinfo hints, *res, *i;
	char *server;
	char *path;
	char *sep;
	char port[6];
	char buf[9];
	int fd;

	if (!(sep = index(server_path, ':')))
		return (0);

	*sep = '\0';

	server = server_path;
	path = sep + 1;
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
		
		break;
	}
	freeaddrinfo(res);

	if (fd == -1)
		return (0);

	ssl = SSL_new(ctx);
	SSL_set_tlsext_host_name(ssl, server);
	SSL_set_fd(ssl, fd);

	if (SSL_connect(ssl) <= 0) {
		srfs_disconnect();
		return (0);
	}

	bzero(buf, 9);
	SSL_read(ssl, buf, 8);

	if (strcmp(buf, SRFS_IDENT) != 0) {
		srfs_disconnect();
		return (0);
	}

	return (1);
}

void
srfs_disconnect(void)
{
	SSL_shutdown(ssl);
	SSL_free(ssl);
	ssl = NULL;
}

int
srfs_fd(void)
{
	return (SSL_get_fd(ssl));
}
