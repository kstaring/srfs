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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "srfs_config.h"

srfs_config_t *srfs_config = NULL;

static int srfs_config_read(char *path);

static int
srfs_config_bool(int line, char *buf)
{
	if (strcmp(buf, "true") == 0)
		return (1);
	if (strcmp(buf, "yes") == 0)
		return (1);
	if (strcmp(buf, "1") == 0)
		return (1);
	if (strcmp(buf, "false") == 0)
		return (1);
	if (strcmp(buf, "no") == 0)
		return (1);
	if (strcmp(buf, "0") == 0)
		return (1);

	printf("srfs_config: line %d: invalid boolean value: %s\n", line,
	       buf);
	exit(1);
}

static void
srfs_config_allow_insecure_connect(int line, char *buf)
{
	srfs_config->allow_insecure_connect = srfs_config_bool(line, buf);
}

static void
srfs_config_auth_methods(int line, char *buf)
{
	int auth_methods = 0;
	char *ptr, *token;

	token = ptr = buf;
	while (ptr) {
		if ((ptr = index(token, ','))) {
			*ptr = '\0';
			ptr++;
		}
		if (strcmp(token, "srfs_auth") == 0)
			auth_methods |= SRFS_AUTH_METHOD_SRFS;
		else if (strcmp(token, "ssh_auth") == 0)
			auth_methods |= SRFS_AUTH_METHOD_SSH;
		else if (strcmp(token, "password") == 0)
			auth_methods |= SRFS_AUTH_METHOD_PWD;
		else {
			printf("srfs_config: line %d: invalid value: %s\n",
			       line, token);
			exit(1);
		}
		token = ptr;
	}

	srfs_config->auth_methods = auth_methods;
}

static int
srfs_config_read(char *path)
{
	char buf[1024];
	char *ptr;
	FILE *f;

	if (!(f = fopen(path, "r")))
		return (0);

	for (int n = 0; fgets(buf, 1023, f); n++) {
		buf[1023] = '\0';
		if ((ptr = rindex(buf, '\n'))) *ptr = '\0';
		for (ptr = buf; *ptr == ' ' || *ptr == '\t'; ptr++) { }
		if (*ptr == '\0' || *ptr == '#')
			continue;

		if (strncmp(ptr, "auth_methods ", 13) == 0)
			srfs_config_auth_methods(n, ptr + 13);
#ifdef SRFS_CLIENT
		else if (strncmp(ptr, "allow_selfsigned_server ", 24) == 0)
			srfs_config_allow_insecure_connect(n, ptr + 24);
#endif
#ifdef SRFS_SERVER
		else if (strncmp(ptr, "allow_unknown_client_keys ", 26) == 0)
			srfs_config_allow_insecure_connect(n, ptr + 26);
#endif
		else {
			printf("srfs_config: line %d: invalid keyword: %s\n",
			       n, ptr);
			exit(1);
		}
	}

	fclose(f);

	return (1);
}

void
srfs_config_init(char *path)
{
	srfs_config = calloc(1, sizeof(srfs_config_t));

	srfs_config->allow_insecure_connect = 0;
	srfs_config->auth_methods = SRFS_AUTH_METHOD_SRFS |
				    SRFS_AUTH_METHOD_SSH;

	srfs_config_read(path);
}
