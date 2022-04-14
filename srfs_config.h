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

#ifndef _SRFS_CONFIG_H
#define _SRFS_CONFIG_H

#define SRFS_BASE_CONFIG_PATH "/etc/srfs"
#define SRFS_CLIENT_CONFIG_FILE SRFS_BASE_CONFIG_PATH "/srfs.conf"
#define SRFS_SERVER_CONFIG_FILE SRFS_BASE_CONFIG_PATH "/srfsd.conf"
#define SRFS_EXPORTS_FILE SRFS_BASE_CONFIG_PATH "/exports"
#define SRFS_CLIENT_KEYS_DIR SRFS_BASE_CONFIG_PATH "/srfs_client_keys.d"

#define SRFS_AUTH_SOCKET "/var/run/srfs_auth.sock"

#define SRFS_SERVER_PRIVKEY SRFS_BASE_CONFIG_PATH "/server.key"
#define SRFS_SERVER_CERT SRFS_BASE_CONFIG_PATH "/server.crt"

#define SRFS_CLIENT_PRIVKEY SRFS_BASE_CONFIG_PATH "/client.key"
#define SRFS_CLIENT_PUBKEY SRFS_BASE_CONFIG_PATH "/client.pub"

#define SRFS_AUTH_METHOD_SRFS	(1 << 0)
#define SRFS_AUTH_METHOD_SSH	(1 << 1)
#define SRFS_AUTH_METHOD_PWD	(1 << 2)

typedef struct srfs_config {
	int allow_insecure_connect;
	int auth_methods;
} srfs_config_t;
extern srfs_config_t *srfs_config;

extern void srfs_config_init(char *path);

#endif
