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
#include <pwd.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <readpassphrase.h>

#include "srfs_protocol.h"

static int
usage(char *prog)
{
	printf("Usage: %s [-u username] [local mountpoint]\n\n", prog);
	return (1);
}

int
main(int argc, char *argv[])
{
	char userpass[SRFS_MAXLOGNAMELEN + _PASSWORD_LEN + 1];
	char *pass, *path, *prog;
	struct sockaddr_un un;
	struct passwd *pwd;
	char *user = NULL;
	char res[1024];
	int ch, fd, rd;
	socklen_t len;

	bzero(userpass, sizeof(userpass));

	prog = argv[0];

	if ((pwd = getpwuid(getuid())))
		user = pwd->pw_name;

	while ((ch = getopt(argc, argv, "u:")) != -1) {
		switch (ch) {
		case 'u': user = optarg; break;
		default: return usage(prog);
		}
	}
	argc -= optind;
	argv += optind;

	path = argv[0];
	if (!path) {
		printf("Mountpoint not specified\n");
		return usage(prog);
	}

	if (!user)
		err(ENOENT, "Couldn't retrieve username for uid %d, use -u",
		       getuid());

	if (strlen(user) >= SRFS_MAXLOGNAMELEN)
		err(ENAMETOOLONG, "Username too long: %s", user);

	strcpy(userpass, user);
	user = userpass;
	pass = user + strlen(user) + 1;
	if (!readpassphrase("Password:", pass, _PASSWORD_LEN, RPP_ECHO_OFF)) {
		printf("Couldn't read password\n");
		exit(1);
	}

	len = sizeof(struct sockaddr_un);
	bzero(&un, len);
	un.sun_family = AF_UNIX;
	if (snprintf(un.sun_path, SUNPATHLEN, "/var/run/srfs-auth%s.sock", path) == SUNPATHLEN)
		err(ENAMETOOLONG, "Socket path too long for local "
		    "mountpoint %s", path);

	for (int i = 18; un.sun_path[i]; i++)
		if (un.sun_path[i] == '/')
			un.sun_path[i] = '-';

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		err(errno, "Couldn't create socket");

	if (connect(fd, (struct sockaddr *)&un, len) == -1)
		err(errno, "Couldn't connect to srfs of mount %s", path);

	if (write(fd, userpass, strlen(user) + strlen(pass) + 2) == -1)
		err(errno, "Couldn't write to srfs socket for mount %s", path);
	if ((rd = read(fd, res, 1023)) == -1)
		err(errno, "Couldn't read from srfs socket for mount %s", path);

	res[rd] = '\0';
	printf("%s\n", res);

	return (0);
}
