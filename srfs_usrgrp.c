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

#include "srfs_usrgrp.h"
#include "srfs_protocol.h"

typedef struct srfs_authuser {
	char usrname[SRFS_MAXLOGNAMELEN];
	uid_t uid;
	gid_t gid;
} srfs_authuser_t;

static srfs_authuser_t *authusers = NULL;

char *
srfs_namebyuid(uid_t uid)
{
	struct passwd *pwd;

	if ((pwd = getpwuid(uid)))
		if (strlen(pwd->pw_name) < SRFS_MAXLOGNAMELEN)
			return (pwd->pw_name);

	return ("nobody");
}

uid_t
srfs_uidbyname(char *usrname)
{
	struct passwd *pwd;

	if (!(pwd = getpwnam(usrname)))
		pwd = getpwnam("nobody");

	if (pwd)
		return (pwd->pw_uid);

	return (65534);
}

gid_t
srfs_gidbyuid(uid_t uid)
{
	struct passwd *pwd;

	if (!(pwd = getpwuid(uid)))
		pwd = getpwnam("nobody");

	if (pwd)
		return (pwd->pw_gid);

	return (65534);
}

char *srfs_namebygid(gid_t gid)
{
	struct group *grp;

	if ((grp = getgrgid(gid)))
		if (strlen(grp->gr_name) < SRFS_MAXGRPNAMELEN)
			return (grp->gr_name);

	return ("nogroup");
}

uid_t srfs_gidbyname(char *grpname)
{
	struct group *grp;

	if (!(grp = getgrnam(grpname)))
		grp = getgrnam("nogroup");

	if (grp)
		return (grp->gr_gid);

	return (65533);
}

char *
srfs_homebyuid(uid_t uid)
{
	struct passwd *pwd;

	if ((pwd = getpwuid(uid)))
		return (pwd->pw_dir);

	return (NULL);
}

void
sfrs_set_authenticated(char *usrname)
{
	uid_t uid;
	gid_t gid;

	uid = srfs_uidbyname(usrname);
	if (!uid)
		return;

	gid = srfs_gidbyuid(uid);

	if (!authusers)
		authusers = calloc(1, sizeof(srfs_authuser_t) * 10);

	for (int i = 0; i < 10; i++) {
		if (!authusers[i].uid) {
			strcpy(authusers[i].usrname, usrname);
			authusers[i].uid = uid;
			authusers[i].gid = gid;
			return;
		}
	}
printf("auth overflow!\n");
}

int
srfs_usr_authenticated(char *usrname)
{
	if (!authusers)
		return (0);

	for (int i = 0; i < 10; i++)
		if (strcmp(authusers[i].usrname, usrname) == 0)
			return (1);

	return (0);
}

int
srfs_uid_authenticated(uid_t uid)
{
	if (!uid || !authusers)
		return (0);

	for (int i = 0; i < 10; i++)
		if (authusers[i].uid == uid)
			return (1);

	return (0);
}
