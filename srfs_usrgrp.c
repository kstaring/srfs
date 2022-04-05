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
#include <sys/queue.h>

#include "srfs_usrgrp.h"
#include "srfs_protocol.h"

struct srfs_pwdcache {
	char *name;
	char *dir;
	uid_t uid;
	gid_t gid;
	LIST_ENTRY(srfs_pwdcache) list;
};

struct srfs_grpcache {
	char *name;
	gid_t gid;
	LIST_ENTRY(srfs_grpcache) list;
};

struct srfs_authuser {
	char usrname[SRFS_MAXLOGNAMELEN];
	uid_t uid;
	gid_t gid;
	LIST_ENTRY(srfs_authuser) list;
};

LIST_HEAD(pwdcache, srfs_pwdcache);
static struct pwdcache pwdcache = LIST_HEAD_INITIALIZER(pwdcache);
LIST_HEAD(grpcache, srfs_grpcache);
static struct grpcache grpcache = LIST_HEAD_INITIALIZER(grpcache);
LIST_HEAD(authusers, srfs_authuser);
static struct authusers authusers = LIST_HEAD_INITIALIZER(authusers);

static struct srfs_pwdcache *
pwdcache_by_name(char *name)
{
	struct srfs_pwdcache *cache;
	struct passwd *pwd;

	LIST_FOREACH(cache, &pwdcache, list)
		if (strcmp(cache->name, name) == 0)
			return (cache);

	if (!(pwd = getpwnam(name)))
		return (NULL);

	cache = malloc(sizeof(struct srfs_pwdcache));
	cache->name = strdup(pwd->pw_name);
	cache->dir = strdup(pwd->pw_dir);
	cache->uid = pwd->pw_uid;
	cache->gid = pwd->pw_gid;
	LIST_INSERT_HEAD(&pwdcache, cache, list);

	return (cache);
}

static struct srfs_pwdcache *
pwdcache_by_uid(uid_t uid)
{
	struct srfs_pwdcache *cache;
	struct passwd *pwd;

	LIST_FOREACH(cache, &pwdcache, list)
		if (cache->uid == uid)
			return (cache);

	if (!(pwd = getpwuid(uid)))
		return (NULL);

	cache = malloc(sizeof(struct srfs_pwdcache));
	cache->name = strdup(pwd->pw_name);
	cache->dir = strdup(pwd->pw_dir);
	cache->uid = pwd->pw_uid;
	cache->gid = pwd->pw_gid;
	LIST_INSERT_HEAD(&pwdcache, cache, list);

	return (cache);
}

static struct srfs_grpcache *
grpcache_by_name(char *name)
{
	struct srfs_grpcache *cache;
	struct group *grp;

	LIST_FOREACH(cache, &grpcache, list)
		if (strcmp(cache->name, name) == 0)
			return (cache);

	if (!(grp = getgrnam(name)))
		return (NULL);

	cache = malloc(sizeof(struct srfs_grpcache));
	cache->name = strdup(grp->gr_name);
	cache->gid = grp->gr_gid;
	LIST_INSERT_HEAD(&grpcache, cache, list);

	return (cache);
}

static struct srfs_grpcache *
grpcache_by_gid(gid_t gid)
{
	struct srfs_grpcache *cache;
	struct group *grp;

	LIST_FOREACH(cache, &grpcache, list)
		if (cache->gid == gid)
			return (cache);

	if (!(grp = getgrgid(gid)))
		return (NULL);

	cache = malloc(sizeof(struct srfs_grpcache));
	cache->name = strdup(grp->gr_name);
	cache->gid = grp->gr_gid;
	LIST_INSERT_HEAD(&grpcache, cache, list);

	return (cache);
}

void
srfs_usrgrp_init(void)
{
	LIST_INIT(&pwdcache);
	LIST_INIT(&grpcache);
	LIST_INIT(&authusers);

	if (!(pwdcache_by_name("nobody"))) {
		printf("user nobody not found!\n");
		exit(1);
	}
	if (!(grpcache_by_name("nogroup"))) {
		printf("gropu nogroup not found!\n");
		exit(1);
	}
}

char *
srfs_namebyuid(uid_t uid)
{
	struct srfs_pwdcache *cache;

	if (!(cache = pwdcache_by_uid(uid)))
		return ("nobody");

	return (cache->name);
}

uid_t
srfs_uidbyname(char *usrname)
{
	struct srfs_pwdcache *cache;

	if (!(cache = pwdcache_by_name(usrname)))
		cache = pwdcache_by_name("nobody");

	return (cache->uid);
}

gid_t
srfs_gidbyuid(uid_t uid)
{
	struct srfs_pwdcache *cache;

	if (!(cache = pwdcache_by_uid(uid)))
		cache = pwdcache_by_name("nobody");

	return (cache->gid);
}

char *srfs_namebygid(gid_t gid)
{
	struct srfs_grpcache *cache;

	if (!(cache = grpcache_by_gid(gid)))
		cache = grpcache_by_name("nogroup");

	return (cache->name);
}

uid_t srfs_gidbyname(char *grpname)
{
	struct srfs_grpcache *cache;

	if (!(cache = grpcache_by_name(grpname)))
		cache = grpcache_by_name("nogroup");

	return (cache->gid);
}

char *
srfs_homebyuid(uid_t uid)
{
	struct srfs_pwdcache *cache;

	if (!(cache = pwdcache_by_uid(uid)))
		cache = pwdcache_by_name("nobody");

	return (cache->dir);
}

int
srfs_usrisnobody(char *usrname)
{
	uid_t uid;

	uid = srfs_uidbyname(usrname);

	return (strcmp(srfs_namebyuid(uid), "nobody") == 0);
}

void
sfrs_set_authenticated(char *usrname)
{
	struct srfs_authuser *user;
	uid_t uid;
	gid_t gid;

	uid = srfs_uidbyname(usrname);
	if (!uid)
		return;

	gid = srfs_gidbyuid(uid);

	user = malloc(sizeof(struct srfs_authuser));
	strcpy(user->usrname, usrname);
	user->uid = uid;
	user->gid = gid;

	LIST_INSERT_HEAD(&authusers, user, list);
}

int
srfs_usr_authenticated(char *usrname)
{
	struct srfs_authuser *user;

	LIST_FOREACH(user, &authusers, list)
		if (strcmp(user->usrname, usrname) == 0)
			return (1);

	return (0);
}

int
srfs_uid_authenticated(uid_t uid)
{
	struct srfs_authuser *user;

	LIST_FOREACH(user, &authusers, list)
		if (user->uid == uid)
			return (1);

	return (0);
}

void
srfs_flush_auth(void)
{
	struct srfs_authuser *user;

	while (!LIST_EMPTY(&authusers)) {
		user = LIST_FIRST(&authusers);
		LIST_REMOVE(user, list);
		free(user);
	}
}
