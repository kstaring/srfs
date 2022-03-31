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
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>

#include "srfs_pki.h"
#include "srfs_config.h"

static RSA *host_privkey = NULL;
static RSA *host_pubkey = NULL;

static RSA *
srfs_load_privkey(char *path)
{
	RSA *res;
	FILE *f;

	if (!(f = fopen(path, "r")))
		return (NULL);
	res = PEM_read_RSAPrivateKey(f, NULL, NULL, NULL);
	fclose(f);

	return (res);
}

static RSA *
srfs_load_pubkey(char *path)
{
	RSA *res;
	FILE *f;

	if (!(f = fopen(path, "r")))
		return (NULL);
	res = PEM_read_RSA_PUBKEY(f, NULL, NULL, NULL);
	fclose(f);

	return (res);
}

int
srfs_load_hostkeys(void)
{
	if (!(host_privkey = srfs_load_privkey(SRFS_HOST_PRIVKEY)))
		printf("Couldn't load %s\n", SRFS_HOST_PRIVKEY);

	if (!(host_pubkey = srfs_load_pubkey(SRFS_HOST_PUBKEY)))
		printf("Couldn't load %s\n", SRFS_HOST_PUBKEY);

	return (1);
}

RSA *
srfs_host_privkey(void)
{
	return (host_privkey);
}

RSA *
srfs_host_pubkey(void)
{
	return (host_pubkey);
}

int
srfs_rsa_sign(RSA *priv, char *msg, size_t msgsize,
	      char **sign, size_t *signsize)
{
	EVP_PKEY *privkey;
	EVP_MD_CTX *ctx;
	int res = 0;

	privkey = EVP_PKEY_new();
	ctx = EVP_MD_CTX_new();
	EVP_PKEY_assign_RSA(privkey, priv);

	if (!EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, privkey))
		goto srfs_rsa_sign_end;
	if (!EVP_DigestSignUpdate(ctx, msg, msgsize))
		goto srfs_rsa_sign_end;
	if (!EVP_DigestSignFinal(ctx, NULL, signsize))
		goto srfs_rsa_sign_end;

	*sign = malloc(*signsize);

	if (!EVP_DigestSignFinal(ctx, (unsigned char *)*sign, signsize))
		free(*sign);
	else
		res = 1;

srfs_rsa_sign_end:
	EVP_MD_CTX_free(ctx);

	return (res);
}

int
srfs_rsa_sign_path(char *path, char *msg, size_t msgsize,
		   char **sign, size_t *signsize)
{
	RSA *priv;
	int res;

	if (!(priv = srfs_load_privkey(path)))
		return (0);

	res = srfs_rsa_sign(priv, msg, msgsize, sign, signsize);

	RSA_free(priv);

	return (res);
}

int
srfs_rsa_verify(RSA *pub, char *msg, size_t msgsize,
		char *sign, size_t signsize)
{
	EVP_PKEY *pubkey;
	EVP_MD_CTX *ctx;
	int res = 0;

	pubkey = EVP_PKEY_new();
	ctx = EVP_MD_CTX_create();
	EVP_PKEY_assign_RSA(pubkey, pub);

	if (!EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pubkey))
		goto srfs_rsa_verify_end;
	if (!EVP_DigestVerifyUpdate(ctx, msg, msgsize))
		goto srfs_rsa_verify_end;
	if (!EVP_DigestVerifyFinal(ctx, (const unsigned char *)sign, signsize))
		goto srfs_rsa_verify_end;

	res = 1;

srfs_rsa_verify_end:
	EVP_MD_CTX_free(ctx);

	return (res);
}

int
srfs_rsa_verify_path(char *path, char *msg, size_t msgsize,
		     char *sign, size_t signsize)
{
	RSA *pub;
	int res;

	if (!(pub = srfs_load_pubkey(path)))
		return (0);

	res = srfs_rsa_verify(pub, msg, msgsize, sign, signsize);

	RSA_free(pub);

	return (res);
}
