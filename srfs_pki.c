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
#include <string.h>
#include <syslog.h>
#include <sys/endian.h>
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

	if (!res)
		syslog(LOG_AUTH | LOG_NOTICE, "Could not load private key "
		       "%s for authentication purposes", path);

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
srfs_b64_decode(char *decoded, char *ptr, size_t b64size)
{
	BIO *b64_bio, *mem_bio;
	int res;

	b64_bio = BIO_new(BIO_f_base64());
	mem_bio = BIO_new(BIO_s_mem());
	BIO_write(mem_bio, ptr, b64size);
	BIO_push(b64_bio, mem_bio);
	BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);
	for (res = 0; BIO_read(b64_bio, decoded + res, 1) > 0 && res < b64size; res++) { }
	BIO_free_all(b64_bio);

	return (res);
}

static RSA *
srfs_load_pubkey_ssh(char *data, size_t size)
{
	char *hdrptr, *expptr, *modptr;
	uint32_t hdrsz, expsz, modsz;
	BIGNUM *expbn, *modbn;
	uint32_t *ptr;
	RSA *res;

	if (size < 4)
		return (NULL);

	ptr = (uint32_t *)data;
	hdrsz = be32toh(*ptr);
	hdrptr = data + sizeof(uint32_t);

	ptr = (uint32_t *)(hdrptr + hdrsz);
	if (size < (char *)ptr - data)
		return (NULL);

	expsz = be32toh(*ptr);
	expptr = (char *)ptr + sizeof(uint32_t);

	ptr = (uint32_t *)(expptr + expsz);
	if (size < (char *)ptr - data)
		return (NULL);

	modsz = be32toh(*ptr);
	modptr = (char *)ptr + sizeof(uint32_t);

	ptr = (uint32_t *)(modptr + modsz);
	if (size < (char *)ptr - data)
		return (NULL);

	if (strncmp(hdrptr, "ssh-rsa", 7) != 0)
		return (NULL);

	res = RSA_new();
	expbn = BN_new();
	modbn = BN_new();

	if (!BN_bin2bn((const unsigned char *)expptr, expsz, expbn))
		goto srfs_load_pubkey_ssh_fail;
	if (!BN_bin2bn((const unsigned char *)modptr, modsz, modbn))
		goto srfs_load_pubkey_ssh_fail;
	if (!RSA_set0_key(res, modbn, expbn, NULL))
		goto srfs_load_pubkey_ssh_fail;

	return (res);

srfs_load_pubkey_ssh_fail:
	BN_free(modbn);
	BN_free(expbn);
	RSA_free(res);
	return (NULL);
}

static RSA *
srfs_ssh_read_pubkey(FILE *f)
{
	char decoded[2048];
	char buf[2048];
	size_t b64size;
	char *endptr;
	char *ptr;

	if (!fgets(buf, 2047, f))
		return (NULL);

	if (strncmp(buf, "ssh-rsa ", 8) != 0)
		return (NULL);

	buf[2047] = '\0';
	ptr = buf + 8;
	if (!(endptr = index(ptr, ' '))) // malformed line
		return (NULL);

	b64size = endptr - ptr;
	srfs_b64_decode(decoded, ptr, b64size);

	return (srfs_load_pubkey_ssh(decoded, b64size));
}

int
srfs_load_hostkeys(void)
{
	if (!(host_privkey = srfs_load_privkey(SRFS_CLIENT_PRIVKEY)))
		printf("Couldn't load %s\n", SRFS_CLIENT_PRIVKEY);

	if (!(host_pubkey = srfs_load_pubkey(SRFS_CLIENT_PUBKEY)))
		printf("Couldn't load %s\n", SRFS_CLIENT_PUBKEY);

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
	FILE *f;

	if (!(f = fopen(path, "r")))
		return (0);

	for (; !feof(f);) {
		if ((pub = PEM_read_RSA_PUBKEY(f, NULL, NULL, NULL))) {
			if (srfs_rsa_verify(pub, msg, msgsize, sign, signsize)){
				RSA_free(pub);
				fclose(f);
				return (1);
			}
		}
		RSA_free(pub);
	}
	fclose(f);

	return (0);
}

int
srfs_ssh_verify_path(char *path, char *msg, size_t msgsize,
		     char *sign, size_t signsize)
{
	RSA *pub;
	FILE *f;

	if (!(f = fopen(path, "r")))
		return (0);

	for(; !feof(f);) {
		if (!(pub = srfs_ssh_read_pubkey(f)))
			continue;

		if (srfs_rsa_verify(pub, msg, msgsize, sign, signsize)) {
			RSA_free(pub);
			fclose(f);
			return (1);
		}
	}
	fclose(f);

	return (0);
}
