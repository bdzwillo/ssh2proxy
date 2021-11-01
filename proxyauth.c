/*
 * proxyauth.c - ssh proxy authentication
 *
 * Copyright (c) 2009-2021 Barnim Dzwillo @ Strato AG
 * Parts of the code are based on the openssh project. See openssh/LICENCE.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <arpa/nameser.h>
#include <netinet/in.h>

#include "includes.h"
#include "log.h"
#include "xmalloc.h"
#include "ssh.h"
#include "ssh2.h"
#include "packet.h"
#include "cipher.h"
#include "digest.h"
#include "kex.h"
#include "mac.h"
#include "ssherr.h"
#include "sshbuf.h"
#include "sshkey.h"
#include "canohost.h"
#include "compat.h"
#include "misc.h"
#include "ssh_api.h"
#include "sshproxy.h"
#include "proxyconf.h"
#include "proxyauth.h"

int proxyauth_send_service_accept(struct ssh *ssh)
{
	int r;
	char *service = "ssh-userauth";

	if ((r = sshpkt_start(ssh, SSH2_MSG_SERVICE_ACCEPT)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, service)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0) {
		error("send_service_accept: service packet_write: %s", ssh_err(r));
		return r;
	}
	return 0;
}

int proxyauth_send_features(struct ssh *ssh, struct Authctxt *authctxt)
{
	char *p;
	char *mp;
	char server[1024];
	char client[1024];

	if (!authctxt->server_methods) {
		return SSH_ERR_INTERNAL_ERROR;
	}
	strlcpy(server, authctxt->server_methods, sizeof(server));
	mp = server;
	client[0] = '\0';

	for (p = strsep(&mp, ","); p && (*p != '\0'); p = strsep(&mp, ",")) {
		if (strcmp(p, "hostbased") == 0) {
			/* skip hostbased */
			continue;
		}
		if (client[0] != '\0') {
			strlcat(client, ",", sizeof(client));
		}
		strlcat(client, p, sizeof(client));
	}
	debug("methods server: %s client: %s",
			authctxt->server_methods, client);

	int r, partial = 0;

	if ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_FAILURE)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, client)) != 0 ||
	    (r = sshpkt_put_u8(ssh, partial)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0) {
		error("auth_send_features: %s", ssh_err(r));
		return r;
	}
	return 0;
}

int proxyauth_send_start_hostbased(struct ssh *ssh)
{
	int r, partial = 0;
	char *methods = "password,hostbased";

	if ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_FAILURE)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, methods)) != 0 ||
	    (r = sshpkt_put_u8(ssh, partial)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0) {
		error("auth_send_start_hostbased: %s", ssh_err(r));
		return r;
	}
	return 0;
}

int proxyauth_send_failure_passwd_only(struct ssh *ssh)
{
	int r, partial = 0;
	char *methods = "password";

	if ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_FAILURE)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, methods)) != 0 ||
	    (r = sshpkt_put_u8(ssh, partial)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0) {
		error("auth_send_failure_passwd_only: %s", ssh_err(r));
		return r;
	}
	return 0;
}

int proxyauth_recv_pk_ok(struct ssh *ssh, struct Authctxt *authctxt)
{
	int r;
	struct sshkey *key = NULL;
	int pktype;
	size_t blen;
	char *pkalg = NULL;
	char *fp = NULL;
	u_char *pkblob = NULL;

	if ((r = sshpkt_get_cstring(ssh, &pkalg, NULL)) != 0 ||
	    (r = sshpkt_get_string(ssh, &pkblob, &blen)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0) {
		error("auth_recv_pk_ok: parse request failed: %s", ssh_err(r));
		goto done;
	}

	debug("Server accepts key: pkalg %s blen %zu", pkalg, blen);

	pktype = sshkey_type_from_name(pkalg);
	if (pktype == KEY_UNSPEC) {
		error("auth_recv_pk_ok: unknown pkalg %s", pkalg);
		r = SSH_ERR_INTERNAL_ERROR;
		goto done;
	}
	if ((r = sshkey_from_blob(pkblob, blen, &key)) != 0) {
		error("auth_recv_pk_ok: no key from blob. pkalg %s: %s", pkalg, ssh_err(r));
		goto done;
	}
	if (key->type != pktype) {
		error("auth_recv_pk_ok: type mismatch for decoded key (received %d, expected %d)", key->type, pktype);
		r = SSH_ERR_KEY_TYPE_MISMATCH;
		goto done;
	}
	fp = sshkey_fingerprint(key, SSH_DIGEST_MD5, SSH_FP_HEX);

	debug("userauth_pk_ok: fp %s", fp);

	if (!authctxt->key) {
		error("pk_ok: no requested auth key for: %s", fp);
		r = SSH_ERR_INTERNAL_ERROR;
		goto done;
	}
	if (!sshkey_equal_public(key, authctxt->key)) {
		error("key does not match requested key: %s", fp);
		r = SSH_ERR_INVALID_ARGUMENT;
		goto done;
	}
	debug("userauth_pk_ok: type=%d OK", key->type);
	r = 0;
done:
	free(fp);
	sshkey_free(key);
	free(pkalg);
	free(pkblob);
	return r;
}

int proxyauth_recv_failure(struct ssh *ssh, struct Authctxt *authctxt)
{
	int r;
        char *authlist = NULL;
        u_char partial;

        if (authctxt == NULL) {
		error("auth_recv_failure: no authentication context");
		return SSH_ERR_INTERNAL_ERROR;
	}

        if ((r = sshpkt_get_cstring(ssh, &authlist, NULL)) != 0 ||
            (r = sshpkt_get_u8(ssh, &partial)) != 0 ||
            (r = sshpkt_get_end(ssh)) != 0) {
		error("auth_recv_failure: decode failed");
		return r;
	}
	authctxt->server_methods = authlist;
	return 0;
}

static char * format_key(const struct sshkey *key)
{
	char *ret, *fp = sshkey_fingerprint(key, SSH_DIGEST_MD5, SSH_FP_DEFAULT);

	xasprintf(&ret, "%s %s", sshkey_type(key), fp);
	free(fp);
	return ret;
}

static void dump_key(struct sshkey *k)
{
	struct sshbuf *b;
	char *b64;
	int r;

	if ((b = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshkey_putb(k, b)) != 0)
		fatal("key_to_blob failed: %s", ssh_err(r));
	if ((b64 = sshbuf_dtob64_string(b, 1)) == NULL)
		fatal("%s: sshbuf_dtob64_string failed", __func__);
	sshbuf_free(b);

	fprintf(stdout, "%s", b64);
	free(b64);
}

static void dump_base64(FILE *fp, const u_char *buf, size_t len)
{
	struct sshbuf *b;
	char *b64;
	int r;

	if ((b = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshbuf_put_string(b, buf, len)) != 0)
		fatal("key_to_blob failed: %s", ssh_err(r));
	if ((b64 = sshbuf_dtob64_string(b, 1)) == NULL)
		fatal("%s: sshbuf_dtob64_string failed", __func__);
	sshbuf_free(b);

	fprintf(stdout, "%s", b64);
	free(b64);
}

int proxyauth_recv_request(struct ssh *ssh, struct Authctxt *authctxt)
{
	char *user = NULL, *service = NULL, *method = NULL, *style = NULL;
	int r;

	if (authctxt == NULL) {
		error("input_userauth_request: no authctxt");
		return SSH_ERR_INTERNAL_ERROR;
	}
	if ((r = sshpkt_get_cstring(ssh, &user, NULL)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &service, NULL)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &method, NULL)) != 0) {
		free(service);
		free(user);
		free(method);
		return r;
	}
	debug("userauth-request for user %s service %s method %s",
		user, service, method);
	debug("attempt %d failures %d", authctxt->attempt, authctxt->failures);

	if ((style = strchr(user, ':')) != NULL)
		*style++ = 0;

	if (authctxt->attempt++ == 0) {
		/* setup auth context */
		authctxt->user = xstrdup(user);
		authctxt->service = xstrdup(service);
	} else if (authctxt->valid) {
		if (strcmp(user, authctxt->user) != 0 ||
		    strcmp(service, authctxt->service) != 0) {
			error("input_userauth_request: mismatch: (%s,%s)!=(%s,%s)",
			    user, service, authctxt->user, authctxt->service);
			authctxt->valid = 0;
		}
	}
	if (authctxt->method) {
		free(authctxt->method);
	}
	authctxt->method = xstrdup(method);

	if (strcmp(method, "none") == 0) {
		if ((r = sshpkt_get_end(ssh)) != 0) {
			error("auth2: none: %s", ssh_err(r));
			return r;
		}
		authctxt->authenticated = 0;
	} else if (strcmp(method, "password") == 0) {
		char *password;
		u_char change;
		size_t len;

		if ((r = sshpkt_get_u8(ssh, &change)) != 0 ||
		    (r = sshpkt_get_cstring(ssh, &password, &len)) != 0 ||
		    (change && (r = sshpkt_get_cstring(ssh, NULL, NULL)) != 0) ||
		    (r = sshpkt_get_end(ssh)) != 0) {
			error("auth2: password: %s", ssh_err(r));
			return r;
		}
		if (change) {
			error("password change not supported");
		}
		authctxt->passwd = password;
		//explicit_bzero(password, len);
		//free(password);
		authctxt->authenticated = 1;
	} else if (strcmp(method, "keyboard-interactive") == 0) {
		char *lang, *devs;

		if ((r = sshpkt_get_cstring(ssh, &lang, NULL)) != 0 ||
		    (r = sshpkt_get_cstring(ssh, &devs, NULL)) != 0 ||
		    (r = sshpkt_get_end(ssh)) != 0) {
			error("auth2: keyboard-interactive: %s", ssh_err(r));
			return r;
		}
		/* some clients like libssh-0.2 send keyboard-interactive
		 * requests even if the support was not signaled from the
		 * server side.
		 */
		error("auth2: keyboard-interactive requested: lang '%s' devs '%s'", lang, devs);

		free(devs);
		free(lang);
		authctxt->authenticated = 0;
	} else if (strcmp(method, "publickey") == 0) {
		char *pkalg = NULL;
		u_char *pkblob = NULL;
		size_t blen, slen;
		u_char have_sig;

		authctxt->authenticated = 0;

		if ((r = sshpkt_get_u8(ssh, &have_sig)) != 0 ||
		    (r = sshpkt_get_cstring(ssh, &pkalg, NULL)) != 0 ||
		    (r = sshpkt_get_string(ssh, &pkblob, &blen)) != 0) {
			error("auth2: parse request failed: %s", ssh_err(r));
			return r;
		}
		authctxt->have_sig = have_sig;

		int pktype;
		struct sshkey *key = NULL;

		pktype = sshkey_type_from_name(pkalg);
		if (pktype == KEY_UNSPEC) {
			/* this is perfectly legal */
			error("auth2: unsupported public key algorithm: %s", pkalg);
			return SSH_ERR_INTERNAL_ERROR;
		}
		if ((r = sshkey_from_blob(pkblob, blen, &key)) != 0) {
			error("auth2: could not parse key: %s", ssh_err(r));
			return r;
		}
		if (key->type != pktype) {
			error("auth2: type mismatch for decoded key (received %d, expected %d)", key->type, pktype);
			return SSH_ERR_KEY_TYPE_MISMATCH;
		}
		if (authctxt->key) {
		    sshkey_free(authctxt->key);
		}
		authctxt->key = key;

		if (authctxt->key != NULL) {
		    if(authctxt->have_sig) {
			char *userstyle = NULL, *key_s = NULL, *ca_s = NULL;
			u_char *sig = NULL;
			struct sshkey_sig_details *sig_details = NULL;

			key_s = format_key(key);
			if (sshkey_is_cert(key))
				ca_s = format_key(key->cert->signature_key);

			debug("auth2: have %s signature for %s%s%s", pkalg, key_s,
			    ca_s == NULL ? "" : " CA ",
			    ca_s == NULL ? "" : ca_s);

			if ((r = sshpkt_get_string(ssh, &sig, &slen)) != 0 ||
			    (r = sshpkt_get_end(ssh)) != 0) {
				error("auth2: get sig %s", ssh_err(r));
				return r;
			}
			struct sshbuf *b = NULL;

			if ((b = sshbuf_new()) == NULL) {
				error("auth2: sshbuf_new failed");
				return SSH_ERR_ALLOC_FAIL;
			}
			if (ssh->compat & SSH_OLD_SESSIONID) {
				if ((r = sshbuf_put(b, ssh->kex->session_id, ssh->kex->session_id_len)) != 0) {
					error("auth2: sshbuf_put session id: %s", ssh_err(r));
					return r;
				}
			} else {
				if ((r = sshbuf_put_string(b, ssh->kex->session_id, ssh->kex->session_id_len)) != 0) {
					error("auth2: sshbuf_put_string session id: %s", ssh_err(r));
					return r;
				}
			}
			//if (!authctxt->valid || authctxt->user == NULL) {
			//	error("auth2: disabled because of invalid user");
			//	return -1;
			//}
			/* reconstruct packet */
			xasprintf(&userstyle, "%s%s%s", authctxt->user,
			    authctxt->style ? ":" : "",
			    authctxt->style ? authctxt->style : "");
			if ((r = sshbuf_put_u8(b, SSH2_MSG_USERAUTH_REQUEST)) != 0 ||
			    (r = sshbuf_put_cstring(b, userstyle)) != 0 ||
			    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
			    (r = sshbuf_put_cstring(b, "publickey")) != 0 ||
			    (r = sshbuf_put_u8(b, have_sig)) != 0 ||
			    (r = sshbuf_put_cstring(b, pkalg)) != 0 ||
			    (r = sshbuf_put_string(b, pkblob, blen)) != 0) {
				error("auth2: build packet failed: %s", ssh_err(r));
				return r;
			}

			if (Opt_debug) {
				sshbuf_dump(b, stderr);
			}
			/* test for correct signature */
			authctxt->authenticated = 0;
			//if (!user_key_allowed(ssh, pw, key, 1, &authopts) {
			//	error("auth2: pubkey not allowed");
			//	return -1;
			//}
			if (sshkey_verify(key, sig, slen,
			    sshbuf_ptr(b), sshbuf_len(b),
			    (ssh->compat & SSH_BUG_SIGTYPE) == 0 ? pkalg : NULL,
			    ssh->compat, &sig_details) == 0) {
				authctxt->authenticated = 1;
				debug("pubkey: %s key_verify ok", pkalg);
			} else {
				error("pubkey: %s key_verify failed", pkalg);
			}
			sshbuf_free(b);
			//sshauthopt_free(authopts);
			free(userstyle);
			free(key_s);
			free(ca_s);
			free(sig);
			sshkey_sig_details_free(sig_details);
		    }
		}
		if (authctxt->key != NULL) {
			debug("pubkey: type=%d alg %s havesig: %d blob:", authctxt->key->type ? authctxt->key->type : -1 ,pkalg, authctxt->have_sig);
		} else {
			debug("pubkey: alg %s havesig: %d blob:", pkalg, authctxt->have_sig);
		}
		if (Opt_debug) {
			dump_base64(stderr, pkblob, blen);
		}
		free(pkalg);
		free(pkblob);
	} else {
		/* the request will be forwarded to the server side
		 * and result in a failure message to the client
		 */
		error("unsupported auth method: %s", method);

		authctxt->authenticated = 0;
		goto unsupported;
	}
unsupported:
	free(service);
	free(user);
	free(method);
	return 0;
}

int proxyauth_recv_auth_pkg(struct ssh *ssh, struct Authctxt *authctxt, struct sshbuf **auth_sbp)
{
	int r;
	u_int32_t seqnr;
	u_char type;
	const u_char *msg;
	size_t len;

	/* blocking recv()
	 */
	if ((r = ssh_packet_read_seqnr(ssh, &type, &seqnr)) != 0) {
		if (r == SSH_ERR_DISCONNECTED) {
			/* connection closed cleanly, has already been logged */
			debug("%s: auth receive got disconnect", ssh_remote_ipaddr(ssh));
			exit(1);
		}
		if (r == SSH_ERR_CONN_TIMEOUT) {
			/* select() timeout */
		}
		if (r == SSH_ERR_CONN_CLOSED) {
			/* read() returned 0 */
		}
		fatal("%s: auth receive username failed: %s", ssh_remote_ipaddr(ssh), ssh_err(r));
	}
	if (type != SSH2_MSG_USERAUTH_REQUEST) {
		fatal("%s: auth receive got type %d instead of USERAUTH", ssh_remote_ipaddr(ssh), type);
	}
	msg = sshpkt_ptr(ssh, &len);

	/* copy userauth request for proxy forward
	 */
	if ((*auth_sbp = sshbuf_from(msg, len)) == NULL) {
		fatal("%s: copy authpkt", ssh_remote_ipaddr(ssh));
	}
	/* msg is consumed here
	 */
	if (proxyauth_recv_request(ssh, authctxt) != 0) {
		fatal("%s: auth receive failed", ssh_remote_ipaddr(ssh));
	}
	return 0;
}

int proxyauth_send_hostbased(struct ssh *ssh, struct Authctxt *authctxt,
	struct sshkey *private)
{
	struct sshbuf *b = NULL;
	int r;
	size_t siglen = 0, keylen = 0;
	u_char *sig = NULL, *keyblob = NULL;
	char *chost = NULL, *lname = NULL;
	char *local_user = NULL;
	int len;
	char *fp = NULL;
	char *method = "hostbased";

	if ((fp = sshkey_fingerprint(private, SSH_DIGEST_MD5, SSH_FP_DEFAULT)) == NULL) {
		error("%s: sshkey_fingerprint failed", __func__);
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	lname = get_local_name(ssh_packet_get_connection_in(ssh));
	if (lname == NULL) {
		error("userauth_hostbased: cannot get local ipaddr/name");
		r = SSH_ERR_SYSTEM_ERROR; // use errno in ssh_err()
		goto out;
	}
	len = strlen(lname) + 2;
	chost = xmalloc(len);
	strlcpy(chost, lname, len);
	strlcat(chost, ".", len);

	debug("userauth_hostbased: chost %s key_type=%d ssh_name='%s'", chost, private->type, sshkey_ssh_name(private));

	/* construct data */
	if ((b = sshbuf_new()) == NULL) {
		error("%s: sshbuf_new failed", __func__);
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshkey_to_blob(private, &keyblob, &keylen)) != 0) {
		error("%s: sshkey_to_blob: %s", __func__, ssh_err(r));
		goto out;
	}
	local_user = authctxt->user; /* make local user the same as remote */

	if ((r = sshbuf_put_string(b, ssh->kex->session_id, ssh->kex->session_id_len)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_MSG_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->user)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
	    (r = sshbuf_put_cstring(b, method)) != 0 ||
	    (r = sshbuf_put_cstring(b, sshkey_ssh_name(private))) != 0 ||
	    (r = sshbuf_put_string(b, keyblob, keylen)) != 0 ||
	    (r = sshbuf_put_cstring(b, chost)) != 0 ||
	    (r = sshbuf_put_cstring(b, local_user)) != 0) {
		error("%s: buffer error: %s", __func__, ssh_err(r));
		goto out;
	}
	if (Opt_debug) {
		sshbuf_dump(b, stderr);
	}
	if ((r = sshkey_sign(private, &sig, &siglen,
	    sshbuf_ptr(b), sshbuf_len(b), sshkey_ssh_name(private), NULL, ssh->compat)) != 0) {
		error("sign using hostkey %s %s failed: %s",
		    sshkey_ssh_name(private), fp, ssh_err(r));
		goto out;
	}
	if ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, method)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, sshkey_ssh_name(private))) != 0 ||
	    (r = sshpkt_put_string(ssh, keyblob, keylen)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, chost)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, local_user)) != 0 ||
	    (r = sshpkt_put_string(ssh, sig, siglen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error("%s: packet error: %s", __func__, ssh_err(r));
		goto out;
	}
	if ((r = ssh_packet_write_wait(ssh)) != 0) {
		error("auth_send_hostbased: packet_write: %s", ssh_err(r));
		goto out;
	}
 out:
	if (sig != NULL)
		freezero(sig, siglen);
	free(keyblob);
	free(lname);
	free(fp);
	free(chost);
	sshkey_free(private);
	sshbuf_free(b);
	return r;
}

int proxyauth_send_pubkey_nosig(struct ssh *ssh, struct Authctxt *authctxt)
{
	u_char *blob = NULL;
	size_t bloblen;
	u_int have_sig = 0;
	int r;

	debug("send_pubkey_nosig");

	if (!authctxt->key) {
		error("send_pubkey_nosig: no key");
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	if ((r = sshkey_to_blob(authctxt->key, &blob, &bloblen)) != 0) {
		/* we cannot handle this key */
		error("%s: cannot handle key: %s", __func__, ssh_err(r));
		goto out;
	}
	if ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method)) != 0 ||
	    (r = sshpkt_put_u8(ssh, have_sig)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, sshkey_ssh_name(authctxt->key))) != 0 ||
	    (r = sshpkt_put_string(ssh, blob, bloblen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error("%s: %s", __func__, ssh_err(r));
		goto out;
	}
	if ((r = ssh_packet_write_wait(ssh)) != 0) {
		error("auth_send_pubkey_nosig: packet_write: %s", ssh_err(r));
		goto out;
	}
 out:
	free(blob);
	return r;
}

