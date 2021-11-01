/*
 * ssh2.c - ssh2 protocol
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

extern int	_ssh_verify_host_key(struct sshkey *, struct ssh *);
extern struct sshkey *_ssh_host_public_key(int, int, struct ssh *);
extern struct sshkey *_ssh_host_private_key(int, int, struct ssh *);
extern int	_ssh_host_key_sign(struct ssh *, struct sshkey *, struct sshkey *,
    u_char **, size_t *, const u_char *, size_t, const char *);

#include "myproposal.h"

static char *myproposal[PROPOSAL_MAX] = { KEX_SERVER };

static int ssh2_verify_host_key(struct sshkey *hostkey, struct ssh *ssh)
{
	struct key_entry *k;

	debug3("%s: need %s", __func__, sshkey_type(hostkey));
	TAILQ_FOREACH(k, &ssh->public_keys, next) {
		debug3("%s: check %s", __func__, sshkey_type(k->key));
		//char *fp = sshkey_fingerprint(k->key, SSH_DIGEST_MD5, SSH_FP_HEX);
		//debug3("verify remote: fp %s", fp);
		//free(fp);
		if (sshkey_equal_public(hostkey, k->key)) {
			return 0;	/* ok */
		}
	}
	char *fp = sshkey_fingerprint(hostkey, SSH_DIGEST_MD5, SSH_FP_HEX);
	error("%s: failed for remote hostkey: %s", __func__, fp);
	free(fp);
	return -1;	/* failed */
}

static int ssh_compat_proposal(struct ssh *ssh)
{
	/* the compat datafellows flag is only valid after banner exchange
	 *
	 * attention: since the flag is global, do all compat checks for
	 *             the client-side before the server-side is connected
	 */
	int r;
	char **proposal;

	/* de-serialize ssh->kex->my, modify it, and change it */
	if ((r = kex_buf2prop(ssh->kex->my, NULL, &proposal)) != 0) {
		return r;
	}
	proposal[PROPOSAL_KEX_ALGS] = compat_kex_proposal(proposal[PROPOSAL_KEX_ALGS]);
	proposal[PROPOSAL_ENC_ALGS_CTOS] = compat_cipher_proposal(proposal[PROPOSAL_ENC_ALGS_CTOS]);
	proposal[PROPOSAL_ENC_ALGS_STOC] = compat_cipher_proposal(proposal[PROPOSAL_ENC_ALGS_STOC]);
	proposal[PROPOSAL_SERVER_HOST_KEY_ALGS] = compat_pkalg_proposal(proposal[PROPOSAL_SERVER_HOST_KEY_ALGS]);

	r = kex_prop2buf(ssh->kex->my, proposal);
	kex_prop_free(proposal);
	return r;
}

struct ssh *ssh2_new(SSH2_CTX *ctx, int is_server, char **proposal)
{
	int r;
	u_int i;
	struct ssh *ssh;

	if ((ssh = ssh_alloc_session_state()) == NULL) {
		return NULL;
	}
	if (is_server) {
		ssh_packet_set_server(ssh);

		for (i=0; i < options.num_host_key_files; i++) {
			if (ctx->host_keys[i]) {
				if ((r = ssh_add_hostkey(ssh, ctx->host_keys[i])) != 0) {
					fatal("ssh_add_hostkey %s failed: %s", sshkey_type(ctx->host_keys[i]), ssh_err(r));
				}
			}
		}
	} else {
		for (i=0; i < options.num_host_key_files; i++) {
			if ((r = ssh_add_hostkey(ssh, ctx->host_pubkeys[i])) != 0) {
				fatal("ssh_add_hostkey %s public failed: %s", sshkey_type(ctx->host_pubkeys[i]), ssh_err(r));
			}
		}
	}
	myproposal[PROPOSAL_KEX_ALGS] = options.kex_algorithms;
	myproposal[PROPOSAL_ENC_ALGS_CTOS] = options.ciphers;
	myproposal[PROPOSAL_ENC_ALGS_STOC] = options.ciphers;
	myproposal[PROPOSAL_MAC_ALGS_CTOS] = myproposal[PROPOSAL_MAC_ALGS_STOC] = options.macs;

	/* Initialize key exchange */
	if ((r = kex_ready(ssh, proposal ? proposal : myproposal)) != 0) {
		fatal("kex_ready failed: %s", ssh_err(r));
	}

	if (is_server) {
#ifdef WITH_OPENSSL
		ssh->kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GEX_SHA1] = kexgex_server;
		ssh->kex->kex[KEX_DH_GEX_SHA256] = kexgex_server;
# ifdef OPENSSL_HAS_ECC
		ssh->kex->kex[KEX_ECDH_SHA2] = kex_gen_server;
# endif
#endif /* WITH_OPENSSL */
		ssh->kex->kex[KEX_C25519_SHA256] = kex_gen_server;
		ssh->kex->kex[KEX_KEM_SNTRUP4591761X25519_SHA512] = kex_gen_server;
		ssh->kex->load_host_public_key=&_ssh_host_public_key;
		ssh->kex->load_host_private_key=&_ssh_host_private_key;
		ssh->kex->sign=&_ssh_host_key_sign;
	} else {
#ifdef WITH_OPENSSL
		ssh->kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GEX_SHA1] = kexgex_client;
		ssh->kex->kex[KEX_DH_GEX_SHA256] = kexgex_client;
# ifdef OPENSSL_HAS_ECC
		ssh->kex->kex[KEX_ECDH_SHA2] = kex_gen_client;
# endif
#endif /* WITH_OPENSSL */
		ssh->kex->kex[KEX_C25519_SHA256] = kex_gen_client;
		ssh->kex->kex[KEX_KEM_SNTRUP4591761X25519_SHA512] = kex_gen_client;
		ssh->kex->verify_host_key =&ssh2_verify_host_key;
	}
	return ssh;
}

void ssh2_set_fd(struct ssh *ssh, int fd)
{
	/* ssh remote_ipaddr & local_ipaddr fields are initialized
	 * on the first call to ssh_packet_set_connection()
	 */
	if (ssh_packet_set_connection(ssh, fd, fd) == NULL) {
		fatal("ssh_packet_set_connection: set fd %d failed", fd);
	}
}

void ssh2_free(struct ssh *ssh)
{
	ssh_packet_close(ssh);
}

/*
 * Handle rekeying request
 *
 * - might test via:
 *   'ssh -o RekeyLimit="100k 5s" user@host'
 *   (new KEXINIT from client after 100k datatransder or 5 seconds):
 *
 * - libssh defaults are rekey_interval=0 & rekey_time=0 (disabled)
 */
int ssh2_recv_kexinit(struct ssh *ssh)
{
	int r;

	/* kex_input_kexinit consumes req buffer
	 */
	if ((r = kex_input_kexinit(SSH2_MSG_KEXINIT, 0 /*unused seq*/, ssh)) != 0) {
		error("recv_kexinit: client rekeying failed: %s", ssh_err(r));
		return r;
	}
	if ((r = ssh2_kex_dispatch(ssh)) != 0) {
		error("recv_kexinit: client rekey dispatch failed: %s", ssh_err(r));
		return r;
	}
	return 0;
}

int ssh2_kex_dispatch(struct ssh *ssh)
{
	int r;
	u_int32_t seqnr;
	u_char type;
	size_t len;

	if ((r = ssh_packet_write_wait(ssh)) != 0) {
		if (r == SSH_ERR_CONN_CLOSED) {
		    	debug("kex_dispatch: connection closed");
		} else if ((r == SSH_ERR_SYSTEM_ERROR) && (errno == ECONNRESET)) {
		    	debug("kex_dispatch: connection reset by peer");
		} else if (r == SSH_ERR_DISCONNECTED) {
			debug("kex_dispatch: disconnected");
		} else {
			error("kex_dispatch: packet_write: %s", ssh_err(r));
		}
		return r;
	}
	while (!ssh->kex->done) {
		/* ssh_packet_read_seqnr() calls blocking select()->read() once
		 * if no packet is available in the incoming buffer.
		 *
		 * note: ssh_packet_read_seqnr() includes the handling for the
		 *       SSH2_MSG_DEBUG/IGNORE/DISCONNECT messages like the
		 *       nonblocking ssh_packet_read_poll_seqnr() call.
		 */
		if ((r = ssh_packet_read_seqnr(ssh, &type, &seqnr)) != 0) {
			error("kex_dispatch: packet_read blocking: %s", ssh_err(r));
			return r;
		}
		(void)sshpkt_ptr(ssh, &len);
		debug("%d: [%d] RECV_DISPATCH %zu", ssh_packet_get_connection_in(ssh), type, len);

		if (type > 0 && type < DISPATCH_MAX &&
		    type >= SSH2_MSG_KEXINIT && type <= SSH2_MSG_TRANSPORT_MAX &&
		    ssh->dispatch[type] != NULL) {
			if ((r = (*ssh->dispatch[type])(type, seqnr, ssh)) != 0) {
				switch (r) {
				case SSH_ERR_NO_CIPHER_ALG_MATCH:
				case SSH_ERR_NO_MAC_ALG_MATCH:
				case SSH_ERR_NO_COMPRESS_ALG_MATCH:
				case SSH_ERR_NO_KEX_ALG_MATCH:
				case SSH_ERR_NO_HOSTKEY_ALG_MATCH:
					error("%s: kex_dispatch: dispatch[%d]: Unable to negotiate remote offer '%s': %s",
						ssh_remote_ipaddr(ssh), type,
						ssh->kex->failed_choice ? ssh->kex->failed_choice : "-", ssh_err(r));
					break;
                		case SSH_ERR_NO_HOSTKEY_LOADED:
					error("%s: kex_dispatch: dispatch[%d]: No matching hostkey alg '%s': %s",
						ssh_remote_ipaddr(ssh), type,
						ssh->kex->hostkey_alg ? ssh->kex->hostkey_alg : "-", ssh_err(r));
					break;
				default:
					error("%s: kex_dispatch: dispatch[%d]: %s", ssh_remote_ipaddr(ssh), type, ssh_err(r));
					break;
				}
				return r;
			}
		} else {
			error("kex_dispatch: unexpected msg type %d", type);
		}
	}
	return 0;
}

int ssh2_accept(struct ssh *ssh)
{
	int r;
	u_int32_t seqnr;
	u_char type;

	if ((r = ssh_compat_proposal(ssh)) != 0) {
		error("accept: compat_proposal: %s", ssh_err(r));
		return r;
	}
	if ((r = kex_send_kexinit(ssh)) != 0) {
		error("accept: send_kexinit: %s", ssh_err(r));
		return r;
	}
	if ((r = ssh_packet_write_wait(ssh)) != 0) {
		error("accept: packet_write: %s", ssh_err(r));
		return r;
	}
	if ((r = ssh2_kex_dispatch(ssh)) != 0) {
		error("accept: kex_dispatch: %s", ssh_err(r));
		return r;
	}

	/* initiate user authentication
	 */
	char *service = NULL;

	/* call blocking recv()
	 */
	if ((r = ssh_packet_read_seqnr(ssh, &type, &seqnr)) != 0) {
		error("accept: service packet_read: %s", ssh_err(r));
		return r;
	}
	if (type != SSH2_MSG_SERVICE_REQUEST) {
		error("accept: expected SERVICE_REQUEST, got %d", type);
		return -1;
	}
	if ((r = sshpkt_get_cstring(ssh, &service, NULL)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0) {
		ssh_packet_disconnect(ssh, "Packet integrity error.");
		return r;
	}
	if (strcmp(service, "ssh-userauth") != 0) {
		ssh_packet_disconnect(ssh, "bad service request %s", service);
		return -1;
	}
	if ((r = sshpkt_start(ssh, SSH2_MSG_SERVICE_ACCEPT)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, service)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0) {
		error("accept: service packet_write: %s", ssh_err(r));
		return r;
	}
	free(service);

	/* next incoming should be SSH2_MSG_USERAUTH_REQUEST
	 */
	return 0;
}

int ssh2_channel_open_conf(struct ssh *ssh, struct Authctxt *authctxt, const char *pkt, size_t plen)
{
	int r;
	struct sshbuf *original = NULL;
	u_int id, remote_id;

	/*
	 * Almost the same as SSH2_MSG_CHANNEL_OPEN, except then we
	 * need to parse 'remote_id' instead of 'ctype'.
	 */
	if ((original = sshbuf_from(pkt, plen)) == NULL) {
		error("channel_open_conf: alloc");
		return -1;
	}
	if ((r = sshbuf_get_u32(original, &remote_id)) != 0 ||
	    (r = sshbuf_get_u32(original, &id)) != 0) {
		error("channel_open_conf: parse error %s", ssh_err(r));
		return r;
	}
	sshbuf_free(original);

	authctxt->chan_client = remote_id;
	authctxt->chan_server = id;
	return 0;
}

int ssh2_channel_send_data(struct ssh *ssh, struct Authctxt *authctxt, char *buf, size_t len)
{
	int r;

	if ((r = sshpkt_start(ssh, SSH2_MSG_CHANNEL_DATA)) != 0 ||
	    (r = sshpkt_put_u32(ssh, authctxt->chan_server)) != 0 ||
	    (r = sshpkt_put_string(ssh, buf, len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0) {
		error("channel_send_data: channel %i: rdynamic: %s", authctxt->chan_server, ssh_err(r));
		return r;
	}
	return 0;
}

int ssh2_connect(struct ssh *ssh)
{
	int r;
	u_int32_t seqnr;
	u_char type;

	if ((r = ssh_compat_proposal(ssh)) != 0) {
		error("connect: compat_proposal: %s", ssh_err(r));
		return r;
	}
	if ((r = kex_send_kexinit(ssh)) != 0) {
		error("connect: send_kexinit: %s", ssh_err(r));
		return r;
	}
	if ((r = ssh_packet_write_wait(ssh)) != 0) {
		error("connect: packet_write: %s", ssh_err(r));
		return r;
	}
	if ((r = ssh2_kex_dispatch(ssh)) != 0) {
		error("connect: kex_dispatch: %s", ssh_err(r));
		return r;
	}

	/* initiate user authentication
	 */
	if ((r = sshpkt_start(ssh, SSH2_MSG_SERVICE_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "ssh-userauth")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0) {
		error("connect: service packet_write: %s", ssh_err(r));
		return r;
	}
	/* call blocking recv()
	 */
	if ((r = ssh_packet_read_seqnr(ssh, &type, &seqnr)) != 0) {
		error("connect: service packet_read: %s", ssh_err(r));
		return r;
	}
	if (type != SSH2_MSG_SERVICE_ACCEPT) {
		error("connect: expected SERVICE_ACCEPT, got %d", type);
		return -1;
	}
	if (ssh_packet_remaining(ssh) > 0) {
		char *reply;

		if ((r = sshpkt_get_cstring(ssh, &reply, NULL)) != 0) {
			error("connect: parse request failed: %s", ssh_err(r));
			return r;
		}
		debug("connect: service_accept: %s", reply);
		free(reply);
	} else {
		debug("connect: buggy server: service_accept w/o service");
	}
	if ((r = sshpkt_get_end(ssh)) != 0) {
		ssh_packet_disconnect(ssh, "Packet integrity error.");
		return r;
	}
	return 0;
}

int ssh2_recv_nonblock(struct ssh *ssh, u_char *typep, const u_char **bufp, size_t *lenp)
{
	int r;
	u_int32_t seqnr;

	/* ssh_packet_read_poll_seqnr() calls the nonblocking
	 * ssh_packet_read_poll2() and adds handling for the
	 * SSH2_MSG_DEBUG/IGNORE/DISCONNECT messages.
	 *
	 * note: packet:ssh_packet_enable_delayed_compress() is called
	 *       internally in ssh_packet_read_poll2().
	 */
	if ((r = ssh_packet_read_poll_seqnr(ssh, typep, &seqnr)) != 0) {
	//if ((r = ssh_packet_read_poll2(ssh, typep, &seqnr)) != 0) {
		return r;
	}
	*bufp = sshpkt_ptr(ssh, lenp);
	debug("%d: [%d] RECV_NONBLOCK %zu", ssh_packet_get_connection_in(ssh), *typep, *lenp);
	return 0;
}

int ssh2_send(struct ssh *ssh, u_char type, const u_char *buf, size_t len)
{
	int r;

	debug("%d: [%u] SEND %zu", ssh_packet_get_connection_out(ssh), type, len);

	if ((r = sshpkt_start(ssh, type)) != 0 ||
	    (r = sshpkt_put(ssh, buf, len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0) {
		if (r != SSH_ERR_DISCONNECTED) {
			error("send: packet_write: %s", ssh_err(r));
		} else {
			debug("send: disconnected");
		}
		return r;
	}
	return 0;
}

/* Checks if there is any buffered output, and tries to write some of the output. */

void ssh2_close(struct ssh *ssh)
{
	if (ssh_packet_get_connection_in(ssh) == ssh_packet_get_connection_out(ssh)) {
		close(ssh_packet_get_connection_in(ssh));
	} else {
		close(ssh_packet_get_connection_in(ssh));
		close(ssh_packet_get_connection_out(ssh));
	}
}

