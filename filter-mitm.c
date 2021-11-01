/*
 * filter-mitm.c - man-in-the-middle test for data channel
 *
 * Copyright (c) 2009-2021 Barnim Dzwillo @ Strato AG
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
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>

#include "includes.h"
#include "log.h"
#include "ssh.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "ssh2.h"
#include "packet.h"
#include "xmalloc.h"
#include "misc.h"
#include "sshproxy.h"
#include "proxyconf.h"
#include "filter.h"

static int client_disabled = 0;

static int mitm_open(struct ssh *ssh, int chan_id)
{
	client_disabled = 0;
	return 0;
}

static int mitm_fd(void)
{
	/* allow channel input from stdin (need to run in foreground)
	 */
	return STDIN_FILENO;
}

static int mitm_client_disabled(void)
{
	return client_disabled;
}

static int mitm_client_data(struct ssh *ssh, u_char type, const char *msg, size_t len)
{
	int r;
	struct Authctxt *authctxt = ssh->authctxt;

	/* log all channel data
	 */
	if (type == SSH2_MSG_CHANNEL_DATA) {
		u_int id;
		struct sshbuf *sb;
		const u_char *data;
		size_t data_len;

		if ((sb = sshbuf_from(msg, len)) == NULL) {
			error("%s: server channel copy data failed", authctxt->id);
			return SSH_ERR_ALLOC_FAIL;
		}
		if ((r = sshbuf_get_u32(sb, &id)) != 0) {
			error("%s: server channel get id failed: %s", authctxt->id, ssh_err(r));
			return r;
       		}
		if ((r = sshbuf_get_string_direct(sb, &data, &data_len)) != 0) {
			error("%s: server channel %d: get data: %s", authctxt->id, id, ssh_err(r));
			return r;
		}
		if (data_len) {
			logit("%s: client data: %.*s", authctxt->id, (int)data_len, (char *)data);
		}
		sshbuf_free(sb);
	}
	if ((r = ssh2_send(authctxt->ssh_server, type, msg, len)) != 0) {
		sshpkt_get(ssh, NULL, len); // consume msg
		return r;
	}
	// consume msg
	if ((r = sshpkt_get(ssh, NULL, len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0) {
		return r;
	}
	return 0;
}

static int mitm_server_data(struct ssh *ssh, u_char type, const char *msg, size_t len)
{
	int r;
	struct Authctxt *authctxt = ssh->authctxt;

	/* echo all channel data to stdout
	 */
	if (type == SSH2_MSG_CHANNEL_DATA) {
		u_int id;
		struct sshbuf *sb;
		const u_char *data;
		size_t data_len;

		if ((sb = sshbuf_from(msg, len)) == NULL) {
			error("%s: server channel copy data failed", authctxt->id);
			return SSH_ERR_ALLOC_FAIL;
		}
		if ((r = sshbuf_get_u32(sb, &id)) != 0) {
			error("%s: server channel get id failed: %s", authctxt->id, ssh_err(r));
			return r;
       		}
		if ((r = sshbuf_get_string_direct(sb, &data, &data_len)) != 0) {
			error("%s: server channel %d: get data: %s", authctxt->id, id, ssh_err(r));
			return r;
		}
		if (data_len) {
			if (write(STDOUT_FILENO, data, data_len) <= 0) {
				return SSH_ERR_SYSTEM_ERROR; // errno contains real err
			}
		}
		sshbuf_free(sb);
	}
	if (!client_disabled) {
		if ((r = ssh2_send(authctxt->ssh_client, type, msg, len)) != 0) {
			sshpkt_get(ssh, NULL, len); // consume msg
			return r;
		}
	}
	// consume msg
	if ((r = sshpkt_get(ssh, NULL, len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0) {
		return r;
	}
	return 0;
}

static int mitm_filter_data(struct ssh *ssh)
{
	int i;
	int r;
	struct Authctxt *authctxt = ssh->authctxt;
	u_char buf[8192];
	size_t len = sizeof(buf) - 1;

	if ((i = read(STDIN_FILENO, buf, len)) <= 0) {
		return -1;
	}
	if ((r = ssh2_channel_send_data(ssh, authctxt, buf, i)) != 0) {
		return -1;
	}
	/* ignore all client data from now on
	 */
	if (!client_disabled) {
		logit("%s: client connection disabled", authctxt->id);
		client_disabled = 1;
	}
	return 0;
}

struct Filtermethod filter_mitm = {
	"mitm",
	mitm_open,
	mitm_fd,
	mitm_client_disabled,
	mitm_client_data,
	mitm_server_data,
	mitm_filter_data,
	&options.filter_mitm,
};

