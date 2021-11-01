/*
 * sshproxy.h
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
#include <openssl/ssl.h>

typedef struct ssh2_ctx {
	struct sshkey **host_keys;		/* all private host keys */
	struct sshkey **host_pubkeys;		/* all public host keys */
	struct sshkey **host_certificates;	/* all public host certificates */
	struct sshkey *authkey;
} SSH2_CTX;

/* authentication states
 */
#define AUTHSTAT_INIT           0
#define AUTHSTAT_PASSWD		1
#define AUTHSTAT_PUBKEY		2
#define AUTHSTAT_OTHER		3
#define AUTHSTAT_PUBKEY_NOSIG	4
#define AUTHSTAT_HOSTBASED	5
#define AUTHSTAT_SUCCESS	6

struct Authctxt {
	int state;
	int success;
	int valid;
	int attempt;
	int failures;
	int authenticated;
	char *user;
	char *passwd;
	char *service;
	char *method;
	char *server_methods;
	char *style;
	int have_sig;
	struct sshkey *key;
	int chan_client;
	int chan_server;
	int have_chan;
	struct Filtermethod *filter;
	struct ssh *ssh_client;
	struct ssh *ssh_server;
	char id[256];
	char server_cname[NI_MAXHOST];
};

struct ssh *ssh2_new(SSH2_CTX *ctx, int is_server, char **proposal);
void	 ssh2_set_fd(struct ssh *ssh, int fd);
int	 ssh2_accept(struct ssh *ssh);
int	 ssh2_connect(struct ssh *ssh);
int	 ssh2_recv_nonblock(struct ssh *ssh, u_char *typep, const u_char **bufp, size_t *lenp);
int	 ssh2_send(struct ssh *ssh, u_char type, const u_char *buf, size_t len);
int	 ssh2_disconnect(struct ssh *ssh, const char *fmt,...);
void	 ssh2_close(struct ssh *ssh);

int ssh2_kex_dispatch(struct ssh *ssh);
int ssh2_recv_kexinit(struct ssh *ssh);

int ssh2_channel_open_conf(struct ssh *ssh, struct Authctxt *authctxt, const char *pkt, size_t plen);
int ssh2_channel_send_data(struct ssh *ssh, struct Authctxt *authctxt, char *buf, size_t len);

extern struct ProxyOptions options;
extern int	Opt_debug;

