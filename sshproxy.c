/*
 * sshproxy.c - user based ssh backend host switch
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
#include <signal.h>
#include <unistd.h>
#include <wait.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <arpa/nameser.h>
#include <arpa/inet.h> /* inet_ntoa */

#include "includes.h"
#include "log.h"
#include "ssh.h"
#include "ssh2.h"
#include "atomicio.h"
#include "version.h"
#include "packet.h"
#include "compat.h"
#include "cipher.h"
#include "ssherr.h"
#include "sshkey.h"
#include "sshbuf.h"
#include "digest.h"
#include "kex.h"
#include "xmalloc.h"
#include "authfile.h"
#include "canohost.h"
#include "match.h"
#include "myproposal.h"
#include "misc.h"
#include "sshproxy.h"
#include "proxyconf.h"
#include "proxyauth.h"
#include "switch.h"
#include "check.h"
#include "filter.h"

#define CONFIG_FILE "sshproxy.conf"

/* Proxy configuration options. */
struct ProxyOptions options;

int	 Opt_debug = 0;
int	 Opt_keepalive = 1; /* Loadbalancer idle timeout is 300 sec */
int	 Opt_dont_fork = 0;

/*
 * The sockets that the server is listening; this is used in the SIGHUP
 * signal handler.
 */
#define	MAX_LISTEN_SOCKS	16
static int listen_socks[MAX_LISTEN_SOCKS];
static int num_listen_socks = 0;

SSH2_CTX *ssh2_client_ctx;

unsigned int lb_offset = 0;

/* debug goes to stderr unless inetd_flag is set */
static int log_stderr = 0;

/* This is set to true when a signal is received. */
static volatile sig_atomic_t received_sigterm = 0;

char	 **ssh2_server_proposal = NULL;

extern char *__progname;

extern int _ssh_send_banner(struct ssh *ssh, struct sshbuf *banner);
extern int _ssh_read_banner(struct ssh *ssh, struct sshbuf *banner);
extern int _ssh_order_hostkeyalgs(struct ssh *ssh);

/* switch methods */

extern struct Switchmethod switch_fixed;

struct Switchmethod *switchmethods[] = {
	&switch_fixed,
	NULL
};

/* check methods */

struct Checkmethod *checkmethods[] = {
	NULL
};

/* filter methods */

extern struct Filtermethod filter_mitm;

struct Filtermethod *filtermethods[] = {
	&filter_mitm,
	NULL
};

#define PROXY_VERSION "0.22"

static void usage(void)
{
	fprintf(stderr, "Version: " PROXY_VERSION "\n"
		"Usage: sshproxy [-d] [-f] [-I] [-c config_file]"
		" [-b bindaddr] [-p local port] [-P server port] [default_host[:port]]\n");
	exit(1);
}

/* offer hostkey algorithms in kexinit depending on registered keys
 * (attention: _ssh_order_hostkeyalgs() does not check the ecdsa nid)
 */
int ssh_order_hostkeyalgs(struct ssh *ssh)
{
	struct key_entry *k;
	char *orig, *avail, *oavail = NULL, *alg, *replace = NULL;
	char **proposal;
	size_t maxlen;
	int ktype, r;

	/* XXX we de-serialize ssh->kex->my, modify it, and change it */
	if ((r = kex_buf2prop(ssh->kex->my, NULL, &proposal)) != 0)
		return r;
	orig = proposal[PROPOSAL_SERVER_HOST_KEY_ALGS];
	if ((oavail = avail = strdup(orig)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	maxlen = strlen(avail) + 1;
	if ((replace = calloc(1, maxlen)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	*replace = '\0';
	while ((alg = strsep(&avail, ",")) && *alg != '\0') {
		if ((ktype = sshkey_type_from_name(alg)) == KEY_UNSPEC)
			continue;
		TAILQ_FOREACH(k, &ssh->public_keys, next) {
#if 0
			if (k->key->type == ktype ||
#else
			if ((k->key->type == ktype &&
			    (ktype != KEY_ECDSA || k->key->ecdsa_nid == sshkey_ecdsa_nid_from_name(alg))) ||
#endif
			    (sshkey_is_cert(k->key) && k->key->type ==
			    sshkey_type_plain(ktype))) {
				if (*replace != '\0')
					strlcat(replace, ",", maxlen);
				strlcat(replace, alg, maxlen);
				break;
			}
		}
	}
	if (*replace != '\0') {
		debug2("%s: orig/%d    %s", __func__, ssh->kex->server, orig);
		debug2("%s: replace/%d %s", __func__, ssh->kex->server, replace);
		free(orig);
		proposal[PROPOSAL_SERVER_HOST_KEY_ALGS] = replace;
		replace = NULL;	/* owned by proposal */
		r = kex_prop2buf(ssh->kex->my, proposal);
	}
 out:
	free(oavail);
	free(replace);
	kex_prop_free(proposal);
	return r;
}

static void authctxt_init(struct Authctxt *authctxt)
{
	memset(authctxt, 0, sizeof(*authctxt));
}

static void authctxt_finit(struct Authctxt *authctxt)
{
	if (authctxt->key) {
		sshkey_free(authctxt->key);
		authctxt->key = NULL;
	}
}

static int server_select(struct ssh *ssh, struct Authctxt *authctxt,
	char **server, unsigned int maxserver, unsigned int *nserver, struct Switchmethod **method)
{
	int i;
	int err = ENOENT;

	/* try all enabled switch methods in order of method list
	 */
	for (i = 0; switchmethods[i] != NULL; i++) {
		if (!switchmethods[i]->enabled) {
			continue;
		}
		debug("server_select: try %s", switchmethods[i]->name);

		if ((err = switchmethods[i]->select(ssh, authctxt, server, maxserver, nserver)) == 0) {
			if (method) {
				*method = switchmethods[i];
			}
			return 0;
		}
		if (err != ENOENT) {
			debug("server_select: method %s for user %s failed: %d", switchmethods[i]->name, authctxt->user, err);
			break;
		}
	}
	return err;
}

static void sigchld_handler(int sig)
{
	int sav_errno;
	pid_t pid;
	int status;

	sav_errno = errno;
	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		if (WIFEXITED(status)) {
			debug("child %d terminated with status %d", pid, WEXITSTATUS(status));
		} else if (WIFSIGNALED(status)) {
			debug("child %d terminated with signal %d", pid, WTERMSIG(status));
		} else {
			debug("child %d other status %d", pid, status);
		}
	}
	signal(SIGCHLD, sigchld_handler);
	errno = sav_errno;
}

/*
 * Close all listening sockets
 */
static void close_listen_socks(void)
{
	int i;

	for (i=0; i < num_listen_socks; i++) {
		close(listen_socks[i]);
	}
	num_listen_socks = -1;
}

/*
 * Listen for TCP connections
 */
static int ssh_listen(struct addrinfo *addrs)
{
	int ret, listen_sock;
	struct addrinfo *ai;
	char ntop[NI_MAXHOST], strport[NI_MAXSERV];

	for (ai = addrs; ai; ai = ai->ai_next) {
		if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
			continue;
		if (num_listen_socks >= MAX_LISTEN_SOCKS)
			fatal("Too many listen sockets. " "Enlarge MAX_LISTEN_SOCKS");
		if ((ret = getnameinfo(ai->ai_addr, ai->ai_addrlen,
			ntop, sizeof(ntop), strport, sizeof(strport),
			NI_NUMERICHOST|NI_NUMERICSERV)) != 0) {
			error("listen: getnameinfo failed: %.100s", ssh_gai_strerror(ret));
			continue;
		}
		/* Create socket for listening. */
		listen_sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (listen_sock == -1) {
			/* kernel may not support ipv6 */
			verbose("listen: socket: %.100s", strerror(errno));
			continue;
		}
		if (set_nonblock(listen_sock) == -1) {
			close(listen_sock);
			continue;
		}
		if (fcntl(listen_sock, F_SETFD, FD_CLOEXEC) == -1) {
			verbose("listen: socket: CLOEXEC: %s", strerror(errno));
			close(listen_sock);
			continue;
		}
		/* Socket options */
		set_reuseaddr(listen_sock);

		/* Only communicate in IPv6 over AF_INET6 sockets. */
		if (ai->ai_family == AF_INET6)
			sock_set_v6only(listen_sock);

		debug("Bind to port %s on %s.", strport, ntop);

		/* Bind the socket to the desired port. */
		if (bind(listen_sock, ai->ai_addr, ai->ai_addrlen) == -1) {
			error("Bind to port %s on %s failed: %.200s.", strport, ntop, strerror(errno));
			close(listen_sock);
			continue;
		}
		listen_socks[num_listen_socks] = listen_sock;
		num_listen_socks++;

		/* Start listening on the port. */
		if (listen(listen_sock, SSH_LISTEN_BACKLOG) == -1) {
			fatal("listen on [%s]:%s: %.100s", ntop, strport, strerror(errno));
		}
		logit("Server listening on %s port %s.",
		    ntop, strport);
	}
	return 0;
}

/*
 * Attempt to resolve a host name / port to a set of addresses and
 * optionally return any CNAMEs encountered along the way.
 * Returns NULL on failure.
 */
static struct addrinfo *resolve_host(const char *name, const char *port, int family, char *cname, size_t clen)
{
	struct addrinfo hints, *res;
	int gaierr;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	if (cname != NULL)
		hints.ai_flags = AI_CANONNAME;
	if ((gaierr = getaddrinfo(name, port, &hints, &res)) != 0) {
		error("resolve_host: Could not resolve hostname %.100s: %s", name, ssh_gai_strerror(gaierr));
		return NULL;
	}
	if (cname != NULL && res->ai_canonname != NULL) {
		if (strlcpy(cname, res->ai_canonname, clen) >= clen) {
			error("resolve_host: host \"%s\" cname \"%s\" too long (max %lu)",
				name,  res->ai_canonname, (u_long)clen);
			if (clen > 0)
				*cname = '\0';
		}
	}
	return res;
}

static SSH2_CTX *SSH2_CTX_new(void)
{
	SSH2_CTX *ctx;

	if (!(ctx = calloc(sizeof(*ctx), 1))) {
		return NULL;
	}
	return ctx;
}

static void proxy_init(const char *bindaddr, const char *default_port)
{
	int r;
	u_int i, j;
	SSH2_CTX *ctx;
	char *p;
	const char *port;
	struct addrinfo *addrs;
	char host[NI_MAXHOST];

	debug("proxy_init");

	if (strlcpy(host, bindaddr, sizeof(host)) >= sizeof(host)) { 
		fatal("bindaddr");
	}
	if ((p = strrchr(host,':'))) {
		*p = '\0';
		port = p+1;
	} else {
		port = default_port;
	}
	if (!(addrs = resolve_host(host, port, options.server_family, NULL, 0))) {
		fatal("resolve");
	}
	if (ssh_listen(addrs) != 0) {
		fatal("listen");
	}

	seed_rng();

	ctx = SSH2_CTX_new();

	/* load host keys */
	ctx->host_keys = xcalloc(options.num_host_key_files, sizeof(struct sshkey *));
	ctx->host_pubkeys = xcalloc(options.num_host_key_files, sizeof(struct sshkey *));
	ctx->host_certificates = xcalloc(options.num_host_key_files, sizeof(struct sshkey *));

	for (i=0; i < options.num_host_key_files; i++) {
		const char *name = options.host_key_files[i];
		struct sshkey *key;
		struct sshkey *pubkey;

		if ((r = sshkey_load_public(name, &pubkey, NULL)) != 0) {
			debug("Could not load public host key %s: %s", name, ssh_err(r));
		}
		if ((r = sshkey_load_private(name, "", &key, NULL)) != 0) {
			if (!pubkey) {
				fatal("Could not load host key %s: %s", name, ssh_err(r));
			}
			debug("Loaded pub key %s type %s", name, sshkey_type(pubkey));
		} else {
			ctx->host_keys[i] = key;

			if (!pubkey) {
				if ((r = sshkey_from_private(key, &pubkey)) != 0) {
					fatal("Could not demote key: %s: %s", name, ssh_err(r));
				}
			}
			debug("Loaded host key %s type %s", name, sshkey_type(key));
		}
		ctx->host_pubkeys[i] = pubkey;

	}

	/*
	 * Load certificates. They are stored in an array at identical
	 * indices to the public keys that they relate to.
	 */
	for (i=0; i < options.num_host_key_files; i++) {
		ctx->host_certificates[i] = NULL;
	}
	for (i=0; i < options.num_host_cert_files; i++) {
		struct sshkey *key;

		if ((r = sshkey_load_public(options.host_cert_files[i], &key, NULL)) != 0) {
			error("Could not load host certificate %s: %s", options.host_cert_files[i], ssh_err(r));
			continue;
		}
		if (!sshkey_is_cert(key)) {
			error("Certificate file is not a certificate: %s", options.host_cert_files[i]);
			sshkey_free(key);
			continue;
		}
		/* Find matching private key */
		for (j = 0; j < options.num_host_key_files; j++) {
			if (ctx->host_keys[j]) {
				if (sshkey_equal_public(key, ctx->host_keys[j])) {
					ctx->host_certificates[j] = key;
					break;
				}
			}
		}
		if (j >= options.num_host_key_files) {
			error("No matching private key for certificate: %s", options.host_cert_files[i]);
			sshkey_free(key);
			continue;
		}
		ctx->host_certificates[j] = key;
		debug("Loaded host certificate: #%u type %d %s", j, key->type, sshkey_type(key));
	}

	//if ((r = sshkey_generate(KEY_RSA, 1024, &ctx->hostkey_rsa)) != 0) {
	//	fatal("Could not generate rsa host key");
	//}

	if (options.hostkey_auth) {
		struct sshkey *key;

		if ((r = sshkey_load_private(options.hostkey_auth, "", &key, NULL)) != 0) {
			fatal("Could not load auth host key %s: %s", options.hostkey_auth, ssh_err(r));
		}
		ctx->authkey = key;
	}
	debug("proxy_init: DONE");

	ssh2_client_ctx = ctx;
}

/* 
 * Creates a socket for use as the ssh connection.
 */
static int ssh_create_socket(struct addrinfo *ai, const char *bind_address)
{
	int sock, r;
	struct sockaddr_storage bindaddr;
	socklen_t bindaddrlen = 0;
	struct addrinfo hints, *res = NULL;
	char ntop[NI_MAXHOST];

	sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	if (sock == -1) {
		error("create_socket: %s", strerror(errno));
		return -1;
	}
	fcntl(sock, F_SETFD, FD_CLOEXEC);

	/* Bind the socket to an alternative local IP address */
	if (bind_address == NULL)
		return sock;

	if (bind_address != NULL) {
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = ai->ai_family;
		hints.ai_socktype = ai->ai_socktype;
		hints.ai_protocol = ai->ai_protocol;
		hints.ai_flags = AI_PASSIVE;
		if ((r = getaddrinfo(bind_address, NULL, &hints, &res)) != 0) {
			error("create_socket: getaddrinfo: %s: %s", bind_address, ssh_gai_strerror(r));
			goto fail;
		}
		if (res == NULL) {
			error("crate_socket: getaddrinfo: no addrs");
			goto fail;
		}
		memcpy(&bindaddr, res->ai_addr, res->ai_addrlen);
		bindaddrlen = res->ai_addrlen;
	}
	if ((r = getnameinfo((struct sockaddr *)&bindaddr, bindaddrlen,
		ntop, sizeof(ntop), NULL, 0, NI_NUMERICHOST)) != 0) {
		error("create_socket: getnameinfo failed: %s", ssh_gai_strerror(r));
		goto fail;
	}
	if (bind(sock, (struct sockaddr *)&bindaddr, bindaddrlen) != 0) {
		error("create_socket: bind %s: %s", ntop, strerror(errno));
		goto fail;
	}
	debug("create_socket: bound to %s", ntop);
	/* success */
	goto out;
fail:
	close(sock);
	sock = -1;
out:
	if (res != NULL)
		freeaddrinfo(res);
	return sock;
}

/* 
 * Opens a TCP/IP connection to the remote server on the given host.
 * The address of the remote host will be returned in hostaddr.
 */
static int ssh_connect(const char *host, struct addrinfo *aitop,
	struct sockaddr_storage *hostaddr,
	int *timeout_ms, int want_keepalive, const char *bindaddr, int *sock_fd)
{
	int on = 1, saved_timeout_ms = *timeout_ms;
	int oerrno, sock = -1;
	char ntop[NI_MAXHOST], strport[NI_MAXSERV];
	struct addrinfo *ai;

	memset(ntop, 0, sizeof(ntop));
	memset(strport, 0, sizeof(strport));

	/*
	 * Loop through addresses for this host, and try each one in
	 * sequence until the connection succeeds.
	 */
	for (ai = aitop; ai; ai = ai->ai_next) {
		if (ai->ai_family != AF_INET &&
		    ai->ai_family != AF_INET6) {
			errno = EAFNOSUPPORT;
			continue;
		}
		if (getnameinfo(ai->ai_addr, ai->ai_addrlen,
		    ntop, sizeof(ntop), strport, sizeof(strport),
		    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
			oerrno = errno;
			error("ssh_connect: getnameinfo failed");
			errno = oerrno;
			continue;
		}
		debug("Connecting to %.200s [%.100s] port %s.",
			host, ntop, strport);

		/* Create a socket for connecting. */
		sock = ssh_create_socket(ai, bindaddr);
		if (sock < 0) {
			/* Any error is already output */
			errno = 0;
			continue;
		}

		*timeout_ms = saved_timeout_ms;
		if (timeout_connect(sock, ai->ai_addr, ai->ai_addrlen, timeout_ms) >= 0) {
			/* Successful connection. */
			memcpy(hostaddr, ai->ai_addr, ai->ai_addrlen);
			break;
		} else {
			oerrno = errno;
			debug("connect to address %s port %s: %s",
			    ntop, strport, strerror(errno));
			close(sock);
			sock = -1;
			errno = oerrno;
		}
	}

	/* Return failure if we didn't get a successful connection. */
	if (sock == -1) {
		int ret = (errno == 0) ? EINVAL : errno;
		error("connect to host %s port %s: %s",
		    host, strport, errno == 0 ? "failure" : strerror(errno));
		return ret;
	}
	debug("Connection established.");

	/* Set SO_KEEPALIVE if requested. */
	if (want_keepalive) {
		if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (void *)&on, sizeof(on)) == -1) {
			error("ssh_connect: setsockopt SO_KEEPALIVE: %.100s", strerror(errno));
		}
	}
	*sock_fd = sock;
	return 0;
}

int server_connect(struct Authctxt *authctxt, const char *name, const char *port, const char *bindaddr,
		   int tmo, int *sock)
{
	int err;
	char *p;
	int tcp_keep_alive = 0;
	int timeout_ms = tmo * 1000;
	struct addrinfo *addrs;
	struct sockaddr_storage hostaddr;
	char host[NI_MAXHOST];

	if (strlcpy(host, name, sizeof(host)) >= sizeof(host)) { 
		return EINVAL;
	}
	if ((p = strrchr(host,':'))) {
		*p = '\0';
		port = p+1;
	}
	if (!(addrs = resolve_host(host, port, options.server_family, authctxt->server_cname, sizeof(authctxt->server_cname)))) {
		return EINVAL;
	}

	/* Open a connection to the remote host. */
	if ((err = ssh_connect(host, addrs, &hostaddr, &timeout_ms, tcp_keep_alive, bindaddr, sock)) != 0) {
		return err;
	}
	if (addrs != NULL) {
		freeaddrinfo(addrs);
	}
	return 0;
}

int server_connect_list(struct Authctxt *authctxt, char **server, unsigned int n, const char *default_port,
	const char *bindaddr, int *sock)
{
	int err;
	int tmo = 1;
	unsigned int i;

	/* try each server in the list, but only if there is more than one
	 */
	if (n > 1) {
		for (i=0; i < n; i++) {
			unsigned int off = (lb_offset + i) % n;

			debug("%s: connecting to server %s default port %s",
				authctxt->id, server[off], default_port ? default_port : "-");

			err = server_connect(authctxt, server[off], default_port, bindaddr, tmo, sock);
			if (err == 0) {
				/* connected */
				return 0;
			}
			/* increase timeout and try next server from list
			*/
			logit("%s: connect to server %s within %ds failed: %d",
				authctxt->id, server[off], tmo, err);
			tmo++;
		}
	}

	/* as fallback do a blocking connect to server[0]
	 */
	err = server_connect(authctxt, server[0], default_port, bindaddr, 0, sock);
	if (err == 0) {
		/* connected */
		return 0;
	}
	logit("%s: connect to server %s (blocking) failed: %d", authctxt->id, server[0], err);
	return err;
}

static void authctxt_update(struct Authctxt *authctxt)
{
	snprintf(authctxt->id, sizeof(authctxt->id), "[%s] (%s:%d -> %s:%d %s)",
		authctxt->user ? authctxt->user : "-",
		authctxt->ssh_client ? ssh_remote_ipaddr(authctxt->ssh_client) : "NONE",
		authctxt->ssh_client ? ssh_remote_port(authctxt->ssh_client) : 0,
		authctxt->server_cname[0] ? authctxt->server_cname : (authctxt->ssh_server ? ssh_remote_ipaddr(authctxt->ssh_server) : "NONE"),
		authctxt->ssh_server ? ssh_remote_port(authctxt->ssh_server) : 0,
		authctxt->method ? authctxt->method : "connecting");
}

static void setstat(struct Authctxt *authctxt, int state)
{
	debug("AUTHSTAT: [%d] -> [%d]", authctxt->state, state);
	authctxt->state = state;
	authctxt_update(authctxt);
}

static void handle_auth_request(
	struct Authctxt *authctxt, struct ssh *ssh_server, int *ignore)
{
	int r;

	/* proxyauth_recv_request() has alread been called */

	debug("Client: SSH2_MSG_USERAUTH_REQUEST, requested method: %s "
		"state=%d, authenticated=%d",
		authctxt->method, authctxt->state, authctxt->authenticated);

	*ignore = 0;

	if (authctxt->state != AUTHSTAT_INIT) {
		fatal("client sent SSH2_MSG_USERAUTH_REQUEST "
			"while other SSH2_MSG_USERAUTH_REQUEST");
	}

	if (strcmp(authctxt->method, "publickey") == 0) {
		/* proxyauth_recv_request() sets authctxt.authenticated = 1
		 * when verify sig succeeds
		 */
		if (authctxt->authenticated) {
			/* send USERAUTH_REQUEST without sig to verify
			 * the server knows the pubkey
			 */
			if ((r = proxyauth_send_pubkey_nosig(ssh_server, authctxt)) != 0) {
				fatal("auth nosig failed: %s", ssh_err(r));
			}
			setstat(authctxt, AUTHSTAT_PUBKEY_NOSIG);
			*ignore = 1;
		} else {
			/* no or wrong sig, passthrough USERAUTH_REQUEST and
			* let server create the suitable response
			*/
			setstat(authctxt, AUTHSTAT_PUBKEY);
		}
		return;
	}

	/* Other auth methods like 'password' and 'none' we can passthrough
	 */
	if (strcmp(authctxt->method, "password") == 0)
		setstat(authctxt, AUTHSTAT_PASSWD);
	else
		setstat(authctxt, AUTHSTAT_OTHER);
}

static int check_login(struct ssh *ssh, struct Authctxt *authctxt, int isgood)
{
	int i;
	int err;
	int valid;

	/* try all enabled check methods in order of method list
	 */
	for (i = 0; checkmethods[i] != NULL; i++) {
		if (checkmethods[i]->enabled == NULL || *(checkmethods[i]->enabled) == 0) {
			continue;
		}
		debug("check_login: %s", checkmethods[i]->name);

		if ((err = checkmethods[i]->post(ssh, authctxt, isgood, &valid)) == 0) {
			return valid;
		}
		if (err != ENOENT) {
			debug("check_login: method %s for user %s failed: %d", checkmethods[i]->name, authctxt->user, err);
			return 0;
		}
	}
	return 1;
}

static int filter_add(struct ssh *ssh, struct Authctxt *authctxt)
{
	int i;
	int err;

	/* try all enabled filter methods in order of filter list
	 */
	for (i = 0; filtermethods[i] != NULL; i++) {
		if (filtermethods[i]->enabled == NULL || *(filtermethods[i]->enabled) == 0) {
			continue;
		}
		debug("filter_add: %s", filtermethods[i]->name);

		if ((err = filtermethods[i]->open(ssh, authctxt->chan_server)) == 0) {
			authctxt->filter = filtermethods[i];
			return 1;
		}
	}
	return 0;
}

void dump_hostkey_proposal(struct ssh *ssh, const char *what)
{
	int r;
	char **proposal;

	if ((r = kex_buf2prop(ssh->kex->my, NULL, &proposal)) != 0) {
		error("%s: kex_buf2prop: %s", ssh_remote_ipaddr(ssh), ssh_err(r));
		return;
	}
	debug("%s: %s hostkey proposal: %s", ssh_remote_ipaddr(ssh), what, proposal[PROPOSAL_SERVER_HOST_KEY_ALGS]);
	kex_prop_free(proposal);
}

/* Call read() once after select signaled new data.
 * see: blocking ssh_packet_read_seqnr()
 */
static int ssh2_read_append(struct ssh *ssh)
{
	int r;
	int len;
	char buf[32768];

	/* Read data from the socket. */
	len = read(ssh_packet_get_connection_in(ssh), buf, sizeof(buf));
	if (len == 0) {
		r = SSH_ERR_CONN_CLOSED;
		goto out;
	}
	if (len == -1) {
		r = SSH_ERR_SYSTEM_ERROR; // use errno in ssh_err()
		goto out;
	}

	/* Append it to the buffer. */
	if ((r = ssh_packet_process_incoming(ssh, buf, len)) != 0) {
		goto out;
	}
out:
	return r;
}

static void proxy_child2(struct Authctxt *authctxt, struct ssh *ssh_client)
{
	int r;
	int err = 0;
	int server_fd;
	fd_set fds;
	int i, pass_done;
	struct sshbuf *auth_sb = NULL;
	struct ssh *ssh_server = NULL;
	SSH2_CTX *ssh_server_ctx;
	char *cp;
	char *sp;
	int ignore;
	unsigned int nserver = 0;
	unsigned int maxserver = 8;
	char *serverlist[maxserver];

	if ((cp = sshbuf_dup_string(ssh_client->kex->client_version)) == NULL) {
		fatal("%s: malloc", authctxt->id);
	}

	/* Perform client key exchange. */
	if ((r = ssh2_accept(ssh_client)) != 0) {
		/* the major reason for a failing client key exchange
		 * is a missing known_hosts entry on the client side
		 * in verify_host_key(). (-> 'waiting for SSH2_MSG_NEWKEYS'
		 * after 'SSH2_MSG_KEX_DH_GEX_REPLY' was sent)
		 */
		fatal("%s: client '%s' key exchange failed: %s", authctxt->id, cp, ssh_err(r));
	}
	debug("%s: accept complete", authctxt->id);

	/*
	 * receive the first auth request, it is mostly for scheme 'none',
	 * followed by additional requests for 'password' or 'pubkey'
	 */
	if ((r = proxyauth_recv_auth_pkg(ssh_client, authctxt, &auth_sb)) != 0) {
		fatal("%s: recv client '%s' userauth failed: %s", authctxt->id, cp, ssh_err(r));
	}
	authctxt_update(authctxt);

	logit("%s: client version: %s compat: %08x", authctxt->id, cp, ssh_client->compat);
	free(cp);

	err = server_select(ssh_client, authctxt, serverlist, maxserver, &nserver, NULL);
	if (err) {
		fatal("%s: server_select %s failed: %d (%s)", authctxt->id, authctxt->user, err, strerror(err));
	}

	/* Connect to real server
	 */
	if ((err = server_connect_list(authctxt, serverlist, nserver, options.server_port, NULL, &server_fd))) {
		fatal("%s: connect: %d (%s)", authctxt->id, err, strerror(err));
	}
	/* Perform server key exchange. */
	debug("%s: Performing server key exchange", authctxt->id);
	if ((ssh_server_ctx = SSH2_CTX_new()) == NULL) {
		fatal("%s: malloc", authctxt->id);
	}
	/* setup public keys for backend verification
	 * (these are currently the same as for the client side)
	 * TODO: should copy keys
	 */
	u_int n;

	ssh_server_ctx->host_pubkeys = xcalloc(options.num_host_key_files, sizeof(struct sshkey *));
	for (n=0; n < options.num_host_key_files; n++) {
		ssh_server_ctx->host_pubkeys[n] = ssh2_client_ctx->host_pubkeys[n];
	}

	if ((ssh_server = ssh2_new(ssh_server_ctx, 0, NULL)) == NULL) {
		fatal("%s: malloc", authctxt->id);
	}
	ssh2_set_fd(ssh_server, server_fd);
	authctxt->ssh_server = ssh_server;
	ssh_server->authctxt = authctxt;
	authctxt_update(authctxt);

	if ((r = _ssh_send_banner(ssh_server, ssh_server->kex->client_version)) != 0) {
		fatal("%s: server send banner failed: %s", authctxt->id, ssh_err(r));
	}
	if ((r = ssh_packet_write_wait(ssh_client)) != 0) {
		fatal("%s: server write banner failed: %s", authctxt->id, ssh_err(r));
	}
	if ((r = ssh2_read_append(ssh_server)) != 0) {
    		fatal("%s: server recv banner failed: %s", authctxt->id, ssh_err(r));
	}
	if ((r = _ssh_read_banner(ssh_server, ssh_server->kex->server_version)) != 0) {
		fatal("%s: server read banner failed: %s", authctxt->id, ssh_err(r));
	}
	if ((sp = sshbuf_dup_string(ssh_server->kex->server_version)) == NULL) {
		fatal("%s: malloc", authctxt->id);
	}
	debug("%s: server version: %s compat: %08x", authctxt->id, sp, ssh_server->compat);
	free(sp);

	if ((r = ssh_order_hostkeyalgs(ssh_server)) != 0) {
		fatal("%s: server order hostkeyags failed: %s", authctxt->id, ssh_err(r));
	}

	/* use always our own proposal (and not ssh_client->peer_proposal) for
	 * server side to avoid using unsupported schemes like zlib-compression
	 */
	if ((r = ssh2_connect(ssh_server)) != 0) {
		fatal("%s: server key exchange failed: %s", authctxt->id, ssh_err(r));
	}

	/* Forward auth pkg to server. */
	handle_auth_request(authctxt, ssh_server, &ignore);
	if (!ignore) {
		if ((r = ssh2_send(ssh_server, SSH2_MSG_USERAUTH_REQUEST, sshbuf_ptr(auth_sb), sshbuf_len(auth_sb))) != 0) {
			fatal("%s: relay client userauth to server failed: %s", authctxt->id, ssh_err(r));
		}
	}
	sshbuf_free(auth_sb);
	auth_sb = NULL;

	pass_done = 0;

	/* Relay packets. */
	for (;;) {
		u_char type;
		const u_char *msg;
		size_t len;
		int client_fd = ssh_packet_get_connection_in(ssh_client);
		int filter_fd = authctxt->filter ? authctxt->filter->fd() : -1;

		FD_ZERO(&fds);
		FD_SET(server_fd, &fds);
		i = server_fd;

		if (filter_fd >= 0) {
			FD_SET(filter_fd, &fds);

			if (!authctxt->filter->client_disabled()) {
				FD_SET(client_fd, &fds);
				i = MAX(client_fd, i);
			}
		} else {
			FD_SET(client_fd, &fds);
			i = MAX(client_fd, i);
		}
		if (select(i + 1, &fds, 0, 0, 0) == -1) {
			if (errno != EINTR)
				break;
		}
		if (FD_ISSET(client_fd, &fds)) {
		    /*
		     * Client section
		     */
		    if ((r = ssh2_read_append(ssh_client)) != 0) {
			if (r == SSH_ERR_CONN_CLOSED) {
			    	debug("%s: client connection closed", authctxt->id);
			} else if ((r == SSH_ERR_SYSTEM_ERROR) && (errno == ECONNRESET)) {
			    	debug("%s: client connection reset by peer", authctxt->id);
			} else {
		    		error("%s: client read failed: %s", authctxt->id, ssh_err(r));
			}
			break;
		    }
		    while(1) {
			if ((r = ssh2_recv_nonblock(ssh_client, &type, &msg, &len)) != 0) {
				if (r == SSH_ERR_DISCONNECTED) {
					debug("%s: client disconnected", authctxt->id);
				} else {
					error("%s: client recv failed: %s", authctxt->id, ssh_err(r));
				}
				goto out;
			}
			if (type == SSH_MSG_NONE) {
				break;
			}
			if (type == SSH2_MSG_KEXINIT) {
				/* rekey request */
				debug("%s: client SSH2_MSG_KEXINIT (rekey)", authctxt->id);
				if ((r = ssh2_recv_kexinit(ssh_client)) != 0) {
					fatal("%s: client rekeying failed: %s", authctxt->id, ssh_err(r));
				}
				continue; // might have packet in buffer
			}
			if (!pass_done) {
			    if (type == SSH2_MSG_SERVICE_REQUEST) {
				debug("%s: Client: SSH2_MSG_SERVICE_REQUEST", authctxt->id);
				/* some clients send another service request
				 * after a userauth request failed
				 * (-> paramiko_1.5.4)
				 */
				if ((r = proxyauth_send_service_accept(ssh_client)) != 0) {
					fatal("%s: service accept failed: %s", authctxt->id, ssh_err(r));
				}
				sshpkt_get(ssh_client, NULL, len); // consume msg

 				setstat(authctxt, AUTHSTAT_INIT);
				continue;
			    }
			    if (type == SSH2_MSG_USERAUTH_INFO_RESPONSE) {
				if ((r = ssh2_send(ssh_server, type, msg, len)) != 0) {
					fatal("%s: relay client userauth info response to server failed: %s", authctxt->id, ssh_err(r));
				}
				sshpkt_get(ssh_client, NULL, len); // consume msg
				continue;
			    }
			    if (type == SSH2_MSG_USERAUTH_REQUEST) {
				/* copy userauth request for passthrough
				 */
				if ((auth_sb = sshbuf_from(msg, len)) == NULL) {
					fatal("%s: copy client authpkt", authctxt->id);
				}
				/* msg is consumed here
				 */
				if ((r = proxyauth_recv_request(ssh_client, authctxt)) != 0) {
					fatal("%s: recv next client userauth failed: %s", authctxt->id, ssh_err(r));
				}
				handle_auth_request(authctxt, ssh_server, &ignore);
				if (!ignore) {
					/* passthrough USERAUTH_REQUEST */
					if ((r = ssh2_send(ssh_server, SSH2_MSG_USERAUTH_REQUEST, sshbuf_ptr(auth_sb), sshbuf_len(auth_sb))) != 0) {
						fatal("%s: relay next client userauth to server failed: %s", authctxt->id, ssh_err(r));
					}
				}
				sshbuf_free(auth_sb);
				auth_sb = NULL;
				continue;
			    } else {
				if (authctxt->state != AUTHSTAT_SUCCESS) {
					error("%s: ignore client msg %d in state %d",
						authctxt->id, type, authctxt->state);
					sshpkt_get(ssh_client, NULL, len); // consume msg
					continue;
				}
				pass_done = 1;

				if (Opt_debug) {
				    char *astr = NULL;
				    char *fp = NULL;

				    if (authctxt->passwd) {
					astr = authctxt->passwd;
				    } else if (authctxt->key) {
					fp = sshkey_fingerprint(authctxt->key, SSH_DIGEST_MD5, SSH_FP_HEX);
					astr = fp;
				    }
				    if (!astr) {
					astr = "";
				    }
				    debug("%s: proxy fp %s", authctxt->id, astr);

				    if (fp) {
					free(fp);
				    }
				}
				logit("%s: proxy running", authctxt->id);
			    }
			}
			if (authctxt->filter) {
				/* msg is consumed here
				 */
				if ((r = authctxt->filter->client_data(ssh_client, type, msg, len)) != 0) {
					error("%s: filter client data %d len %zu failed: %s", authctxt->id, type, len, ssh_err(r));
					goto out;
				}
				continue;
			}
			if (type < SSH2_MSG_CONNECTION_MIN) {
				error("%s: no passthrough for client msg %d in state %d", authctxt->id, type, authctxt->state);
			} else {
				if ((r = ssh2_send(ssh_server, type, msg, len)) != 0) {
					sshpkt_get(ssh_client, NULL, len); // consume msg
					goto out;
				}
			}
			// consume msg
			if ((r = sshpkt_get(ssh_client, NULL, len)) != 0 ||
			    (r = sshpkt_get_end(ssh_client)) != 0) {
				goto out;
			}
		    }
		} else if (FD_ISSET(server_fd, &fds)) {
		    /*
		     * SERVER section
		     */
		    if ((r = ssh2_read_append(ssh_server)) != 0) {
			if (r == SSH_ERR_CONN_CLOSED) {
			    	debug("%s: server connection closed", authctxt->id);
			} else {
			    	error("%s: server read failed: %s", authctxt->id, ssh_err(r));
			}
			break;
		    }
		    while (1) {
			if ((r = ssh2_recv_nonblock(ssh_server, &type, &msg, &len)) != 0) {
				if (r == SSH_ERR_DISCONNECTED) {
					debug("%s: server disconnected", authctxt->id);
				} else {
					error("%s: server recv failed: %s", authctxt->id, ssh_err(r));
				}
				goto out;
			}
			if (type == SSH_MSG_NONE) {
				break;
			}
			/*
			 * Server wants to rekey. This may be cipher
			 * dependent.
			 */
			if (type == SSH2_MSG_KEXINIT) {
				debug("%s: server SSH2_MSG_KEXINIT (rekey)", authctxt->id);
				if ((r = ssh2_recv_kexinit(ssh_server)) != 0) {
					fatal("%s: server rekeying failed: %s", authctxt->id, ssh_err(r));
				}
				continue; // might have packet in buffer
			}
			/* TODO: for challenge-response SSH2_MSG_USERAUTH_INFO_REQUEST
			 *       has the same msg-id as SSH2_MSG_USERAUTH_PK_OK.
			 */
			if (type == SSH2_MSG_USERAUTH_PK_OK) {
				/* copy userauth request for passthrough
				 */
				struct sshbuf *sb;

				if ((sb = sshbuf_from(msg, len)) == NULL) {
					fatal("%s: copy server userauth_pk_ok", authctxt->id);
				}
				debug("%s: server SSH2_MSG_USERAUTH_PK_OK", authctxt->id);

				/* msg is consumed here
				 */
				if ((r = proxyauth_recv_pk_ok(ssh_server, authctxt)) != 0) {
					fatal("%s: userauth_pk_ok receive failed: %s", authctxt->id, ssh_err(r));
				}
				switch(authctxt->state) {
				case AUTHSTAT_PUBKEY_NOSIG:
					if ((r = proxyauth_send_hostbased(ssh_server, authctxt, ssh2_client_ctx->authkey)) != 0) {
						fatal("%s: auth hostbased failed: %s", authctxt->id, ssh_err(r));
					}
					setstat(authctxt, AUTHSTAT_HOSTBASED);
					break;
				default:
					setstat(authctxt, AUTHSTAT_INIT);

					/* passthrough PK_OK */
					if ((r = ssh2_send(ssh_client, type, sshbuf_ptr(sb), sshbuf_len(sb))) != 0) {
						fatal("%s: relay server userauth_pk_ok to client failed: %s", authctxt->id, ssh_err(r));
					}
					break;
				}
				sshbuf_free(sb);
				continue;
			}
			if (type == SSH2_MSG_USERAUTH_SUCCESS) {
				debug("%s: server SSH2_MSG_USERAUTH_SUCCESS", authctxt->id);

				switch(authctxt->state) {
				case AUTHSTAT_PASSWD:
					/* login brute force check: send SSH2_MSG_USERAUTH_FAILURE if blacklisted */
					if (!check_login(ssh_client, authctxt, 1)) {
						error("%s: check_login invalid", authctxt->id);
						type = SSH2_MSG_USERAUTH_FAILURE;
						if ((r = proxyauth_send_features(ssh_client, authctxt)) != 0) {
							fatal("%s: login brute forced - auth features failed for user=%s: %s", authctxt->id, authctxt->user, ssh_err(r));
						}
						sshpkt_get(ssh_server, NULL, len); // consume msg
						setstat(authctxt, AUTHSTAT_INIT);
						continue;
					}
					break;
				case AUTHSTAT_HOSTBASED:
					break;
				default:
					error("%s: auth success w.o. pk_ok", authctxt->id);
					if ((r = proxyauth_send_failure_passwd_only(ssh_client)) != 0) {
					    fatal("%s: auth failure failed: %s", authctxt->id, ssh_err(r));
					}
					sshpkt_get(ssh_server, NULL, len); // consume msg
					setstat(authctxt, AUTHSTAT_INIT);
					continue;
				}

				/* passthrough SUCCESS */
				setstat(authctxt, AUTHSTAT_SUCCESS);
				if ((r = ssh2_send(ssh_client, type, msg, len)) != 0) {
					sshpkt_get(ssh_server, NULL, len); // consume msg
					goto out;
				}
				sshpkt_get(ssh_server, NULL, len); // consume msg
				continue;
			}
			if (type == SSH2_MSG_USERAUTH_FAILURE) {
				debug("%s: server SSH2_MSG_USERAUTH_FAILURE", authctxt->id);

				/* msg is consumed here
				 */
				if ((r = proxyauth_recv_failure(ssh_server, authctxt)) != 0) {
					fatal("%s: auth receive failed: %s", authctxt->id, ssh_err(r));
				}

				/* always remove 'hostbased' here
				 *
				 * TODO:
				 * remove 'pubkey' here if server
				 * does not support 'hostbased'
				 */
				if(authctxt->state == AUTHSTAT_PASSWD) {
					/* login brute force check: update rate */
					check_login(ssh_client, authctxt, 0);
				} else if (authctxt->state == AUTHSTAT_HOSTBASED) {
					logit("%s: server hostbased auth failed", authctxt->id);
				}
				if (proxyauth_send_features( ssh_client, authctxt) < 0) {
					fatal("%s: auth features failed", authctxt->id);
				}
				setstat(authctxt, AUTHSTAT_INIT);
				continue;
			}
			if (type == SSH2_MSG_USERAUTH_BANNER) {
				if ((r = ssh2_send(ssh_client, type, msg, len)) != 0) {
					sshpkt_get(ssh_server, NULL, len); // consume msg
					goto out;
				}
				sshpkt_get(ssh_server, NULL, len); // consume msg
				continue;
			}
			if (type == SSH2_MSG_CHANNEL_OPEN_CONFIRMATION) {
				debug("%s: server SSH2_MSG_CHANNEL_OPEN_CONFIRMATION", authctxt->id);

			    if (!authctxt->have_chan) {
				// todo: might consume msg & dup msg for send() here
				if ((r = ssh2_channel_open_conf(ssh_server, authctxt, msg, len)) != 0) {
					error("%s: channel open conf: %s", authctxt->id, ssh_err(r));
				} else {
			    		authctxt->have_chan = 1;
					filter_add(ssh_server, authctxt);
				}
			    }
			}
			if (authctxt->filter) {
				/* msg is consumed here
				 */
				if ((r = authctxt->filter->server_data(ssh_server, type, msg, len)) != 0) {
					error("%s: filter server data %d len %zu failed: %s", authctxt->id, type, len, ssh_err(r));
					goto out;
				}
				continue;
			}
			if (type < SSH2_MSG_CONNECTION_MIN) {
				error("%s: no passthrough for server msg %d in state %d", authctxt->id, type, authctxt->state);
			} else {
				if ((r = ssh2_send(ssh_client, type, msg, len)) != 0) {
					sshpkt_get(ssh_server, NULL, len); // consume msg
					goto out;
				}
			}
			// consume msg
			if ((r = sshpkt_get(ssh_server, NULL, len)) != 0 ||
			    (r = sshpkt_get_end(ssh_server)) != 0) {
				goto out;
			}
		    }
		} else if ((filter_fd >= 0) && FD_ISSET(filter_fd, &fds)) {
			if (authctxt->filter->filter_data(ssh_server) != 0) {
				error("%s: filter input failed", authctxt->id);
				break;
			}
		} else {
			fatal("%s: select failed: %s", authctxt->id, strerror(errno));
		}
	}
out:
	logit("%s: disconnected", authctxt->id);

	for (i=0; i < (int)nserver; i++) {
		free(serverlist[i]);
		serverlist[i] = NULL;
	}
	ssh2_close(ssh_server);
	ssh2_close(ssh_client);
	authctxt_finit(authctxt);
}

static void proxy_child(int client_fd)
{
	int r;
	struct ssh *ssh_client = NULL;
	char *cp;
	int on = 1;
	struct Authctxt authctxt;

	if (Opt_keepalive) {
	    if (setsockopt(client_fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&on,
		sizeof(on)) < 0) {
		fatal("setsockopt SO_KEEPALIVE: %.100s", strerror(errno));
	    }
	}
	if (fcntl(client_fd, F_SETFL, 0) == -1) {
		fatal("fcntl");
	}
	if ((ssh_client = ssh2_new(ssh2_client_ctx, 1, ssh2_server_proposal)) == NULL) {
		fatal("malloc");
	}
	ssh2_set_fd(ssh_client, client_fd);

	authctxt_init(&authctxt);
	authctxt.ssh_client = ssh_client;
	ssh_client->authctxt = &authctxt;
	authctxt_update(&authctxt);

	debug("new connection from %s", ssh_remote_ipaddr(ssh_client));

	//dump_hostkey_proposal(ssh_client, "orig");
	if ((r = ssh_order_hostkeyalgs(ssh_client)) != 0) {
		fatal("%s: client order hostkeyags failed: %s", ssh_remote_ipaddr(ssh_client), ssh_err(r));
	}
	//dump_hostkey_proposal(ssh_client, "order");

	if ((r = _ssh_send_banner(ssh_client, ssh_client->kex->server_version)) != 0) {
		fatal("%s: client send banner failed: %s", ssh_remote_ipaddr(ssh_client), ssh_err(r));
	}
	if ((r = ssh_packet_write_wait(ssh_client)) != 0) {
		fatal("%s: server write banner failed: %s", ssh_remote_ipaddr(ssh_client), ssh_err(r));
	}
	if ((r = ssh2_read_append(ssh_client)) != 0) {
		if (r == SSH_ERR_CONN_CLOSED) {
			debug("%s: client connection closed", ssh_remote_ipaddr(ssh_client));
			exit(1);
		} else {
	    		fatal("%s: client recv banner failed: %s", ssh_remote_ipaddr(ssh_client), ssh_err(r));
		}
	}
	if ((r = _ssh_read_banner(ssh_client, ssh_client->kex->client_version)) != 0) {
		if (r == SSH_ERR_PROTOCOL_MISMATCH) {
			fatal("%s: client protocol mismatch", ssh_remote_ipaddr(ssh_client));
		} else {
			fatal("%s: client read banner failed: %s", ssh_remote_ipaddr(ssh_client), ssh_err(r));
		}
	}
	if (Opt_debug) {
		if ((cp = sshbuf_dup_string(ssh_client->kex->client_version)) == NULL) {
			fatal("malloc");
		}
		debug("client %s:%d version: %s compat: %08x", ssh_remote_ipaddr(ssh_client), ssh_remote_port(ssh_client), cp, ssh_client->compat);
		free(cp);
	}
	proxy_child2(&authctxt, ssh_client);
}

static int server_dispatch(int so, struct sockaddr *saddr)
{
	pid_t pid;

	if (Opt_dont_fork) {
#ifdef IGNORE_LB_MONITORING
		/* ignore monitoring */
		char *peer = get_peer_ipaddr(so);
		if (strncmp(peer, "192.168.5", 9) == 0) {
			free(peer);
			close(so);
			return 0;
		}
		free(peer);
#endif
		pid = 0;
	} else {
		if ((pid = fork()) < 0) {
			close(so);
			return errno;
		}
	}
	if (pid == 0) {
		close_listen_socks();

		log_init(__progname, options.log_level, options.log_facility, log_stderr);

		if (options.gid && setgid(options.gid)) {
			fatal("server_dispatch: setgid(%d) failed %s", options.gid, strerror(errno));
		}
		if (options.uid && setuid(options.uid)) {
			fatal("server_dispatch: setuid(%d) failed %s", options.uid, strerror(errno));
		}
		proxy_child(so);
		exit(0);
	}
	close(so);
	return 0;
}

static void sigterm_handler(int sig)
{
	received_sigterm = sig;
}

static void proxy_run(void)
{
	int ret;
	int i;
	int sock;
	int maxfd;
	fd_set fds;
	struct sockaddr_storage from;
	socklen_t fromlen;

	signal(SIGCHLD, sigchld_handler);
	signal(SIGTERM, sigterm_handler);
	signal(SIGQUIT, sigterm_handler);

	/* setup fd set for accept */
	maxfd = 0;
	for (i=0; i < num_listen_socks; i++) {
		if (listen_socks[i] > maxfd) {
			maxfd = listen_socks[i];
		}
	}
	for (;;) {
		FD_ZERO(&fds);

		for (i=0; i < num_listen_socks; i++) {
			FD_SET(listen_socks[i], &fds);
		}
		/* Wait in select until there is a connection. */
		if ((ret = select(maxfd + 1, &fds, 0, 0, 0)) == -1) {
			if (errno != EINTR) {
				fatal("select");
			}
		}
		if (received_sigterm) {
			logit("Received signal %d; terminating.", (int) received_sigterm);
			close_listen_socks();
			exit(received_sigterm == SIGTERM ? 0 : 255);
		}
		if (ret == -1) {
			continue;
		}
		for (i=0; i < num_listen_socks; i++) {
			if (!FD_ISSET(listen_socks[i], &fds)) {
				continue;
			}
			fromlen = sizeof(from);
			sock = accept(listen_socks[i], (struct sockaddr *)&from, &fromlen);

			if (sock == -1) {
				if (errno != EINTR && errno != EWOULDBLOCK &&
				    errno != ECONNABORTED && errno != EAGAIN) {
					error("accept: %.100s", strerror(errno));
				}
				continue;
			}
			if (unset_nonblock(sock) == -1) {
				close(sock);
				continue;
			}
			server_dispatch(sock, (struct sockaddr *)&from);
			lb_offset++;

		}
	}
}

int main(int argc, char *argv[])
{
	extern char *optarg;
	extern int optind;
	int c;
	int err;
	char *config_file = CONFIG_FILE;

	proxy_options_init(&options);

	__progname = ssh_get_progname(argv[0]);

	while ((c = getopt(argc, argv, "deIrfp:P:c:b:R:D:A:E:C:2h?Vh")) != -1) {
		switch (c) {
		case 'd':
			options.log_level = SYSLOG_LEVEL_DEBUG3;
			Opt_debug = 1;
			break;
		case 'e':
			log_stderr = 1;
			break;
		case 'I':
			options.filter_mitm = 1;
			break;
		case 'f':
			Opt_dont_fork = 1;
			break;
		case 'p':
			options.local_port = optarg;
			break;
		case 'P':
			options.server_port = optarg;
			break;
		case 'c':
			config_file = optarg;
			break;
		case 'b':
			options.bindaddr = optarg;
			break;
		case 'h':
		default:
			usage();
			break;
		}
	}
	argc -= optind;
	argv += optind;

	log_init(__progname, options.log_level, options.log_facility, log_stderr);

	if (argc > 0) {
		options.default_server = argv[0];
	}
	if ((err = config_read(config_file, &options))) {
		fatal("config_read failed: %s", strerror(err));
	}

	/* as a default bind to all interfaces (INADDR_ANY:port)
	 * if no opt_bindaddr is given
	 */
	if (!options.local_port) {
		options.local_port = "22"; /* default port */
	}
	proxy_init(options.bindaddr, options.local_port);

	if (options.switch_methods) {
		int i, len;
		char *p, *s;
		
		for (s = options.switch_methods; s != NULL; s = p+1) {
			if ((p = strchr(s, ','))) {
				len = p-s;
			} else {
				len = strlen(s);
			}
			for (i=0; switchmethods[i] != NULL; i++) {
				if (strncmp(switchmethods[i]->name, s, len) == 0) {
					switchmethods[i]->enabled = 1;
					break;
				}
			}
			if (switchmethods[i] == NULL) {
				fatal("bad switch method: %.*s", len, s);
			}
			if (!p) {
				break;
			}
		}
	} else {
		options.switch_methods = "no";
	}
	logit("sshproxy " PROXY_VERSION " " SSH_VERSION " - conf: %s (use %s switch)", config_file, options.switch_methods);
	proxy_run();

	exit(0);
}
