/*
 * proxyconf.h
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

struct target {
	char *user;
	char *server;
};

/* proxy options
 */
struct ProxyOptions {
	char	**host_key_files;	/* Files containing host keys. */
	u_int	num_host_key_files;     /* Number of files for host keys. */
	char	**host_cert_files;	/* Files containing host certs. */
	u_int	num_host_cert_files;	/* Number of files for host certs. */

	SyslogFacility log_facility;	/* Facility for system logging. */
	LogLevel log_level;		/* Level for system logging. */

	char   *ciphers;		/* Supported SSH2 ciphers. */
	char   *macs;			/* Supported SSH2 macs. */
	char   *kex_algorithms;		/* SSH2 kex methods in order of preference. */

	char	*bindaddr;
	char	*hostkey_auth;
	char	*default_server;	/* default server for fixed switch */
	char	*server_port;
	int	server_family;
	char	*local_port;
	int	uid;
	int	gid;
	char	*switch_methods;	/* enable switch methods explicitly */
	struct target *switch_targets;  /* list of user targets for fixed switch */
	u_int	num_switch_targets;
	int 	filter_mitm;
};

void proxy_options_init(struct ProxyOptions *options);
int config_read(const char *name, struct ProxyOptions *options);

void add_hostkey(struct ProxyOptions *options, const char *path);
void add_hostcert(struct ProxyOptions *options, const char *path);
void add_hostkeys(struct ProxyOptions *options, char *path);
void add_hostcerts(struct ProxyOptions *options, char *path);

