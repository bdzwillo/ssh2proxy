/*
 * proxyconf.c
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
#include "switch.h"
#include "check.h"
#include "filter.h"

static void assemble_algorithms(struct ProxyOptions *options)
{
	char *all_cipher, *all_mac, *all_kex;
	char *def_cipher, *def_mac, *def_kex;
	int r;

	all_cipher = cipher_alg_list(',', 0);
	all_mac = mac_alg_list(',');
	all_kex = kex_alg_list(',');
	/* remove unsupported algos from default lists */
	def_cipher = match_filter_whitelist(KEX_SERVER_ENCRYPT, all_cipher);
	def_mac = match_filter_whitelist(KEX_SERVER_MAC, all_mac);
	def_kex = match_filter_whitelist(KEX_SERVER_KEX, all_kex);
#define ASSEMBLE(what, defaults, all) \
	do { \
		if ((r = kex_assemble_names(&options->what, defaults, all)) != 0) \
			fatal("%s: %s: %s", __func__, #what, ssh_err(r)); \
	} while (0)
	ASSEMBLE(ciphers, def_cipher, all_cipher);
	ASSEMBLE(macs, def_mac, all_mac);
	ASSEMBLE(kex_algorithms, def_kex, all_kex);
#undef ASSEMBLE
	free(all_cipher);
	free(all_mac);
	free(all_kex);
	free(def_cipher);
	free(def_mac);
	free(def_kex);
}

void proxy_options_init(struct ProxyOptions *options)
{
	memset(options, 0, sizeof(*options));
	options->log_facility = SYSLOG_FACILITY_USER;
	options->log_level = SYSLOG_LEVEL_INFO;

	/* add some algorithms for compatibility with older clients
	 */
	options->kex_algorithms = xstrdup("+diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1");
	//options->ciphers = xstrdup("+aes256-cbc");
	
	assemble_algorithms(options);
}

static void array_append(char ***array, u_int *lp, const char *s)
{
	if (*lp >= INT_MAX)
		fatal("array_append: Too many entries");

	*array = xrecallocarray(*array, *lp, *lp + 1, sizeof(**array));
	(*array)[*lp] = xstrdup(s);
	(*lp)++;
}

void add_hostkey(struct ProxyOptions *options, const char *path)
{
	path = xstrdup(path);
	array_append(&options->host_key_files, &options->num_host_key_files, path);
}

void add_hostcert(struct ProxyOptions *options, const char *path)
{
	path = xstrdup(path);
	array_append(&options->host_cert_files, &options->num_host_cert_files, path);
}

void add_hostkeys(struct ProxyOptions *options, char *path)
{
	char *p;

	while ((p = strchr(path,','))) {
		*p = '\0';
		add_hostkey(options, path);
		path = p+1;
		*p = ',';
	}
	if (*path) {
		add_hostkey(options, path);
	}
}

void add_hostcerts(struct ProxyOptions *options, char *path)
{
	char *p;

	while ((p = strchr(path,','))) {
		*p = '\0';
		add_hostcert(options, path);
		path = p+1;
		*p = ',';
	}
	if (*path) {
		add_hostcert(options, path);
	}
}

void add_target(struct ProxyOptions *options, const char *user, const char *server)
{
	struct target *target;

	options->switch_targets = xreallocarray(options->switch_targets,
	    options->num_switch_targets + 1,
	    sizeof(*options->switch_targets));
	target = &options->switch_targets[options->num_switch_targets++];
	target->user = xstrdup(user);
	target->server = xstrdup(server);
}

int match(const char *key, const char *pat)
{
	return strcmp(key, pat) == 0;
}

int config_read(const char *name, struct ProxyOptions *options)
{
	FILE *fp;
	char *key;
	char *val;
	char buf[1024];
	char *eq;

	if (!(fp = fopen(name, "r"))) {
		return errno;
	}
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		if (buf[0] == '\n' || buf[0] == '#') {
			/* skip empty and comment lines */
			continue;
		}
		if (!(key = strtok(buf, " \t")) 
			|| !(eq = strtok(NULL, " \t"))
			|| (strcmp(eq, "=") != 0)
			|| !(val = strtok(NULL, " \t\r\n"))) {
			continue;
		}
		val = xstrdup(val);

		if (match(key, "bindaddr")) {
			if (!options->bindaddr) {
				options->bindaddr = val;
			}
		} else if (match(key, "server_port")) {
 			// default server port if no port is given
			options->server_port = val;
		} else if (match(key, "server_family")) {
			options->server_family = atoi(val);
		} else if (match(key, "hostkey_auth")) {
			options->hostkey_auth = val;
		} else if (match(key, "hostkey")) {
			add_hostkey(options, val);
		} else if (match(key, "hostkey_certs")) {
			add_hostcerts(options, val);
		} else if (match(key, "switch_methods")) {
			options->switch_methods = val;
		} else if (match(key, "default_server")) {
			options->default_server = val;
		} else if (match(key, "switch_target")) {
			char *server = strtok(NULL, " \t\r\n");
			if (!server) {
				logit("switch_target config missing server for user '%s'", val);
				continue;
			}
			add_target(options, val, server);
		} else if (match(key, "setuid")) {
			options->uid = atoi(val);
		} else if (match(key, "setgid")) {
			options->gid = atoi(val);
		} else if (match(key, "proxy_port")) {
			if (!options->local_port) {
				options->local_port = val;
			}
		} else {
			debug("ignore config option: %s = %s", key, val);
		}
	}
	if (!options->server_port) {
		options->server_port = "22";
	}
	if (!options->switch_methods) {
		if (options->default_server) {
			options->switch_methods = "fixed";
		}
	}
	fclose(fp);
	return 0;
}

