/*
 * switch-fixed.c - config based backend host switch
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
#include "ssh2.h"
#include "packet.h"
#include "match.h"
#include "xmalloc.h"
#include "misc.h"
#include "sshproxy.h"
#include "proxyconf.h"
#include "switch.h"

static int fixed_server_select(struct ssh *ssh, struct Authctxt *authctxt,
	char **server, unsigned int maxserver, unsigned int *nserver)
{
	u_int i;

	if (maxserver < 1) {
		return EINVAL;
	}
	for (i = 0; i < options.num_switch_targets; i++) {
		struct target *target = options.switch_targets + i;
		if (match_usergroup_pattern_list(target->user, authctxt->user)) {
			server[0] = xstrdup(target->server);
			*nserver = 1;
			return 0;
		}
	}
	if (options.default_server) {
		server[0] = xstrdup(options.default_server);
		*nserver = 1;
		return 0;
	}
	return ENOENT;
}

struct Switchmethod switch_fixed = {
	"fixed",
	fixed_server_select,
	0,
};

