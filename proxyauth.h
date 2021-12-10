/*
 * proxyauth.h
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

int proxyauth_recv_request(struct ssh *ssh, struct Authctxt *authctxt);
int proxyauth_recv_pk_ok(struct ssh *ssh, struct Authctxt *authctxt);
int proxyauth_recv_failure(struct ssh *ssh, struct Authctxt *authctxt);
int proxyauth_recv_auth_pkg(struct ssh *ssh, struct Authctxt *authctxt,
	struct sshbuf **auth_sbp);
int proxyauth_send_service_accept(struct ssh *ssh);
int proxyauth_send_reply(struct ssh *ssh, struct Authctxt *authctxt);
int proxyauth_send_features(struct ssh *ssh, struct Authctxt *authctxt);
int proxyauth_send_failure_passwd_only(struct ssh *ssh);
int proxyauth_send_none(struct ssh *ssh, struct Authctxt *authctxt);
int proxyauth_send_passwd(struct ssh *ssh, struct Authctxt *authctxt);
int proxyauth_send_start_hostbased(struct ssh *ssh);
int proxyauth_send_hostbased(struct ssh *ssh, struct Authctxt *authctxt,
	struct sshkey *private);
int proxyauth_send_pubkey_nosig(struct ssh *ssh, struct Authctxt *authctxt);
int proxyauth_sign_and_send_pubkey(struct ssh *ssh, struct Authctxt *authctxt,
	struct sshkey *private);

