/*
 * test/proxy_password.c - password authentication.
 *
 * Prove the proxy's password path against a real backend sshd. The proxy reads
 * the username, dials the backend, completes a key exchange, then relays the
 * client's password request (README step 6).
 *
 * The backend must present the hostkey the proxy is configured with: the proxy
 * verifies it against its configured key (so a client's known_hosts still
 * matches - see README).
 *
 * test_password() - the password request is relayed to the backend
 * test_password_ok() - a password login completes end to end (user namespace)
 */
#define _GNU_SOURCE
#include <sched.h>
#include <sys/mount.h>

#include <crypt.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "tap.h"
#include "proxy_test.h"
#include "chroot_ns.h"

#define LOGIN_USER "wuser"
#define LOGIN_PASS "PROXY_TEST_PW"

/* test_password: the proxy relays the client's password request to the backend.
 * - a bogus password is fed, and the backend logs a password attempt
 * - cannot succeed unprivileged (sshd can't check a real account), but the
 *   relay is what matters
 */
static void test_password(const struct proxy_env *e)
{
	char tmp[256], pcfg[PATH_MAX], plog[PATH_MAX];
	char scfg[PATH_MAX], slog[PATH_MAX];
	char hostkey[PATH_MAX], id[PATH_MAX], askpass[PATH_MAX];
	struct passwd *pw = getpwuid(getuid());
	const char *me = pw ? pw->pw_name : "nobody";
	int pport, bport;
	pid_t sshd_pid, proxy_pid;

	if (make_tmpdir("ssh_proxy_password", tmp, sizeof(tmp)) != 0) {
		tap_skip(2, "no tmpdir");
		return;
	}
	snprintf(hostkey, sizeof(hostkey), "%s/hostkey", tmp);
	snprintf(id, sizeof(id), "%s/id", tmp);
	if (ssh_gen_key(&e->tool, hostkey) != 0 || ssh_gen_key(&e->tool, id) != 0) {
		tap_skip(2, "keygen failed");
		return;
	}
	snprintf(scfg, sizeof(scfg), "%s/sshd_config", tmp);
	snprintf(slog, sizeof(slog), "%s/sshd.log", tmp);
	snprintf(pcfg, sizeof(pcfg), "%s/sshproxy.conf", tmp);
	snprintf(plog, sizeof(plog), "%s/proxy.log", tmp);
	snprintf(askpass, sizeof(askpass), "%s/askpass.sh", tmp);

	/* backend sshd: shares the proxy's hostkey, password auth on, no PAM so
	 * the (doomed) password check is logged as a plain "Failed password"
	 */
	bport = pick_free_port();
	if (file_writef(scfg,
	    "Port %d\n"
	    "ListenAddress 127.0.0.1\n"
	    "HostKey %s\n"
	    "StrictModes no\n"
	    "LogLevel VERBOSE\n"
	    "UsePAM no\n"
	    "PrintMotd no\n"
	    "PasswordAuthentication yes\n"
	    "PubkeyAuthentication no\n",
	    bport, hostkey) != 0) {
		tap_skip(2, "no sshd cfg");
		return;
	}

	sshd_pid = sshd_spawn(e, scfg, slog);
	if (!tap_ok(sshd_pid > 0 && wait_for_listen(bport, 5000) == 0,
	    "password: backend sshd up on 127.0.0.1:%d", bport)) {
		file_dump(slog, "sshd.log");
		tap_skip(1, "backend sshd down");
		reap_pg(sshd_pid, 50);
		return;
	}

	/* proxy in front, default_server -> the backend sshd */
	pport = pick_free_port();
	if (file_writef(pcfg,
	    "bindaddr = 127.0.0.1:%d\n"
	    "hostkey = %s\n"
	    "hostkey_auth = %s\n"
	    "switch_methods = fixed\n"
	    "default_server = 127.0.0.1:%d\n",
	    pport, hostkey, id, bport) != 0) {
		tap_skip(1, "no proxy cfg");
		reap_pg(sshd_pid, 50);
		return;
	}

	proxy_pid = proxy_spawn(e, pcfg, plog);
	if (proxy_pid <= 0 || wait_for_listen(pport, 5000) != 0) {
		tap_ok(0, "password: proxy relays the password attempt to the backend");
		file_dump(plog, "proxy.log");
		reap_pg(proxy_pid, 50);
		reap_pg(sshd_pid, 50);
		return;
	}

	write_askpass(askpass, "BOGUS_PASSWORD");
	ssh_password(e, me, pport, askpass);

	if (!tap_ok(file_contains(slog, "Failed password"),
	    "password: proxy relays the password attempt to the backend")) {
		file_dump(plog, "proxy.log");
		file_dump(slog, "sshd.log");
	}

	reap_pg(proxy_pid, 50);
	reap_pg(sshd_pid, 50);
}

/* Set up the sandbox login. Returns 0 on success.
 *
 * Binds a fake /etc/passwd with:
 *   - LOGIN_USER at uid 0, so sshd's setuid is a no-op
 *   - that user's given crypt hash and sandbox home
 *   - the sshd privsep user
 *
 * Binds a 0755 /var/empty for sshd privsep.
 */
static int prep_password_ns(const char *tmp, const char *home, const char *hash)
{
	char body[2 * PATH_MAX + 128];

	snprintf(body, sizeof(body),
		"%s:%s:0:0:%s:%s:/bin/sh\n"
		"sshd:x:0:0:sshd:/var/empty:/sbin/nologin\n",
		LOGIN_USER, hash, LOGIN_USER, home);
	if (ns_bind_passwd(tmp, body) != 0) {
		return -1;
	}
	return ns_bind_var_empty(tmp);
}

/* test_password_ok: a password login completes end to end.
 * - runs in a user namespace mapped to uid 0
 * - binds an /etc/passwd whose login user has a known crypt(3) hash, absent
 *   from the host's /etc/shadow, so sshd (UsePAM no) checks the sandbox
 * - skips if user namespaces are unavailable
 */
static void test_password_ok(const struct proxy_env *e)
{
	char tmp[256], home[PATH_MAX], askpass[PATH_MAX + 16];
	char pcfg[PATH_MAX], plog[PATH_MAX], scfg[PATH_MAX], slog[PATH_MAX];
	char hostkey[PATH_MAX], reason[256], stub[PATH_MAX + 32], out[1024];
	char *hash;
	int pport, bport, rc;
	pid_t sshd_pid, proxy_pid;

	resolve_sibling(e->tool.argv0, "setgroups_stub.so", stub, sizeof(stub));

	if (enter_userns() != 0) {
		snprintf(reason, sizeof(reason),
			"user namespaces unavailable (%s)", strerror(errno));
		tap_skip(2, reason);
		return;
	}
	if (make_tmpdir("ssh_proxy_password_ok", tmp, sizeof(tmp)) != 0) {
		tap_skip(2, "no tmpdir");
		return;
	}
	snprintf(home, sizeof(home), "%s/home", tmp);
	if (mkdir(home, 0755) < 0 && errno != EEXIST) {
		tap_skip(2, "no sandbox home");
		return;
	}
	hash = crypt(LOGIN_PASS, "$6$proxytest$");
	if (hash == NULL) {
		tap_skip(2, "crypt failed");
		return;
	}
	if (prep_password_ns(tmp, home, hash) != 0) {
		snprintf(reason, sizeof(reason),
			"namespace fs setup failed (%s)", strerror(errno));
		tap_skip(2, reason);
		return;
	}

	snprintf(hostkey, sizeof(hostkey), "%s/hostkey", tmp);
	if (ssh_gen_key(&e->tool, hostkey) != 0) {
		tap_skip(2, "keygen failed");
		return;
	}
	snprintf(scfg, sizeof(scfg), "%s/sshd_config", tmp);
	snprintf(slog, sizeof(slog), "%s/sshd.log", tmp);
	snprintf(pcfg, sizeof(pcfg), "%s/sshproxy.conf", tmp);
	snprintf(plog, sizeof(plog), "%s/proxy.log", tmp);
	snprintf(askpass, sizeof(askpass), "%s/askpass.sh", tmp);

	bport = pick_free_port();
	if (file_writef(scfg,
	    "Port %d\n"
	    "ListenAddress 127.0.0.1\n"
	    "HostKey %s\n"
	    "StrictModes no\n"
	    "LogLevel VERBOSE\n"
	    "UsePAM no\n"
	    "PrintMotd no\n"
	    "PermitRootLogin yes\n"
	    "PasswordAuthentication yes\n"
	    "PubkeyAuthentication no\n",
	    bport, hostkey) != 0) {
		tap_skip(2, "no sshd cfg");
		return;
	}

	setenv("LD_PRELOAD", stub, 1);
	sshd_pid = sshd_spawn(e, scfg, slog);
	unsetenv("LD_PRELOAD");
	if (!tap_ok(sshd_pid > 0 && wait_for_listen(bport, 5000) == 0,
	    "password_ok: backend sshd up on 127.0.0.1:%d (uid 0 in ns)", bport)) {
		file_dump(slog, "sshd.log");
		tap_skip(1, "backend sshd down");
		reap_pg(sshd_pid, 50);
		return;
	}

	pport = pick_free_port();
	if (file_writef(pcfg,
	    "bindaddr = 127.0.0.1:%d\n"
	    "hostkey = %s\n"
	    "switch_methods = fixed\n"
	    "default_server = 127.0.0.1:%d\n",
	    pport, hostkey, bport) != 0) {
		tap_skip(1, "no proxy cfg");
		reap_pg(sshd_pid, 50);
		return;
	}

	proxy_pid = proxy_spawn(e, pcfg, plog);
	if (proxy_pid <= 0 || wait_for_listen(pport, 5000) != 0) {
		file_dump(plog, "proxy.log");
		tap_skip(1, "proxy down");
		reap_pg(proxy_pid, 50);
		reap_pg(sshd_pid, 50);
		return;
	}

	write_askpass(askpass, LOGIN_PASS);
	/* the login must complete AND run a remote command end to end */
	rc = ssh_password_cmd(e, LOGIN_USER, pport, askpass,
		"echo PW_LOGIN_OK", out, sizeof(out));

	if (!tap_ok(rc == 0 && strstr(out, "PW_LOGIN_OK") != NULL &&
	    file_contains(slog, "Accepted password for " LOGIN_USER),
	    "password_ok: password login runs a remote command via the proxy")) {
		fprintf(stderr, "# ssh rc=%d out='%s'\n", rc, out);
		file_dump(plog, "proxy.log");
		file_dump(slog, "sshd.log");
	}

	reap_pg(proxy_pid, 50);
	reap_pg(sshd_pid, 50);
}

int main(int argc, char **argv)
{
	struct proxy_env env;

	(void)argc;
	tap_plan(4);

	proxy_resolve_paths(&env, argv[0]);
	test_password(&env);      /* relayed (no namespace) */
	test_password_ok(&env);   /* full login (user namespace) */

	return tap_done();
}
