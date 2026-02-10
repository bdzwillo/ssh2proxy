/*
 * test/proxy_pubkey.c - public-key and hostbased authentication.
 *
 * Prove the proxy's public-key path against a real backend sshd:
 *   - the proxy validates the client's signed key itself
 *   - it probes the backend with the unsigned key to learn whether it is known
 *   - it then re-authenticates to the backend with *hostbased* auth, using the
 *     proxy's hostkey_auth key (README steps 7-9)
 *
 * This is the proxy's defining trick: a client pubkey can't be replayed to the
 * backend (the kex hash differs), so the backend authentication switches to
 * hostbased.
 *
 * test_pubkey() - observable steps, with no host trust set up
 * test_hostbased() - full hostbased login in a user namespace
 * test_rekey() - in-session rekeying survives the proxy
 * test_interactive() - interactive pty session through the proxy
 */
#define _GNU_SOURCE
#include <sched.h>
#include <sys/mount.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "tap.h"
#include "proxy_test.h"
#include "chroot_ns.h"

/* payload streamed back in test_rekey(); >> RekeyLimit so each leg rekeys many
 * times mid-transfer (262144 / 16384 = 16 rekeys per direction).
 */
#define REKEY_BYTES 262144

/* like ssh_pubkey_cmd() but pins RekeyLimit to its 16-byte-rounded-up minimum so
 * the client rekeys the client<->proxy leg repeatedly during the transfer.
 */
static int ssh_rekey_cmd(const struct proxy_env *e, const char *user, int port,
	const char *identity, const char *cmd, char *out, size_t outsz)
{
	char userat[256], portarg[16];

	snprintf(userat, sizeof(userat), "%s@127.0.0.1", user);
	snprintf(portarg, sizeof(portarg), "%d", port);
	{
		char *argv[] = {
			(char *)e->tool.ssh, "-F", "/dev/null",
			"-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "GlobalKnownHostsFile=/dev/null",
			"-o", "LogLevel=ERROR",
			"-o", "BatchMode=yes",
			"-o", "ConnectTimeout=5",
			"-o", "PreferredAuthentications=publickey",
			"-o", "RekeyLimit=16k",
			"-i", (char *)identity, "-p", portarg, userat,
			(char *)cmd, (char *)NULL
		};
		return run_capture(argv, 0, out, outsz);
	}
}

/* test_pubkey: observable steps of the pubkey->hostbased translation, with no
 * host trust set up (so the hostbased leg is expected to be rejected).
 * - the backend accepts the proxy's no-sig pubkey probe
 * - the proxy emits a hostbased request, which the backend then rejects
 */
static void test_pubkey(const struct proxy_env *e)
{
	char tmp[256], pcfg[PATH_MAX], plog[PATH_MAX];
	char scfg[PATH_MAX], slog[PATH_MAX];
	char hostkey[PATH_MAX], id[PATH_MAX], authkeys[PATH_MAX + 4];
	char out[1024];
	struct passwd *pw = getpwuid(getuid());
	const char *me = pw ? pw->pw_name : "nobody";
	int pport, bport;
	pid_t sshd_pid, proxy_pid;

	if (make_tmpdir("ssh_proxy_pubkey", tmp, sizeof(tmp)) != 0) {
		tap_skip(3, "no tmpdir");
		return;
	}
	snprintf(hostkey, sizeof(hostkey), "%s/hostkey", tmp);
	snprintf(id, sizeof(id), "%s/id", tmp);
	if (ssh_gen_key(&e->tool, hostkey) != 0 || ssh_gen_key(&e->tool, id) != 0) {
		tap_skip(3, "keygen failed");
		return;
	}
	/* the client identity doubles as the backend's authorized_keys */
	snprintf(authkeys, sizeof(authkeys), "%s.pub", id);
	snprintf(scfg, sizeof(scfg), "%s/sshd_config", tmp);
	snprintf(slog, sizeof(slog), "%s/sshd.log", tmp);
	snprintf(pcfg, sizeof(pcfg), "%s/sshproxy.conf", tmp);
	snprintf(plog, sizeof(plog), "%s/proxy.log", tmp);

	/* backend sshd: shares the proxy hostkey, knows the client key, and is
	 * willing to do hostbased (so the proxy's translated request is logged)
	 */
	bport = pick_free_port();
	if (file_writef(scfg,
	    "Port %d\n"
	    "ListenAddress 127.0.0.1\n"
	    "HostKey %s\n"
	    "StrictModes no\n"
	    "LogLevel DEBUG1\n"
	    "UsePAM no\n"
	    "PrintMotd no\n"
	    "PasswordAuthentication no\n"
	    "PubkeyAuthentication yes\n"
	    "HostbasedAuthentication yes\n"
	    "AuthorizedKeysFile %s\n",
	    bport, hostkey, authkeys) != 0) {
		tap_skip(3, "no sshd cfg");
		return;
	}

	sshd_pid = sshd_spawn(e, scfg, slog);
	if (!tap_ok(sshd_pid > 0 && wait_for_listen(bport, 5000) == 0,
	    "pubkey: backend sshd up on 127.0.0.1:%d", bport)) {
		file_dump(slog, "sshd.log");
		tap_skip(2, "backend sshd down");
		reap_pg(sshd_pid, 50);
		return;
	}

	pport = pick_free_port();
	if (file_writef(pcfg,
	    "bindaddr = 127.0.0.1:%d\n"
	    "hostkey = %s\n"
	    "hostkey_auth = %s\n"
	    "switch_methods = fixed\n"
	    "default_server = 127.0.0.1:%d\n",
	    pport, hostkey, id, bport) != 0) {
		tap_skip(2, "no proxy cfg");
		reap_pg(sshd_pid, 50);
		return;
	}

	proxy_pid = proxy_spawn(e, pcfg, plog);
	if (proxy_pid <= 0 || wait_for_listen(pport, 5000) != 0) {
		file_dump(plog, "proxy.log");
		tap_skip(2, "proxy down");
		reap_pg(proxy_pid, 50);
		reap_pg(sshd_pid, 50);
		return;
	}

	ssh_pubkey_cmd(e, me, pport, id, "true", out, sizeof(out));

	if (!tap_ok(file_contains(slog, "Postponed publickey"),
	    "pubkey: backend accepts the proxy's no-sig pubkey probe")) {
		file_dump(slog, "sshd.log");
	}
	if (!tap_ok(file_contains(plog, "userauth_hostbased"),
	    "pubkey: proxy translates the client pubkey to hostbased")) {
		file_dump(plog, "proxy.log");
	}

	reap_pg(proxy_pid, 50);
	reap_pg(sshd_pid, 50);
}

/* Set up the sandbox login. Returns 0 on success.
 *
 * Binds a fake /etc/passwd with:
 *   - login user "root" at uid 0, so sshd's setuid is a no-op
 *   - that user's sandbox home
 *   - the sshd privsep user
 *
 * Binds a 0755 /var/empty for sshd privsep.
 */
static int prep_hostbased_ns(const char *tmp, const char *home)
{
	char body[2 * PATH_MAX + 128];

	snprintf(body, sizeof(body),
		"root:x:0:0:root:%s:/bin/sh\n"
		"sshd:x:0:0:sshd:/var/empty:/sbin/nologin\n", home);
	if (ns_bind_passwd(tmp, body) != 0) {
		return -1;
	}
	return ns_bind_var_empty(tmp);
}

/* test_hostbased: the hostbased login *succeeds* and a remote command runs.
 * - the backend must trust the proxy's host: the client host name in ~/.shosts
 *   and the hostkey_auth key in ~/.ssh/known_hosts of the target user, under
 *   its pw_dir - which must not be touched in the real home
 * - so this runs in a user namespace mapped to uid 0, with a bind-mounted
 *   /etc/passwd whose login user "root" has a sandbox home the test populates
 * - the real home is never written; skips without user namespaces
 */
static void test_hostbased(const struct proxy_env *e)
{
	char tmp[256], home[PATH_MAX], sshdir[PATH_MAX + 8];
	char pcfg[PATH_MAX], plog[PATH_MAX], scfg[PATH_MAX], slog[PATH_MAX];
	char hostkey[PATH_MAX], id[PATH_MAX], authkeys[PATH_MAX + 4];
	char out[4096], reason[256], stub[PATH_MAX + 32];
	int pport, bport;
	pid_t sshd_pid, proxy_pid;

	resolve_sibling(e->tool.argv0, "setgroups_stub.so", stub, sizeof(stub));

	if (enter_userns() != 0) {
		snprintf(reason, sizeof(reason),
			"user namespaces unavailable (%s)", strerror(errno));
		tap_skip(2, reason);
		return;
	}
	if (make_tmpdir("ssh_proxy_hostbased", tmp, sizeof(tmp)) != 0) {
		tap_skip(2, "no tmpdir");
		return;
	}
	snprintf(home, sizeof(home), "%s/home", tmp);
	snprintf(sshdir, sizeof(sshdir), "%s/.ssh", home);
	if (mkdir(home, 0755) < 0 || mkdir(sshdir, 0755) < 0) {
		tap_skip(2, "no sandbox home");
		return;
	}
	if (prep_hostbased_ns(tmp, home) != 0) {
		snprintf(reason, sizeof(reason),
			"namespace fs setup failed (%s)", strerror(errno));
		tap_skip(2, reason);
		return;
	}

	snprintf(hostkey, sizeof(hostkey), "%s/hostkey", tmp);
	snprintf(id, sizeof(id), "%s/id", tmp);
	if (ssh_gen_key(&e->tool, hostkey) != 0 || ssh_gen_key(&e->tool, id) != 0) {
		tap_skip(2, "keygen failed");
		return;
	}
	snprintf(authkeys, sizeof(authkeys), "%s.pub", id);

	/* trust the proxy's host for user root, pinning its hostkey_auth key (id) */
	if (setup_hostbased_trust(home, sshdir, authkeys) != 0) {
		tap_skip(2, "hostbased trust setup failed");
		return;
	}

	snprintf(scfg, sizeof(scfg), "%s/sshd_config", tmp);
	snprintf(slog, sizeof(slog), "%s/sshd.log", tmp);
	snprintf(pcfg, sizeof(pcfg), "%s/sshproxy.conf", tmp);
	snprintf(plog, sizeof(plog), "%s/proxy.log", tmp);

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
	    "PasswordAuthentication no\n"
	    "PubkeyAuthentication yes\n"
	    "HostbasedAuthentication yes\n"
	    "HostbasedUsesNameFromPacketOnly yes\n"
	    "IgnoreRhosts no\n"
	    "AuthorizedKeysFile %s\n",
	    bport, hostkey, authkeys) != 0) {
		tap_skip(2, "no sshd cfg");
		return;
	}

	setenv("LD_PRELOAD", stub, 1);
	sshd_pid = sshd_spawn(e, scfg, slog);
	unsetenv("LD_PRELOAD");
	if (!tap_ok(sshd_pid > 0 && wait_for_listen(bport, 5000) == 0,
	    "hostbased: backend sshd up on 127.0.0.1:%d (uid 0 in ns)", bport)) {
		file_dump(slog, "sshd.log");
		tap_skip(1, "backend sshd down");
		reap_pg(sshd_pid, 50);
		return;
	}

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
		file_dump(plog, "proxy.log");
		tap_skip(1, "proxy down");
		reap_pg(proxy_pid, 50);
		reap_pg(sshd_pid, 50);
		return;
	}

	ssh_pubkey_cmd(e, "root", pport, id, "echo HB_SUCCESS", out, sizeof(out));

	if (!tap_ok(strstr(out, "HB_SUCCESS") != NULL &&
	    file_contains(slog, "Accepted hostbased for root"),
	    "hostbased: pubkey login completes via the backend hostbased leg")) {
		fprintf(stderr, "# out='%s'\n", out);
		file_dump(plog, "proxy.log");
		file_dump(slog, "sshd.log");
	}

	reap_pg(proxy_pid, 50);
	reap_pg(sshd_pid, 50);
}

/* test_rekey (2 tests): in-session rekeying must survive the proxy. A mid
 * session SSH2_MSG_KEXINIT is handled per leg (ssh2_recv_kexinit):
 *
 *   - the client rekeys the client<->proxy leg
 *   - the backend rekeys the proxy<->backend leg
 *
 * RekeyLimit 16k on both the client and the backend sshd forces many rekeys
 * while the payload streams back; it must arrive intact. Same hostbased uid-0
 * user-namespace login as test_hostbased; skips without user namespaces.
 */
static void test_rekey(const struct proxy_env *e)
{
	char tmp[256], home[PATH_MAX], sshdir[PATH_MAX + 8];
	char pcfg[PATH_MAX], plog[PATH_MAX], scfg[PATH_MAX], slog[PATH_MAX];
	char hostkey[PATH_MAX], id[PATH_MAX], authkeys[PATH_MAX + 4];
	char reason[256], stub[PATH_MAX + 32], cmd[128];
	char *out;
	size_t outsz = REKEY_BYTES + 4096;
	int pport, bport;
	pid_t sshd_pid, proxy_pid;

	resolve_sibling(e->tool.argv0, "setgroups_stub.so", stub, sizeof(stub));

	if ((out = malloc(outsz)) == NULL) {
		tap_skip(2, "no memory");
		return;
	}
	if (enter_userns() != 0) {
		snprintf(reason, sizeof(reason),
			"user namespaces unavailable (%s)", strerror(errno));
		tap_skip(2, reason);
		free(out);
		return;
	}
	if (make_tmpdir("ssh_proxy_rekey", tmp, sizeof(tmp)) != 0) {
		tap_skip(2, "no tmpdir");
		free(out);
		return;
	}
	snprintf(home, sizeof(home), "%s/home", tmp);
	snprintf(sshdir, sizeof(sshdir), "%s/.ssh", home);
	if (mkdir(home, 0755) < 0 || mkdir(sshdir, 0755) < 0) {
		tap_skip(2, "no sandbox home");
		free(out);
		return;
	}
	if (prep_hostbased_ns(tmp, home) != 0) {
		snprintf(reason, sizeof(reason),
			"namespace fs setup failed (%s)", strerror(errno));
		tap_skip(2, reason);
		free(out);
		return;
	}

	snprintf(hostkey, sizeof(hostkey), "%s/hostkey", tmp);
	snprintf(id, sizeof(id), "%s/id", tmp);
	if (ssh_gen_key(&e->tool, hostkey) != 0 || ssh_gen_key(&e->tool, id) != 0) {
		tap_skip(2, "keygen failed");
		free(out);
		return;
	}
	snprintf(authkeys, sizeof(authkeys), "%s.pub", id);

	if (setup_hostbased_trust(home, sshdir, authkeys) != 0) {
		tap_skip(2, "hostbased trust setup failed");
		free(out);
		return;
	}

	snprintf(scfg, sizeof(scfg), "%s/sshd_config", tmp);
	snprintf(slog, sizeof(slog), "%s/sshd.log", tmp);
	snprintf(pcfg, sizeof(pcfg), "%s/sshproxy.conf", tmp);
	snprintf(plog, sizeof(plog), "%s/proxy.log", tmp);

	bport = pick_free_port();
	/* RekeyLimit 16k here makes the backend rekey the proxy<->backend leg too */
	if (file_writef(scfg,
	    "Port %d\n"
	    "ListenAddress 127.0.0.1\n"
	    "HostKey %s\n"
	    "StrictModes no\n"
	    "LogLevel VERBOSE\n"
	    "UsePAM no\n"
	    "PrintMotd no\n"
	    "PermitRootLogin yes\n"
	    "PasswordAuthentication no\n"
	    "PubkeyAuthentication yes\n"
	    "HostbasedAuthentication yes\n"
	    "HostbasedUsesNameFromPacketOnly yes\n"
	    "IgnoreRhosts no\n"
	    "RekeyLimit 16k\n"
	    "AuthorizedKeysFile %s\n",
	    bport, hostkey, authkeys) != 0) {
		tap_skip(2, "no sshd cfg");
		free(out);
		return;
	}

	setenv("LD_PRELOAD", stub, 1);
	sshd_pid = sshd_spawn(e, scfg, slog);
	unsetenv("LD_PRELOAD");
	if (!tap_ok(sshd_pid > 0 && wait_for_listen(bport, 5000) == 0,
	    "rekey: backend sshd up on 127.0.0.1:%d (uid 0 in ns)", bport)) {
		file_dump(slog, "sshd.log");
		tap_skip(1, "backend sshd down");
		reap_pg(sshd_pid, 50);
		free(out);
		return;
	}

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
		free(out);
		return;
	}

	proxy_pid = proxy_spawn(e, pcfg, plog);
	if (proxy_pid <= 0 || wait_for_listen(pport, 5000) != 0) {
		file_dump(plog, "proxy.log");
		tap_skip(1, "proxy down");
		reap_pg(proxy_pid, 50);
		reap_pg(sshd_pid, 50);
		free(out);
		return;
	}

	/* stream REKEY_BYTES of 'a' back over the connection, then a sentinel */
	snprintf(cmd, sizeof(cmd),
		"dd if=/dev/zero bs=1024 count=%d 2>/dev/null | tr '\\0' a; echo END",
		REKEY_BYTES / 1024);
	out[0] = '\0';
	ssh_rekey_cmd(e, "root", pport, id, cmd, out, outsz);

	/* intact == exactly REKEY_BYTES of payload then "END\n", and the proxy log
	 * must prove a rekey actually happened on at least one leg.
	 */
	if (!tap_ok(strlen(out) == (size_t)REKEY_BYTES + 4 &&
	    strcmp(out + REKEY_BYTES, "END\n") == 0 &&
	    file_contains(plog, "(rekey)"),
	    "rekey: %d-byte transfer survives repeated rekeys via the proxy",
	    REKEY_BYTES)) {
		fprintf(stderr, "# got %zu bytes (want %d)\n", strlen(out),
			REKEY_BYTES + 4);
		file_dump(plog, "proxy.log");
		file_dump(slog, "sshd.log");
	}

	reap_pg(proxy_pid, 50);
	reap_pg(sshd_pid, 50);
	free(out);
}

/* test_interactive (2 tests): a full interactive pty session through the proxy.
 *
 * - same hostbased full-login setup as test_hostbased, plus a usable pty in
 *   the sandbox (ns_setup_pty)
 * - drives a real client pty (pty_fork) and types a command whose output
 *   (OK_42) differs from the typed text, so a match proves it ran on the backend
 */
static void test_interactive(const struct proxy_env *e)
{
	char tmp[256], home[PATH_MAX], sshdir[PATH_MAX + 8];
	char pcfg[PATH_MAX], plog[PATH_MAX], scfg[PATH_MAX], slog[PATH_MAX];
	char hostkey[PATH_MAX], id[PATH_MAX], authkeys[PATH_MAX + 4];
	char sshlog[PATH_MAX], stub[PATH_MAX + 32], portarg[16], reason[256];
	char buf[16384];
	int pport, bport, master, st, sent_cmd = 0, sent_exit = 0;
	size_t total = 0;
	struct timespec start;
	pid_t sshd_pid, proxy_pid, ssh_pid;

	resolve_sibling(e->tool.argv0, "setgroups_stub.so", stub, sizeof(stub));

	if (enter_userns() != 0) {
		snprintf(reason, sizeof(reason),
			"user namespaces unavailable (%s)", strerror(errno));
		tap_skip(2, reason);
		return;
	}
	if (make_tmpdir("ssh_proxy_interactive", tmp, sizeof(tmp)) != 0) {
		tap_skip(2, "no tmpdir");
		return;
	}
	snprintf(home, sizeof(home), "%s/home", tmp);
	snprintf(sshdir, sizeof(sshdir), "%s/.ssh", home);
	if (mkdir(home, 0755) < 0 || mkdir(sshdir, 0755) < 0) {
		tap_skip(2, "no sandbox home");
		return;
	}
	if (prep_hostbased_ns(tmp, home) != 0) {
		snprintf(reason, sizeof(reason),
			"namespace fs setup failed (%s)", strerror(errno));
		tap_skip(2, reason);
		return;
	}
	if (ns_setup_pty(tmp) != 0) {
		snprintf(reason, sizeof(reason),
			"sandbox pty unavailable (%s)", strerror(errno));
		tap_skip(2, reason);
		return;
	}

	snprintf(hostkey, sizeof(hostkey), "%s/hostkey", tmp);
	snprintf(id, sizeof(id), "%s/id", tmp);
	if (ssh_gen_key(&e->tool, hostkey) != 0 || ssh_gen_key(&e->tool, id) != 0) {
		tap_skip(2, "keygen failed");
		return;
	}
	snprintf(authkeys, sizeof(authkeys), "%s.pub", id);
	if (setup_hostbased_trust(home, sshdir, authkeys) != 0) {
		tap_skip(2, "hostbased trust setup failed");
		return;
	}

	snprintf(scfg, sizeof(scfg), "%s/sshd_config", tmp);
	snprintf(slog, sizeof(slog), "%s/sshd.log", tmp);
	snprintf(pcfg, sizeof(pcfg), "%s/sshproxy.conf", tmp);
	snprintf(plog, sizeof(plog), "%s/proxy.log", tmp);
	snprintf(sshlog, sizeof(sshlog), "%s/ssh.log", tmp);

	bport = pick_free_port();
	if (file_writef(scfg,
	    "Port %d\nListenAddress 127.0.0.1\nHostKey %s\nStrictModes no\n"
	    "LogLevel VERBOSE\nUsePAM no\nPrintMotd no\nPermitRootLogin yes\n"
	    "PasswordAuthentication no\nPubkeyAuthentication yes\n"
	    "HostbasedAuthentication yes\nHostbasedUsesNameFromPacketOnly yes\n"
	    "IgnoreRhosts no\nAuthorizedKeysFile %s\n",
	    bport, hostkey, authkeys) != 0) {
		tap_skip(2, "no sshd cfg");
		return;
	}

	setenv("LD_PRELOAD", stub, 1);
	sshd_pid = sshd_spawn(e, scfg, slog);
	unsetenv("LD_PRELOAD");
	if (!tap_ok(sshd_pid > 0 && wait_for_listen(bport, 5000) == 0,
	    "interactive: backend sshd up on 127.0.0.1:%d (uid 0 in ns)", bport)) {
		file_dump(slog, "sshd.log");
		tap_skip(1, "backend sshd down");
		reap_pg(sshd_pid, 50);
		return;
	}

	pport = pick_free_port();
	if (file_writef(pcfg,
	    "bindaddr = 127.0.0.1:%d\nhostkey = %s\nhostkey_auth = %s\n"
	    "switch_methods = fixed\ndefault_server = 127.0.0.1:%d\n",
	    pport, hostkey, id, bport) != 0) {
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

	snprintf(portarg, sizeof(portarg), "%d", pport);
	ssh_pid = pty_fork(&master);
	if (ssh_pid < 0) {
		tap_skip(1, "pty_fork failed");
		reap_pg(proxy_pid, 50);
		reap_pg(sshd_pid, 50);
		return;
	}
	if (ssh_pid == 0) {
		/* keep stdin/stdout on the pty (the interactive channel); send
		 * ssh's -vvv debug to a file so it stays off the pty
		 */
		int lf = open(sshlog, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		if (lf >= 0) {
			dup2(lf, 2);
			if (lf > 2) {
				close(lf);
			}
		}
		execl(e->tool.ssh, e->tool.ssh, "-tt",
			"-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "GlobalKnownHostsFile=/dev/null",
			"-o", "PreferredAuthentications=publickey",
			"-vvv", "-i", id, "-p", portarg, "root@127.0.0.1",
			(char *)NULL);
		_exit(127);
	}

	/* drive the session on a timeline while reading concurrently so no pty
	 * output is lost at teardown
	 */
	clock_gettime(CLOCK_MONOTONIC, &start);
	for (;;) {
		fd_set rf;
		struct timeval tv = { 1, 0 };
		struct timespec now;
		double el;
		ssize_t n;

		clock_gettime(CLOCK_MONOTONIC, &now);
		el = (now.tv_sec - start.tv_sec) +
		    (now.tv_nsec - start.tv_nsec) / 1e9;
		if (!sent_cmd && el >= 1.0) {
			dprintf(master, "echo OK_$((6*7))\n");
			sent_cmd = 1;
		}
		if (!sent_exit && el >= 3.0) {
			dprintf(master, "exit\n");
			sent_exit = 1;
		}
		if (el >= 5.0) {
			break;
		}
		FD_ZERO(&rf);
		FD_SET(master, &rf);
		if (select(master + 1, &rf, 0, 0, &tv) <= 0) {
			continue;
		}
		n = read(master, buf + total, sizeof(buf) - 1 - total);
		if (n <= 0) {
			break;
		}
		total += (size_t)n;
		if (total >= sizeof(buf) - 1) {
			break;
		}
	}
	buf[total] = '\0';
	close(master);
	waitpid(ssh_pid, &st, 0);

	if (!tap_ok(strstr(buf, "OK_42") != NULL &&
	    file_contains(slog, "Accepted hostbased for root"),
	    "interactive: pty session runs a command through the proxy")) {
		file_dump(slog, "sshd.log");
		file_dump(plog, "proxy.log");
		file_dump(sshlog, "ssh.log");
	}

	reap_pg(proxy_pid, 50);
	reap_pg(sshd_pid, 50);
}

int main(int argc, char **argv)
{
	struct proxy_env env;

	(void)argc;
	tap_plan(9);

	proxy_resolve_paths(&env, argv[0]);
	test_pubkey(&env);        /* observable steps (no namespace) */
	test_hostbased(&env);     /* full hostbased login (user namespace) */
	test_rekey(&env);         /* in-session rekeying (user namespace) */
	test_interactive(&env);   /* interactive pty session (user namespace) */

	return tap_done();
}
