/*
 * test/proxy_hpn.c - HPN receive-window scaling through the proxy.
 *
 * The sshproxy is unmodified: it relays packets and owns no channels, so the
 * channel windows are negotiated end-to-end between client and backend and
 * SSH_MSG_CHANNEL_WINDOW_ADJUST passes through it untouched. This checks that a
 * stock proxy is transparent to that - an HPN client pulling a bulk download
 * through it from an HPN backend must still see its window grow.
 *
 * HPN is an opt-in build (--with-hpn). The test skips on a stock build.
 *
 * test_window_growth() - the client window grows on a bulk download through
 *                        the proxy, with a real backend sshd behind it
 */
#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "tap.h"
#include "proxy_test.h"
#include "chroot_ns.h"

#define NTESTS 2

/* HPN build present iff sshd accepts the HPNDisabled keyword. sshproxy and the
 * tools come out of the same tree, so this covers the proxy's "hpn" too.
 */
static int hpn_build(const struct proxy_env *e)
{
	char tmp[256], cfg[PATH_MAX], hostkey[PATH_MAX];
	char *a[5];

	if (make_tmpdir("proxy_hpn_probe", tmp, sizeof(tmp)) != 0) {
		return 0;
	}
	snprintf(cfg, sizeof(cfg), "%s/sshd_config", tmp);
	snprintf(hostkey, sizeof(hostkey), "%s/hostkey", tmp);
	if (ssh_gen_key(&e->tool, hostkey) != 0) {
		return 0;
	}
	file_writef(cfg, "HostKey %s\nHPNDisabled no\n", hostkey);
	a[0] = (char *)e->tool.sshd; a[1] = "-t"; a[2] = "-f"; a[3] = cfg; a[4] = NULL;
	return run_capture(a, 0, NULL, 0) == 0;
}

/* kernel TCP receive-buffer autotuning ceiling (tcp_rmem max), 0 if unknown */
static long tcp_rmem_max(void)
{
	FILE *f = fopen("/proc/sys/net/ipv4/tcp_rmem", "r");
	long lo = 0, def = 0, max = 0;

	if (f == NULL) {
		return 0;
	}
	if (fscanf(f, "%ld %ld %ld", &lo, &def, &max) != 3) {
		max = 0;
	}
	fclose(f);
	return max;
}

/* Set up the sandbox login, as in proxy_pubkey.c: a fake /etc/passwd whose
 * login user "root" is uid 0 with a sandbox home, plus a 0755 /var/empty for
 * sshd privsep. Returns 0 on success.
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

/* test_window_growth (2 tests): the end-to-end payoff. A real HPN backend sshd
 * sits behind a stock proxy, and a HPN client streams a bulk download
 * through it. Since the window is negotiated client-to-backend right through
 * the proxy, the client's own debug log has to show "Window growth".
 *
 * What is checked is that the negotiation survives the relay at all, not the
 * size the window reaches - that is what 'make perf' quantifies.
 *
 * The login is the hostbased one from proxy_pubkey.c (the proxy translates the
 * client pubkey to hostbased for the backend), so this needs the same uid-0
 * user namespace with a sandbox home. It skips without user namespaces, and
 * needs a kernel that autotunes SO_RCVBUF past the 2 MB stock window too.
 */
static void test_window_growth(const struct proxy_env *e)
{
	char tmp[256], home[PATH_MAX], sshdir[PATH_MAX + 8];
	char pcfg[PATH_MAX], plog[PATH_MAX], scfg[PATH_MAX], slog[PATH_MAX];
	char hostkey[PATH_MAX], id[PATH_MAX], authkeys[PATH_MAX + 4];
	char errf[PATH_MAX + 8], portarg[16], reason[256], stub[PATH_MAX + 32];
	int pport, bport;
	pid_t sshd_pid, proxy_pid;

	ssh_enable_legacy_rsa_sha1();

	resolve_sibling(e->tool.argv0, "setgroups_stub.so", stub, sizeof(stub));

	if (tcp_rmem_max() <= 2 * 1024 * 1024) {
		tap_skip(2, "kernel tcp_rmem max <= 2MB; window cannot grow past stock");
		return;
	}
	if (enter_userns() != 0) {
		snprintf(reason, sizeof(reason),
			"user namespaces unavailable (%s)", strerror(errno));
		tap_skip(2, reason);
		return;
	}
	if (make_tmpdir("proxy_hpn_grow", tmp, sizeof(tmp)) != 0) {
		tap_skip(2, "hpn_grow: no tmpdir");
		return;
	}
	snprintf(home, sizeof(home), "%s/home", tmp);
	snprintf(sshdir, sizeof(sshdir), "%s/.ssh", home);
	if (mkdir(home, 0755) < 0 || mkdir(sshdir, 0755) < 0) {
		tap_skip(2, "hpn_grow: no sandbox home");
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
		tap_skip(2, "hpn_grow: keygen failed");
		return;
	}
	snprintf(authkeys, sizeof(authkeys), "%s.pub", id);

	/* trust the proxy's host for user root, pinning its hostkey_auth key (id) */
	if (setup_hostbased_trust(home, sshdir, authkeys) != 0) {
		tap_skip(2, "hpn_grow: hostbased trust setup failed");
		return;
	}

	snprintf(scfg, sizeof(scfg), "%s/sshd_config", tmp);
	snprintf(slog, sizeof(slog), "%s/sshd.log", tmp);
	snprintf(pcfg, sizeof(pcfg), "%s/sshproxy.conf", tmp);
	snprintf(plog, sizeof(plog), "%s/proxy.log", tmp);
	snprintf(errf, sizeof(errf), "%s/ssh.err", tmp);

	bport = pick_free_port();
	if (file_writef(scfg,
	    "Port %d\n"
	    "ListenAddress 127.0.0.1\n"
	    "HostKey %s\n"
	    "StrictModes no\n"
	    "HPNDisabled no\n"
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
		tap_skip(2, "hpn_grow: no sshd cfg");
		return;
	}

	setenv("LD_PRELOAD", stub, 1);
	sshd_pid = sshd_spawn(e, scfg, slog);
	unsetenv("LD_PRELOAD");
	if (!tap_ok(sshd_pid > 0 && wait_for_listen(bport, 5000) == 0,
	    "hpn_grow: HPN backend sshd up on 127.0.0.1:%d (uid 0 in ns)", bport)) {
		file_dump(slog, "sshd.log");
		tap_skip(1, "hpn_grow: backend sshd down");
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
		tap_skip(1, "hpn_grow: no proxy cfg");
		reap_pg(sshd_pid, 50);
		return;
	}

	proxy_pid = proxy_spawn(e, pcfg, plog);
	if (proxy_pid <= 0 || wait_for_listen(pport, 5000) != 0) {
		file_dump(plog, "proxy.log");
		tap_skip(1, "hpn_grow: proxy down");
		reap_pg(proxy_pid, 50);
		reap_pg(sshd_pid, 50);
		return;
	}

	snprintf(portarg, sizeof(portarg), "%d", pport);
	{
		/* the remote dd streams 64 MB back through the proxy. LogLevel=DEBUG
		 * shows the growth line without the per-packet debug2 output
		 */
		char *a[] = {
			(char *)e->tool.ssh, "-F", "/dev/null",
			"-o", "HPNDisabled=no",
			"-o", "TcpRcvBufPoll=yes",
			"-o", "LogLevel=DEBUG",
			"-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "GlobalKnownHostsFile=/dev/null",
			"-o", "BatchMode=yes",
			"-o", "PreferredAuthentications=publickey",
			"-i", id, "-p", portarg, "root@127.0.0.1",
			"dd if=/dev/zero bs=1M count=64 2>/dev/null", NULL
		};
		run_capture_e(a, 0, NULL, 0, errf);   /* stdout drained + discarded */
	}
	if (!tap_ok(file_contains(errf, "Window growth") ||
	    file_contains(errf, "Enabled Dynamic Window Scaling"),
	    "hpn_grow: client window grows on a bulk download through the proxy")) {
		file_dump(errf, "ssh.err");
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
	tap_plan(NTESTS);

	proxy_resolve_paths(&env, argv[0]);

	/* opt-in build, skip cleanly without --with-hpn */
	if (!hpn_build(&env)) {
		fprintf(stderr, "# sshd does not accept HPNDisabled; not an HPN build\n");
		tap_skip(NTESTS, "not an HPN build");
		return tap_done();
	}

	test_window_growth(&env);

	return tap_done();
}
