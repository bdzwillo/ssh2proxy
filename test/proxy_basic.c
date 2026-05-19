/*
 * test/proxy_basic.c - pre-auth proxy behavior.
 *
 * Unprivileged TAP integration tests for the freshly-built sshproxy. Each
 * test_*() runs a real proxy on a loopback high port and probes it with the
 * build-tree ssh tools.
 *
 *   test_hostkey()      - proxy comes up and presents its configured hostkey
 *   test_hostkey_rsa()  - RSA hostkey: only rsa-sha2, pre-7.2 client rejected
 *   test_hostkey_rsa_legacy() - legacy_rsa_hostkey re-enables ssh-rsa
 *   test_switch()       - the "fixed" switch routes a client by username
 *   test_badconf()      - a bad config makes the proxy exit instead of serving
 */
#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "tap.h"
#include "proxy_test.h"

/* read the whitespace-separated field N (1-based) of the first line of path. */
static int read_field(const char *path, int n, char *buf, size_t bufsz)
{
	char line[8192];
	FILE *f = fopen(path, "r");
	char *tok;
	int i = 0;

	buf[0] = '\0';
	if (f == NULL) {
		return -1;
	}
	/* skip ssh-keyscan's leading "# host banner" comment lines (stdout
	 * since OpenSSH 9.8) and any blank lines to reach the key line.
	 */
	do {
		if (fgets(line, sizeof(line), f) == NULL) {
			fclose(f);
			return -1;
		}
	} while (line[0] == '#' || line[0] == '\n' || line[0] == '\r');
	fclose(f);
	for (tok = strtok(line, " \t\r\n"); tok != NULL; tok = strtok(NULL, " \t\r\n")) {
		if (++i == n) {
			snprintf(buf, bufsz, "%s", tok);
			return 0;
		}
	}
	return -1;
}

/* test_hostkey (2 tests): the proxy comes up and presents the configured
 * hostkey to a client. ssh-keyscan does a key exchange with the proxy (step 1
 * of the proxy protocol, before any backend is involved) and prints the offered
 * hostkey, which must equal the key from the config file.
 */
static void test_hostkey(const struct proxy_env *e)
{
	char tmp[256], cfg[PATH_MAX], log[PATH_MAX], hostkey[PATH_MAX];
	char pubfile[PATH_MAX + 4], scanfile[PATH_MAX];
	char cfgkey[8192], scankey[8192], portarg[16];
	int port;
	pid_t proxy_pid;

	if (make_tmpdir("proxy_hostkey", tmp, sizeof(tmp)) != 0 ||
	    ssh_gen_key(&e->tool, hostkey_path(tmp, hostkey, sizeof(hostkey))) != 0) {
		tap_skip(2, "hostkey: setup failed (tmpdir + keygen)");
		return;
	}
	snprintf(cfg, sizeof(cfg), "%s/sshproxy.conf", tmp);
	snprintf(log, sizeof(log), "%s/proxy.log", tmp);
	snprintf(scanfile, sizeof(scanfile), "%s/scan.out", tmp);
	snprintf(pubfile, sizeof(pubfile), "%s.pub", hostkey);

	port = pick_free_port();
	if (file_writef(cfg,
	    "bindaddr = 127.0.0.1:%d\n"
	    "hostkey = %s\n"
	    "switch_methods = fixed\n"
	    "default_server = 127.0.0.1:1\n",
	    port, hostkey) != 0) {
		tap_skip(2, "hostkey: write config failed");
		return;
	}

	proxy_pid = proxy_spawn(e, cfg, log);
	if (!tap_ok(proxy_pid > 0 && wait_for_listen(port, 5000) == 0,
	    "hostkey: sshproxy up on 127.0.0.1:%d", port)) {
		file_dump(log, "proxy.log");
		tap_ok(0, "hostkey: proxy presents the configured hostkey");
		reap_pg(proxy_pid, 50);
		return;
	}

	snprintf(portarg, sizeof(portarg), "%d", port);
	{
		char *scanargv[] = {
			(char *)e->tool.keyscan, "-t", "ed25519", "-p", portarg,
			"127.0.0.1", NULL
		};
		char out[8192];
		run_capture(scanargv, 0, out, sizeof(out));
		file_write_str(scanfile, out);
	}
	/* keyscan line: "[127.0.0.1]:port ssh-ed25519 <blob>" -> field 3;
	 * the .pub line: "ssh-ed25519 <blob> comment"         -> field 2.
	 */
	if (read_field(scanfile, 3, scankey, sizeof(scankey)) != 0 ||
	    read_field(pubfile, 2, cfgkey, sizeof(cfgkey)) != 0) {
		scankey[0] = cfgkey[0] = '\0';
	}
	if (!tap_ok(scankey[0] != '\0' && strcmp(scankey, cfgkey) == 0,
	    "hostkey: proxy presents the configured hostkey")) {
		fprintf(stderr, "# scan='%s'\n# cfg ='%s'\n", scankey, cfgkey);
		file_dump(log, "proxy.log");
	}
	reap_pg(proxy_pid, 50);
}

/* test_hostkey_rsa (2 tests): the proxy serves an RSA hostkey, offering only
 * rsa-sha2 for it (upstream's default since 8.8).
 *
 * - a modern client negotiates the hostkey via rsa-sha2
 * - a pre-OpenSSH-7.2 client (only ssh-rsa for host keys) is rejected
 */
static void test_hostkey_rsa(const struct proxy_env *e)
{
	char tmp[256], cfg[PATH_MAX], log[PATH_MAX], hostkey[PATH_MAX];
	char pubfile[PATH_MAX + 4], scanfile[PATH_MAX], errfile[PATH_MAX];
	char cfgkey[8192], scankey[8192], portarg[16], out[8192];
	int port;
	pid_t proxy_pid;

	if (make_tmpdir("proxy_hostkey_rsa", tmp, sizeof(tmp)) != 0 ||
	    ssh_gen_key_type(&e->tool,
		hostkey_path(tmp, hostkey, sizeof(hostkey)), "rsa", 2048) != 0) {
		tap_skip(2, "hostkey_rsa: setup failed (tmpdir + keygen)");
		return;
	}
	snprintf(cfg, sizeof(cfg), "%s/sshproxy.conf", tmp);
	snprintf(log, sizeof(log), "%s/proxy.log", tmp);
	snprintf(scanfile, sizeof(scanfile), "%s/scan.out", tmp);
	snprintf(errfile, sizeof(errfile), "%s/ssh.err", tmp);
	snprintf(pubfile, sizeof(pubfile), "%s.pub", hostkey);

	port = pick_free_port();
	if (file_writef(cfg,
	    "bindaddr = 127.0.0.1:%d\n"
	    "hostkey = %s\n"
	    "switch_methods = fixed\n"
	    "default_server = 127.0.0.1:1\n",
	    port, hostkey) != 0) {
		tap_skip(2, "hostkey_rsa: write config failed");
		return;
	}

	proxy_pid = proxy_spawn(e, cfg, log);
	if (proxy_pid <= 0 || wait_for_listen(port, 5000) != 0) {
		file_dump(log, "proxy.log");
		tap_skip(2, "hostkey_rsa: proxy down");
		reap_pg(proxy_pid, 50);
		return;
	}

	snprintf(portarg, sizeof(portarg), "%d", port);

	/* a modern client (rsa-sha2 host-key algs) fetches the RSA hostkey */
	{
		char *scanargv[] = {
			(char *)e->tool.keyscan, "-t", "rsa", "-p", portarg,
			"127.0.0.1", NULL
		};
		run_capture(scanargv, 0, out, sizeof(out));
		file_write_str(scanfile, out);
	}
	if (read_field(scanfile, 3, scankey, sizeof(scankey)) != 0 ||
	    read_field(pubfile, 2, cfgkey, sizeof(cfgkey)) != 0) {
		scankey[0] = cfgkey[0] = '\0';
	}
	if (!tap_ok(scankey[0] != '\0' && strcmp(scankey, cfgkey) == 0,
	    "hostkey_rsa: modern client negotiates the RSA hostkey via rsa-sha2")) {
		fprintf(stderr, "# scan='%s'\n# cfg ='%s'\n", scankey, cfgkey);
		file_dump(log, "proxy.log");
	}

	/* a pre-7.2 client (only ssh-rsa for host keys) cannot: the proxy offers
	 * only rsa-sha2 for the RSA key, so host-key negotiation fails outright
	 */
	{
		char *oldargv[] = {
			(char *)e->tool.ssh, "-F", "/dev/null",
			"-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "GlobalKnownHostsFile=/dev/null",
			"-o", "BatchMode=yes",
			"-o", "ConnectTimeout=5",
			"-o", "HostKeyAlgorithms=ssh-rsa",
			"-o", "PreferredAuthentications=publickey",
			"-p", portarg, "old@127.0.0.1", "true", NULL
		};
		run_capture_e(oldargv, 0, out, sizeof(out), errfile);
	}
	if (!tap_ok(file_contains(errfile, "no matching host key type"),
	    "hostkey_rsa: pre-7.2 ssh-rsa-only client is rejected")) {
		file_dump(errfile, "ssh.err");
	}

	reap_pg(proxy_pid, 50);
}

/* test_hostkey_rsa_legacy (1 test): with legacy_rsa_hostkey set, the proxy adds
 * ssh-rsa to its RSA host-key algorithms (the opposite of test_hostkey_rsa).
 *
 * - a pre-OpenSSH-7.2 client (only ssh-rsa for host keys) verifies the hostkey
 *   and gets past key exchange
 */
static void test_hostkey_rsa_legacy(const struct proxy_env *e)
{
	char tmp[256], cfg[PATH_MAX], log[PATH_MAX], hostkey[PATH_MAX];
	char errfile[PATH_MAX], portarg[16], out[8192];
	int port;
	pid_t proxy_pid;

	ssh_enable_legacy_rsa_sha1();

	if (make_tmpdir("proxy_hostkey_rsa_legacy", tmp, sizeof(tmp)) != 0 ||
	    ssh_gen_key_type(&e->tool,
		hostkey_path(tmp, hostkey, sizeof(hostkey)), "rsa", 2048) != 0) {
		tap_skip(1, "hostkey_rsa_legacy: setup failed (tmpdir + keygen)");
		return;
	}
	snprintf(cfg, sizeof(cfg), "%s/sshproxy.conf", tmp);
	snprintf(log, sizeof(log), "%s/proxy.log", tmp);
	snprintf(errfile, sizeof(errfile), "%s/ssh.err", tmp);

	port = pick_free_port();
	if (file_writef(cfg,
	    "bindaddr = 127.0.0.1:%d\n"
	    "hostkey = %s\n"
	    "switch_methods = fixed\n"
	    "default_server = 127.0.0.1:1\n"
	    "legacy_rsa_hostkey = 1\n",
	    port, hostkey) != 0) {
		tap_skip(1, "hostkey_rsa_legacy: write config failed");
		return;
	}

	proxy_pid = proxy_spawn(e, cfg, log);
	if (proxy_pid <= 0 || wait_for_listen(port, 5000) != 0) {
		file_dump(log, "proxy.log");
		tap_skip(1, "hostkey_rsa_legacy: proxy down");
		reap_pg(proxy_pid, 50);
		return;
	}

	snprintf(portarg, sizeof(portarg), "%d", port);
	{
		char *oldargv[] = {
			(char *)e->tool.ssh, "-vvv", "-F", "/dev/null",
			"-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "GlobalKnownHostsFile=/dev/null",
			"-o", "BatchMode=yes",
			"-o", "ConnectTimeout=5",
			"-o", "HostKeyAlgorithms=ssh-rsa",
			"-o", "PreferredAuthentications=publickey",
			"-p", portarg, "old@127.0.0.1", "true", NULL
		};
		run_capture_e(oldargv, 0, out, sizeof(out), errfile);
	}
	if (!tap_ok(file_contains(errfile, "Server host key: ssh-rsa") &&
	    !file_contains(errfile, "no matching host key type"),
	    "hostkey_rsa_legacy: legacy_rsa_hostkey lets an ssh-rsa-only client in")) {
		file_dump(errfile, "ssh.err");
	}

	reap_pg(proxy_pid, 50);
}

/* test_switch (3 tests): the "fixed" switch routes a client to the right
 * backend by username. The proxy picks a backend and dials it as soon as the
 * client sends its first userauth request (carrying the username), before auth
 * completes - so a login that never succeeds still proves the routing. Two
 * plain listening sockets stand in for the backends:
 *
 *   default_server      -> backend D (any non-matching user)
 *   switch_target alice -> backend A
 *
 * Connects as "alice" (expect A, not D) and as "bob" (expect D, not A).
 */
static void test_switch(const struct proxy_env *e)
{
	char tmp[256], cfg[PATH_MAX], log[PATH_MAX], hostkey[PATH_MAX];
	int port, port_a, port_d, fd_a, fd_d;
	int hit_a, hit_d;
	pid_t proxy_pid;

	if (make_tmpdir("proxy_switch", tmp, sizeof(tmp)) != 0 ||
	    ssh_gen_key(&e->tool, hostkey_path(tmp, hostkey, sizeof(hostkey))) != 0) {
		tap_skip(3, "switch: setup failed");
		return;
	}
	snprintf(cfg, sizeof(cfg), "%s/sshproxy.conf", tmp);
	snprintf(log, sizeof(log), "%s/proxy.log", tmp);

	port = pick_free_port();
	port_a = pick_free_port();
	port_d = pick_free_port();
	fd_a = backend_listener(port_a);
	fd_d = backend_listener(port_d);
	if (fd_a < 0 || fd_d < 0) {
		tap_skip(3, "switch: backend_listener failed");
		return;
	}

	if (file_writef(cfg,
	    "bindaddr = 127.0.0.1:%d\n"
	    "hostkey = %s\n"
	    "switch_methods = fixed\n"
	    "default_server = 127.0.0.1:%d\n"
	    "switch_target = alice 127.0.0.1:%d\n",
	    port, hostkey, port_d, port_a) != 0) {
		tap_skip(3, "switch: write config failed");
		return;
	}

	proxy_pid = proxy_spawn(e, cfg, log);
	if (!tap_ok(proxy_pid > 0 && wait_for_listen(port, 5000) == 0,
	    "switch: sshproxy up on 127.0.0.1:%d", port)) {
		file_dump(log, "proxy.log");
		tap_ok(0, "switch: user 'alice' routed to switch_target backend");
		tap_ok(0, "switch: user 'bob' routed to default_server backend");
		close(fd_a);
		close(fd_d);
		reap_pg(proxy_pid, 50);
		return;
	}

	/* alice -> switch_target backend A */
	{
		pid_t ca = backend_accept_fork(fd_a, 5000);
		pid_t cd = backend_accept_fork(fd_d, 5000);
		ssh_pubkey_poke(e, "alice", port);
		hit_a = backend_hit(ca);
		hit_d = backend_hit(cd);
	}
	if (!tap_ok(hit_a && !hit_d,
	    "switch: user 'alice' routed to switch_target backend")) {
		fprintf(stderr, "# hit_a=%d hit_d=%d\n", hit_a, hit_d);
		file_dump(log, "proxy.log");
	}

	/* bob -> default_server backend D */
	{
		pid_t ca = backend_accept_fork(fd_a, 5000);
		pid_t cd = backend_accept_fork(fd_d, 5000);
		ssh_pubkey_poke(e, "bob", port);
		hit_d = backend_hit(cd);
		hit_a = backend_hit(ca);
	}
	if (!tap_ok(hit_d && !hit_a,
	    "switch: user 'bob' routed to default_server backend")) {
		fprintf(stderr, "# hit_a=%d hit_d=%d\n", hit_a, hit_d);
		file_dump(log, "proxy.log");
	}

	close(fd_a);
	close(fd_d);
	reap_pg(proxy_pid, 50);
}

/* test_badconf (2 tests): the proxy rejects a bad configuration instead of
 * coming up. An unknown switch_methods value makes main() fatal() during
 * startup; the process must exit non-zero and say why in its log.
 */
static void test_badconf(const struct proxy_env *e)
{
	char tmp[256], cfg[PATH_MAX], log[PATH_MAX], hostkey[PATH_MAX];
	int port, code;
	pid_t proxy_pid;

	if (make_tmpdir("proxy_badconf", tmp, sizeof(tmp)) != 0 ||
	    ssh_gen_key(&e->tool, hostkey_path(tmp, hostkey, sizeof(hostkey))) != 0) {
		tap_skip(2, "badconf: setup failed");
		return;
	}
	snprintf(cfg, sizeof(cfg), "%s/sshproxy.conf", tmp);
	snprintf(log, sizeof(log), "%s/proxy.log", tmp);

	port = pick_free_port();
	if (file_writef(cfg,
	    "bindaddr = 127.0.0.1:%d\n"
	    "hostkey = %s\n"
	    "switch_methods = bogus_method\n"
	    "default_server = 127.0.0.1:1\n",
	    port, hostkey) != 0) {
		tap_skip(2, "badconf: write config failed");
		return;
	}

	proxy_pid = proxy_spawn(e, cfg, log);
	if (proxy_pid <= 0) {
		tap_skip(2, "badconf: proxy_spawn failed");
		return;
	}
	code = wait_exit(proxy_pid, 5000);
	if (!tap_ok(code > 0, "badconf: proxy exits non-zero on bad switch method")) {
		fprintf(stderr, "# exit code=%d (expected >0)\n", code);
		file_dump(log, "proxy.log");
	}
	if (!tap_ok(file_contains(log, "bad switch method"),
	    "badconf: log explains the bad switch method")) {
		file_dump(log, "proxy.log");
	}
}

int main(int argc, char **argv)
{
	struct proxy_env env;

	(void)argc;
	tap_plan(10);

	proxy_resolve_paths(&env, argv[0]);

	test_hostkey(&env);
	test_hostkey_rsa(&env);
	test_hostkey_rsa_legacy(&env);
	test_switch(&env);
	test_badconf(&env);

	return tap_done();
}
