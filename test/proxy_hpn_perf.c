/*
 * test/proxy_hpn_perf.c - HPN throughput benchmark through the sshproxy
 * (raw-TCP ceiling + plain ssh pipe, download and upload).
 *
 * The sshproxy itself is unmodified, so this measures what HPN-capable
 * endpoints gain across a stock relay. It first measures a raw-TCP transfer
 * over the link to record the reachable "link ceiling", then times a large
 * transfer through a freshly built sshproxy in front of a freshly built sshd
 * (unprivileged, no root) in two legs, reporting throughput, the speedup and
 * the in-flight window each reached (sampled with ss) as TAP diagnostics:
 *
 *   - hpn  HPN on the client and the backend sshd
 *   - off  HPN disabled on both - the fixed 2 MB (stock) window
 *
 * The ssh/sshd built here keep upstream's HPN default, which is on, so it is
 * the "off" leg that has to say so explicitly (HPNDisabled=yes).
 *
 * The pass/fail assertion covers integrity only (each transfer completed and the
 * byte counts match). Throughput is too host- and link-dependent to threshold.
 *
 * The path:
 *
 *   [client ns] ssh  veth-c <==netem==> veth-s  sshproxy -> sshd  [server ns]
 *
 * Only the client-to-proxy hop is shaped: the proxy is the WAN-facing endpoint
 * and the backend sits next to it. Proxy and backend both run in the server
 * namespace and talk over the server address, which is local there, so that leg
 * is delivered via lo and never crosses netem. The shaped hop is a veth pair
 * across two net namespaces.
 *
 * The proxy owns no channels: client and backend negotiate their windows
 * end-to-end straight through it, so nothing here is configured on the proxy.
 *
 * HPN_PERF_RTT_MS defaults to 200 here and HPN_PERF_MB to 512: a shorter
 * transfer at this RTT never leaves slow-start and both legs read the same.
 *
 * An asymmetry worth knowing when reading the upload line. The receiver's window
 * tracks the SO_RCVBUF of the receiver's *own* socket, and through a proxy the
 * two directions do not see the same socket:
 *   - download: the receiver is the client, whose socket is the shaped hop, so
 *     the window tracks the BDP that matters
 *   - upload: the receiver is the backend, whose socket is the local proxy-to-
 *     backend hop - it sizes its window from a loopback buffer that has nothing
 *     to do with the client's BDP. Uploads still gain over "off" (the
 *     stock 2 MB window binds either way), but the window they land on is
 *     incidental rather than matched to the path, and varies between runs.
 *
 * Reading the numbers. The first case is the raw-TCP link ceiling: the same
 * transfer size over the same link with no ssh and no disk, timed start to end
 * exactly as the ssh cases are, so every ssh line reads against what the path
 * itself can carry. A single ssh stream can run below it and still be healthy:
 * if its in-flight data stays under the BDP while the channel window is larger
 * and nothing drops, the transfer is application-limited (the single SSH
 * channel), not window- or network-limited. Both the ceiling and the ssh lines
 * rise with HPN_PERF_MB, because every transfer pays a fixed startup cost (key
 * exchange and auth for ssh, TCP slow-start for both) that a short transfer
 * cannot amortize.
 *
 * Authentication is the production shape: the client authenticates to the proxy
 * with a public key, and the proxy re-authenticates to the backend with
 * hostbased (see README.md). That needs ~/.shosts and ~/.ssh/known_hosts of the
 * login user, so the run binds a /etc/passwd giving it a sandbox home - the real
 * home is never written. The auth cost is a one-off per leg and amortizes away
 * in the transfer.
 *
 * Run 'make perf' (not in 'make test', skips on a stock, non-HPN tree). Env, all
 * optional:
 *   - HPN_PERF_MB        transfer size in MiB (default 512). Large enough to
 *                        reach steady state past slow-start, where the ratio is
 *                        stable. At 128 the default RTT keeps the whole run
 *                        inside the ramp and the ratio flattens.
 *   - HPN_PERF_RTT_MS    round-trip time (default 200, 0 = none). Split in half
 *                        and applied as one-way netem delay per endpoint.
 *   - HPN_PERF_RATE      per-endpoint rate cap in Mbit/s (default 1000, 0 = none)
 *   - HPN_PERF_RMEM_MB   TCP buffer autotuning ceiling in MiB, raised in the net
 *                        ns. Unset = auto ~2*BDP, floored at 64. 0 = kernel
 *                        default. HPN's window tracks SO_RCVBUF, capped by this.
 *   - HPN_PERF_CC        TCP congestion control, both ns (default unset). "bbr"
 *                        paces the sender so a ~2*BDP buffer does not bloat and
 *                        overshoot the way loss-based CUBIC does.
 *
 * BDP(MB) ~= HPN_PERF_RATE x HPN_PERF_RTT_MS / 8000.
 */
#define _GNU_SOURCE     /* perf_test.h needs setns/unshare/CLONE_* */
#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "tap.h"
#include "proxy_test.h"
#include "chroot_ns.h"
#include "perf_test.h"

#define NTESTS  (1 + 1 + 1)     /* link ceiling, download, upload */

/* the two legs, in report order */
enum leg { LEG_HPN, LEG_OFF, NLEGS };

static const char *leg_name[NLEGS] = { "hpn", "off" };

/* HPN on the peers (client + backend sshd) per leg */
static const int leg_peer_hpn[NLEGS] = { 1, 0 };

/* The veth link + identities (see perf_test.h): sshproxy and sshd are spawned
 * into the server ns, the ssh client runs in the client ns, and both servers
 * listen on g_net.srv_ip.
 */
static struct perf_net g_net = { .server_ns_fd = -1 };

/* set up once for the whole run and shared by every leg: the login user's
 * sandbox home, the hostkey the proxy and the backend both present, and the
 * key that is the client identity and the proxy's hostkey_auth.
 */
static char g_home[PATH_MAX];
static char g_hostkey[PATH_MAX];
static char g_id[PATH_MAX];
static char g_userat[256];

/* transfer size in MiB, from $HPN_PERF_MB (default 512, clamped 1..4096) */
static size_t perf_mb(void)
{
	const char *s = getenv("HPN_PERF_MB");
	long v = s ? atol(s) : 512;

	if (v < 1) {
		v = 1;
	}
	if (v > 4096) {
		v = 4096;
	}
	return (size_t)v;
}

/* round-trip time in ms, from $HPN_PERF_RTT_MS (default 200, so the ~25 MB BDP
 * is well past the stock 2 MB window - see the file header). Split in half as
 * one-way netem delay on each endpoint's egress.
 */
static int perf_rtt_ms(void)
{
	const char *s = getenv("HPN_PERF_RTT_MS");
	long v = s ? atol(s) : 200;

	if (v < 0) {
		v = 0;
	}
	if (v > 4000) {
		v = 4000;
	}
	return (int)v;
}

/* per-endpoint egress rate cap in Mbit/s, from $HPN_PERF_RATE (default 1000) */
static int perf_rate_mbit(void)
{
	const char *s = getenv("HPN_PERF_RATE");
	long v = s ? atol(s) : 1000;

	if (v < 0) {
		v = 0;
	}
	if (v > 100000) {
		v = 100000;
	}
	return (int)v;
}

/* TCP buffer autotuning ceiling in MiB, from $HPN_PERF_RMEM_MB. Unset = ~2*BDP
 * (the standard TCP buffer rule), floored at 64 and clamped to 4096.
 */
static int perf_rmem_mb(void)
{
	const char *s = getenv("HPN_PERF_RMEM_MB");
	long v;

	if (s != NULL) {
		v = atol(s);
	} else {
		int rate = perf_rate_mbit(), rtt = perf_rtt_ms();
		long bdp = (rate > 0 && rtt > 0) ? (long)rate * rtt / 8000 : 0;

		v = 2 * bdp;
		if (v < 64) {
			v = 64;
		}
	}
	if (v < 0) {
		v = 0;
	}
	if (v > 4096) {
		v = 4096;
	}
	return (int)v;
}

/* TCP congestion control for both namespaces, from $HPN_PERF_CC (NULL = kernel
 * default). "bbr" paces the sender and holds a small queue.
 */
static const char *perf_cc(void)
{
	const char *s = getenv("HPN_PERF_CC");

	return (s != NULL && *s != '\0') ? s : NULL;
}

/* create a mb-MiB file of non-trivial (incompressible-ish) bytes at path */
static int make_bigfile(const char *path, size_t mb)
{
	char buf[65536];
	size_t i, total = mb * 1024 * 1024, done = 0;
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);

	if (fd < 0) {
		return -1;
	}
	for (i = 0; i < sizeof(buf); i++) {
		buf[i] = (char)(i * 31 + 7);
	}
	while (done < total) {
		ssize_t w = write(fd, buf, sizeof(buf));

		if (w <= 0) {
			close(fd);
			return -1;
		}
		done += (size_t)w;
	}
	return close(fd);
}

static long long file_size(const char *path)
{
	struct stat st;

	return (stat(path, &st) == 0) ? (long long)st.st_size : -1;
}

/* Like perf_spawn_ns(), but with stdout/stderr on logpath instead of /dev/null -
 * the sshproxy logs its -e output there, which is the only diagnostic when a leg
 * fails (sshd takes a -E logfile of its own and does not need this).
 */
static pid_t perf_spawn_ns_log(const struct perf_net *pn, char *const argv[],
	const char *logpath)
{
	pid_t pid = fork();

	if (pid < 0) {
		return -1;
	}
	if (pid == 0) {
		int dn = open("/dev/null", O_RDONLY);
		int lf = open(logpath, O_WRONLY | O_CREAT | O_TRUNC, 0600);

		if (setns(pn->server_ns_fd, CLONE_NEWNET) != 0 ||
		    perf_userns_map(pn) != 0) {
			_exit(126);
		}
		setpgid(0, 0);
		if (dn >= 0) {
			dup2(dn, 0);
			if (dn > 2) {
				close(dn);
			}
		}
		if (lf >= 0) {
			dup2(lf, 1);
			dup2(lf, 2);
			if (lf > 2) {
				close(lf);
			}
		}
		execv(argv[0], argv);
		_exit(127);
	}
	return pid;
}

/* Give the login user a sandbox home, so the hostbased leg's ~/.shosts and
 * ~/.ssh/known_hosts never touch the real one: a mount ns (we are outer-root
 * after perf_veth_up, so CAP_SYS_ADMIN is held) with a /etc/passwd bound over
 * the real one. The login user keeps its own uid, so the backend sshd's setuid
 * stays the no-op it already is when running unprivileged. The sshd privsep
 * account has to resolve, so it is listed too. Returns 0 on success.
 */
static int perf_bind_passwd(const char *tmp, const char *user, const char *home)
{
	char body[2 * PATH_MAX + 256];

	if (unshare(CLONE_NEWNS) != 0) {
		return -1;
	}
	if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
		return -1;
	}
	snprintf(body, sizeof(body),
		"%s:x:%u:%u:%s:%s:/bin/sh\n"
		"sshd:x:%u:%u:sshd:/var/empty:/sbin/nologin\n",
		user, (unsigned)g_net.ruid, (unsigned)g_net.rgid, user, home,
		(unsigned)g_net.ruid, (unsigned)g_net.rgid);
	return ns_bind_passwd(tmp, body);
}

/* Bring up the backend sshd in the server ns, pubkey + hostbased only, with HPN
 * on or off. It listens on both loopback and g_net.srv_ip: the proxy dials
 * loopback (so its hostbased chost is "localhost", the name pinned by
 * setup_hostbased_trust), while perf_wait_listen probes the server address from
 * the client ns. Either way the leg is local to the server ns and never crosses
 * netem. Fills *port, returns the pid (or -1).
 */
static pid_t perf_sshd_up(const struct proxy_env *e, const char *tmp, int hpn,
	int *port)
{
	char cfg[PATH_MAX], log[PATH_MAX + 8];
	pid_t pid;

	snprintf(cfg, sizeof(cfg), "%s/sshd_config", tmp);
	snprintf(log, sizeof(log), "%s/sshd.log", tmp);
	*port = pick_free_port();
	if (file_writef(cfg,
	    "Port %d\n"
	    "ListenAddress 127.0.0.1\n"
	    "ListenAddress %s\n"
	    "HostKey %s\n"
	    "PidFile none\n"
	    "StrictModes no\n"
	    "%s\n"
	    "LogLevel ERROR\n"
	    "PrintMotd no\n"
	    "PasswordAuthentication no\n"
	    "PubkeyAuthentication yes\n"
	    "HostbasedAuthentication yes\n"
	    "HostbasedUsesNameFromPacketOnly yes\n"
	    "IgnoreRhosts no\n"
	    "PerSourcePenalties no\n"
	    "AuthorizedKeysFile %s.pub\n",
	    *port, g_net.srv_ip, g_hostkey,
	    hpn ? "HPNDisabled no" : "HPNDisabled yes", g_id) != 0) {
		return -1;
	}
	{
		char sessopt[PATH_MAX + 48], authopt[PATH_MAX + 48];
		char *a[] = { (char *)e->tool.sshd, "-D", "-f", cfg, "-E", log,
			"-o", sessopt, "-o", authopt, NULL };

		snprintf(sessopt, sizeof(sessopt), "SshdSessionPath=%s", e->tool.sshd_session);
		snprintf(authopt, sizeof(authopt), "SshdAuthPath=%s", e->tool.sshd_auth);
		pid = perf_spawn_ns(&g_net, a);
	}
	if (pid <= 0 || perf_wait_listen(g_net.srv_ip, *port, 5000) != 0) {
		file_dump(log, "sshd.log");
		return -1;
	}
	return pid;
}

/* Bring up the sshproxy in the server ns in front of the backend on bport.
 * Fills *port, returns the pid (or -1).
 */
static pid_t perf_proxy_up(const struct proxy_env *e, const char *tmp,
	int bport, int *port)
{
	char cfg[PATH_MAX], log[PATH_MAX + 8];
	pid_t pid;

	snprintf(cfg, sizeof(cfg), "%s/sshproxy.conf", tmp);
	snprintf(log, sizeof(log), "%s/proxy.log", tmp);
	*port = pick_free_port();
	if (file_writef(cfg,
	    "bindaddr = %s:%d\n"
	    "hostkey = %s\n"
	    "hostkey_auth = %s\n"
	    "switch_methods = fixed\n"
	    "default_server = 127.0.0.1:%d\n",
	    g_net.srv_ip, *port, g_hostkey, g_id, bport) != 0) {
		return -1;
	}
	{
		char *a[] = { (char *)e->sshproxy, "-d", "-e", "-c", cfg, NULL };

		pid = perf_spawn_ns_log(&g_net, a, log);
	}
	if (pid <= 0 || perf_wait_listen(g_net.srv_ip, *port, 5000) != 0) {
		file_dump(log, "proxy.log");
		return -1;
	}
	return pid;
}

/* the ssh client argv shared by both directions. peer_hpn says whether this leg
 * runs the client with HPN on. remote is the command to run on the backend.
 */
static int build_ssh_argv(const struct proxy_env *e, char **a, int peer_hpn,
	const char *portarg, const char *remote)
{
	int n = 0;

	a[n++] = (char *)e->tool.ssh; a[n++] = "-F"; a[n++] = "/dev/null";
	a[n++] = "-o"; a[n++] = peer_hpn ? "HPNDisabled=no" : "HPNDisabled=yes";
	a[n++] = "-o"; a[n++] = "TcpRcvBufPoll=yes";
	a[n++] = "-o"; a[n++] = "StrictHostKeyChecking=no";
	a[n++] = "-o"; a[n++] = "UserKnownHostsFile=/dev/null";
	a[n++] = "-o"; a[n++] = "GlobalKnownHostsFile=/dev/null";
	a[n++] = "-o"; a[n++] = "LogLevel=ERROR";
	a[n++] = "-o"; a[n++] = "BatchMode=yes";
	a[n++] = "-o"; a[n++] = "PreferredAuthentications=publickey";
	a[n++] = "-i"; a[n++] = g_id;
	a[n++] = "-p"; a[n++] = (char *)portarg;
	a[n++] = g_userat;
	a[n++] = (char *)remote;
	a[n] = NULL;
	return n;
}

/* Time one leg: bring up a backend sshd and a proxy in this leg's modes, run the
 * transfer through the proxy, sample the window on the shaped hop, verify the
 * byte count, store throughput via *mibps.
 *
 * download: `ssh host cat src` > dst - the client is the receiver, the proxy is
 * the sender on the shaped hop, so sample the server ns. upload: `ssh host wc -c`
 * with src on stdin - the client is the sender, so sample here.
 *
 * Returns 0, -1 on transfer failure, -2 if a server did not come up.
 */
static int measure_leg(const struct proxy_env *e, const char *tmp, enum leg lg,
	int download, const char *src, const char *dst, size_t mb,
	struct winpeak *wp, double *mibps)
{
	char portarg[16], serr[PATH_MAX + 16], sspath[PATH_MAX + 16];
	char remote[PATH_MAX + 8], out[4096];
	int bport = 0, pport = 0, rc;
	pid_t sshd_pid, proxy_pid, sampler;
	double t0, dt;
	char *a[40];

	memset(wp, 0, sizeof(*wp));
	snprintf(serr, sizeof(serr), "%s/ssh.stderr.%s", tmp, leg_name[lg]);
	snprintf(sspath, sizeof(sspath), "%s/ss.%s", tmp, leg_name[lg]);

	sshd_pid = perf_sshd_up(e, tmp, leg_peer_hpn[lg], &bport);
	if (sshd_pid < 0) {
		return -2;
	}
	proxy_pid = perf_proxy_up(e, tmp, bport, &pport);
	if (proxy_pid < 0) {
		reap_pg(sshd_pid, 50);
		return -2;
	}
	snprintf(portarg, sizeof(portarg), "%d", pport);
	if (download) {
		snprintf(remote, sizeof(remote), "cat %s", src);
	} else {
		snprintf(remote, sizeof(remote), "wc -c");
	}
	build_ssh_argv(e, a, leg_peer_hpn[lg], portarg, remote);

	if (download && strcmp(dst, "/dev/null") != 0) {
		(void)truncate(dst, 0);
	}
	/* sample the client-to-proxy connection - the only shaped hop - on
	 * whichever side is sending it, where cwnd/inflight are meaningful
	 */
	sampler = perf_win_sampler_start(portarg, sspath,
		download ? g_net.server_ns_fd : -1);
	t0 = perf_mono_now();
	if (download) {
		rc = perf_run_mapped(&g_net, a, NULL, dst, NULL, 0, serr);
	} else {
		rc = perf_run_mapped(&g_net, a, src, NULL, out, sizeof(out), serr);
	}
	dt = perf_mono_now() - t0;
	if (sampler > 0) {
		kill(sampler, SIGKILL);
		waitpid(sampler, NULL, 0);
	}
	perf_winpeak_parse(sspath, wp);
	reap_pg(proxy_pid, 50);
	reap_pg(sshd_pid, 50);

	if (download) {
		/* a /dev/null sink has no size to check, so verify on the exit code */
		if (rc != 0 || (strcmp(dst, "/dev/null") != 0 &&
		    file_size(dst) != (long long)mb * 1024 * 1024)) {
			fprintf(stderr, "# %s: rc=%d size=%lld want=%lld\n", leg_name[lg],
				rc, file_size(dst), (long long)mb * 1024 * 1024);
			file_dump(serr, "ssh.stderr");
			return -1;
		}
	} else {
		long long got = atoll(out);     /* wc -c echoes the byte count */

		if (rc != 0 || got != (long long)mb * 1024 * 1024) {
			fprintf(stderr, "# %s: rc=%d got=%lld want=%lld out='%s'\n",
				leg_name[lg], rc, got, (long long)mb * 1024 * 1024, out);
			file_dump(serr, "ssh.stderr");
			return -1;
		}
	}
	*mibps = (dt > 0.0) ? (double)mb / dt : 0.0;
	return 0;
}

/* One direction, both legs, as a single line: what HPN buys end-to-end through
 * the proxy. The inflt figures are the sender's peak unacked bytes on the
 * shaped hop - the window each leg reached.
 */
static void run_cmp(const struct proxy_env *e, const char *tag, const char *label,
	int download)
{
	const double M = 1024.0 * 1024.0;
	char tmp[256], src[PATH_MAX], dst[PATH_MAX];
	size_t mb = perf_mb();
	double t[NLEGS] = { 0.0, 0.0 };
	struct winpeak wp[NLEGS];
	int i;

	if (make_tmpdir(tag, tmp, sizeof(tmp)) != 0) {
		tap_skip(1, "no tmpdir");
		return;
	}
	snprintf(src, sizeof(src), "%s/src", tmp);
	snprintf(dst, sizeof(dst), "%s/got", tmp);
	if (make_bigfile(src, mb) != 0) {
		tap_skip(1, "no source file");
		return;
	}
	for (i = 0; i < NLEGS; i++) {
		if (measure_leg(e, tmp, (enum leg)i, download, src, dst, mb,
		    &wp[i], &t[i]) == -2) {
			tap_skip(1, "proxy or backend sshd did not come up");
			return;
		}
	}
	if (tap_ok(t[LEG_HPN] > 0.0 && t[LEG_OFF] > 0.0,
	    "hpn perf: %s through the proxy, %zu MiB", label, mb)) {
		fprintf(stderr, "# %-8s: hpn %5.1f | off %5.1f MiB/s   hpn/off %5.2fx   "
			"inflt %.0f / %.0f MB   retrans %ld / %ld\n",
			label, t[LEG_HPN], t[LEG_OFF],
			t[LEG_OFF] > 0.0 ? t[LEG_HPN] / t[LEG_OFF] : 0.0,
			wp[LEG_HPN].inflight / M, wp[LEG_OFF].inflight / M,
			wp[LEG_HPN].retrans, wp[LEG_OFF].retrans);
		if (!download) {
			/* see the file header: the backend sizes its window from
			 * the local hop, so this line wanders between runs
			 */
			fprintf(stderr, "#         : upload window is set by the local "
				"proxy-to-backend socket, not the shaped hop\n");
		}
	}
}

/* Raw-TCP link ceiling: what the shaped hop carries with no ssh and no proxy -
 * the reachable throughput every leg is measured against.
 */
static void run_link_ceiling(double *up, double *down, int rate_mbit)
{
	size_t mb = perf_mb();
	int ok_up = (perf_tcp_bench(&g_net, mb, 0, up) == 0);
	int ok_down = (perf_tcp_bench(&g_net, mb, 1, down) == 0);

	if (tap_ok(ok_up && ok_down, "raw TCP link ceiling %zu MiB", mb)) {
		if (rate_mbit > 0) {
			double cap = rate_mbit * 125000.0 / 1048576.0;  /* Mbit/s -> MiB/s */

			fprintf(stderr, "# %-8s: up %5.1f  down %5.1f MiB/s  (%.0f%%/%.0f%% of "
				"%dmbit cap; raw TCP, same size, start to end)\n",
				"ceiling", *up, *down, 100.0 * *up / cap, 100.0 * *down / cap,
				rate_mbit);
		} else {
			fprintf(stderr, "# %-8s: up %5.1f  down %5.1f MiB/s  (raw TCP, same "
				"size, start to end)\n", "ceiling", *up, *down);
		}
	}
}

/* HPN build present iff sshd accepts the HPNDisabled keyword (config test) */
static int hpn_build(const struct proxy_env *e)
{
	char tmp[256], cfg[PATH_MAX], hostkey[PATH_MAX];
	char *a[5];

	if (make_tmpdir("proxy_hpn_perf_probe", tmp, sizeof(tmp)) != 0) {
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

/* The keys and the sandbox home every leg shares: one hostkey presented by both
 * the proxy and the backend (a client must not see a different key through the
 * proxy, see README.md), and one key that is at once the client identity, the
 * backend's authorized key and the proxy's hostkey_auth for the hostbased leg.
 * Returns 0 on success.
 */
static int perf_setup_auth(const struct proxy_env *e, const char *tmp,
	const char *user)
{
	char sshdir[PATH_MAX + 8], authkeys[PATH_MAX + 4];

	snprintf(g_home, sizeof(g_home), "%s/home", tmp);
	snprintf(sshdir, sizeof(sshdir), "%s/.ssh", g_home);
	if (mkdir(g_home, 0755) < 0 || mkdir(sshdir, 0755) < 0) {
		return -1;
	}
	snprintf(g_hostkey, sizeof(g_hostkey), "%s/hostkey", tmp);
	snprintf(g_id, sizeof(g_id), "%s/id", tmp);
	if (ssh_gen_key(&e->tool, g_hostkey) != 0 || ssh_gen_key(&e->tool, g_id) != 0) {
		return -1;
	}
	snprintf(authkeys, sizeof(authkeys), "%s.pub", g_id);
	if (setup_hostbased_trust(g_home, sshdir, authkeys) != 0) {
		return -1;
	}
	snprintf(g_userat, sizeof(g_userat), "%s@%s", user, g_net.srv_ip);
	return perf_bind_passwd(tmp, user, g_home);
}

int main(int argc, char **argv)
{
	struct proxy_env env;
	struct passwd *pw;
	char user[64], tmp[256];
	double ceil_up = 0.0, ceil_down = 0.0;
	int rtt, delay, rate, rmem, rmem_ok = 0, cc_ok = 0;
	long bdp;
	const char *cc;

	(void)argc;
	g_net.ruid = getuid();
	g_net.rgid = getgid();
	pw = getpwuid(g_net.ruid);
	snprintf(user, sizeof(user), "%s", pw ? pw->pw_name : "nobody");

	tap_plan(NTESTS);
	proxy_resolve_paths(&env, argv[0]);
	ssh_enable_legacy_rsa_sha1();

	/* opt-in build, skip cleanly without --with-hpn */
	if (!hpn_build(&env)) {
		fprintf(stderr, "# sshd does not accept HPNDisabled; not an HPN build\n");
		tap_skip(NTESTS, "not an HPN build");
		return tap_done();
	}

	rtt = perf_rtt_ms();
	delay = rtt / 2;                /* per-endpoint netem delay, halves sum to rtt */
	rate = perf_rate_mbit();
	rmem = perf_rmem_mb();
	cc = perf_cc();
	bdp = (rate > 0 && rtt > 0) ? (long)rate * rtt / 8000 : 0;

	fprintf(stderr, "# env: HPN_PERF_MB=%zu HPN_PERF_RTT_MS=%d HPN_PERF_RATE=%d "
		"HPN_PERF_RMEM_MB=%d%s HPN_PERF_CC=%s\n",
		perf_mb(), rtt, rate, rmem,
		getenv("HPN_PERF_RMEM_MB") ? "" : " (auto ~2*BDP)",
		cc ? cc : "(default)");

	if (perf_veth_up(&g_net, delay, rate, rmem, cc, &rmem_ok, &cc_ok) != 0) {
		fprintf(stderr, "# could not build veth link (need iproute2 + user/net "
			"namespaces)\n");
		tap_skip(NTESTS, "veth setup failed");
		return tap_done();
	}
	fprintf(stderr, "# link: veth pair (2 net ns) + netem");
	if (rtt > 0) {
		fprintf(stderr, " RTT %dms (delay %dms/endpoint)", rtt, delay);
	}
	if (rate > 0) {
		fprintf(stderr, " rate %dmbit", rate);
	}
	if (rmem > 0) {
		if (rmem_ok) {
			fprintf(stderr, " rmem/wmem max %dMB", rmem);
		} else {
			fprintf(stderr, " (rmem/wmem NOT raised - /proc/sys read-only; "
				"HPN gain will be capped)");
		}
	}
	if (cc != NULL) {
		if (cc_ok) {
			fprintf(stderr, " cc %s", cc);
		} else {
			fprintf(stderr, " (cc %s NOT applied - /proc/sys read-only, or not "
				"loaded on the host)", cc);
		}
	}
	fprintf(stderr, "\n# path: ssh -> [veth+netem] -> sshproxy -> sshd "
		"(proxy and backend both in the server ns, over lo)\n");
	if (bdp > 0) {
		fprintf(stderr, "# BDP: ~%ldMB (%dmbit x %dms RTT) in flight required to "
			"saturate the link\n", bdp, rate, rtt);
		if (rmem > 0 && rmem < bdp) {
			fprintf(stderr, "# WARNING: HPN_PERF_RMEM_MB=%d < BDP ~%ldMB - raise "
				"it toward the BDP, else\n#          HPN's window can't fill the "
				"pipe and may collapse below no-HPN\n", rmem, bdp);
		}
	}

	run_link_ceiling(&ceil_up, &ceil_down, rate);
	if (ceil_up <= 0.0 || ceil_down <= 0.0) {
		fprintf(stderr, "# WARNING: link ceiling did not complete - the numbers "
			"below may be unreliable\n");
	}

	/* the keys, the sandbox home and the /etc/passwd bind are set up once and
	 * shared by every leg (see perf_setup_auth)
	 */
	if (make_tmpdir("proxy_hpn_perf", tmp, sizeof(tmp)) != 0 ||
	    perf_setup_auth(&env, tmp, user) != 0) {
		fprintf(stderr, "# auth/sandbox setup failed (%s)\n", strerror(errno));
		tap_skip(2, "auth setup failed");
		return tap_done();
	}

	run_cmp(&env, "proxy_hpn_perf_dl", "download", 1);
	run_cmp(&env, "proxy_hpn_perf_ul", "upload", 0);

	return tap_done();
}
