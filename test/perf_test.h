/*
 * test/perf_test.h - network throughput test helpers: a netem-shaped veth pair
 * across two net namespaces, independent of the server/client programs.
 *
 *   perf_veth_up()            build the netem-shaped veth pair (2 net ns)
 *   perf_spawn_ns()           spawn a server into the server ns (invoking uid)
 *   perf_run_mapped()         run a client in the client ns (invoking uid)
 *   perf_wait_listen()        wait for the server to accept on the veth address
 *   perf_win_sampler_start()  background `ss` sampler of the data connection
 *   perf_winpeak_parse()      reduce the `ss` samples to peak window metrics
 *   perf_mono_now()           monotonic seconds, for transfer timing
 *   perf_tcp_bench()          raw-TCP link ceiling over the veth (no ssh/disk)
 *
 * Topology (perf_veth_up):
 *
 *   [client ns] client  veth-c 10.0.0.1 <==netem==> veth-s 10.0.0.2  server [server ns]
 *
 * Why a veth pair and not loopback:
 *   - a veth pair between two namespaces is a real forwarding path, so TCP
 *     ACK-clocks and cwnd fills the bandwidth-delay product - a larger window
 *     turns into throughput
 *   - netem on lo does not stream at window/RTT (TCP cannot fill the pipe), so
 *     throughput floors far below the window and its effect cannot be measured
 *
 * Usage:
 *   - unprivileged (user + net namespaces), needs iproute2 (ip/tc)
 *   - the includer must define _GNU_SOURCE before its first include (setns/
 *     unshare/CLONE_*) and record the invoking uid/gid in the perf_net before
 *     unsharing
 */
#ifndef TEST_PERF_TEST_H
#define TEST_PERF_TEST_H

#include <sched.h>
#include <time.h>

#include "util.h"

#define PERF_VETH_CLI_IP  "10.0.0.1"
#define PERF_VETH_SRV_IP  "10.0.0.2"
#define PERF_NETEM_LIMIT  "100000"      /* netem backlog (packets), past any BDP,
					 * else drops cap throughput below the
					 * window */

/* The veth link + identities threaded through the perf helpers. Fill ruid/rgid
 * before unsharing. perf_veth_up() fills server_ns_fd and defaults cli_ip/srv_ip
 * (to PERF_VETH_*_IP) when left NULL.
 */
struct perf_net {
	uid_t ruid;             /* real uid/gid, captured before unshare */
	gid_t rgid;
	int server_ns_fd;       /* server net ns - keeps it alive, setns target */
	const char *cli_ip;     /* addresses on the veth /24 */
	const char *srv_ip;
};

/* peak window metrics sampled during a transfer (bytes), from `ss -tinm` on
 * the data connection:
 *   - rcvbuf   max SO_RCVBUF (skmem rb) - what autotune grew the buffer to
 *   - sndbuf   max SO_SNDBUF (skmem tb)
 *   - inflight max unacked*mss - a fixed app window caps this, a scaled one
 *              lets it grow toward the BDP
 *   - cwndb    max cwnd*mss
 *   - retrans  cumulative retransmits (ss retrans:cur/total) on the sampled
 *              (sender) socket - evidence of a window overshooting the BDP
 */
struct winpeak {
	long rcvbuf;
	long sndbuf;
	long inflight;
	long cwndb;
	long retrans;
};

/* first executable candidate (absolute paths preferred - iproute2's ip/tc live
 * in /usr/sbin, which may not be on a non-login PATH), else the bare name.
 */
static inline const char *perf_tool_path(const char *const *cands)
{
	int i;

	for (i = 0; cands[i] != NULL; i++) {
		if (access(cands[i], X_OK) == 0) {
			return cands[i];
		}
	}
	return cands[0];
}

/* run argv to completion with output discarded, returns the exit code (or -1) */
static inline int perf_run_quiet(char *const argv[])
{
	return run_capture(argv, 0, NULL, 0);
}

/* Raise the TCP buffer ceiling (tcp_rmem/tcp_wmem max) to mb MiB so SO_RCVBUF
 * can autotune toward the BDP and a scaled window has room to grow. Returns 1 if
 * the ceiling is confirmed >= mb after the write, else 0.
 *   - these sysctls are net-namespaced: called while root in the private ns,
 *     the host is untouched
 *   - /proc/sys is often a read-only locked mount (containers), where the write
 *     is silently refused, so read tcp_rmem back rather than trust the write.
 *     A 0 return is non-fatal - the run falls back to the stock ceiling.
 */
static inline int perf_set_tcp_buf(int mb)
{
	char buf[64];
	long lo, def, max = 0, want = (long)mb * 1024 * 1024;
	FILE *f;

	if (mb <= 0) {
		return 0;
	}
	snprintf(buf, sizeof(buf), "4096 131072 %ld\n", want);
	(void)file_write_str("/proc/sys/net/ipv4/tcp_rmem", buf);
	snprintf(buf, sizeof(buf), "4096 16384 %ld\n", want);
	(void)file_write_str("/proc/sys/net/ipv4/tcp_wmem", buf);

	f = fopen("/proc/sys/net/ipv4/tcp_rmem", "r");
	if (f == NULL) {
		return 0;
	}
	if (fscanf(f, "%ld %ld %ld", &lo, &def, &max) != 3) {
		max = 0;
	}
	fclose(f);
	return max >= want;
}

/* Set the net-ns default TCP congestion control (net.ipv4.tcp_congestion_control,
 * net-namespaced) to cc - e.g. "bbr", which paces the sender and holds a near-
 * zero queue, so a 2*BDP buffer no longer bloats and overshoots the way loss-
 * based CUBIC does. NULL/empty leaves the kernel default. Returns 1 when unset
 * (nothing to do) or the value read back matches cc, else 0 (module
 * missing, or /proc/sys read-only). A 0 is non-fatal, like perf_set_tcp_buf.
 */
static inline int perf_set_cc(const char *cc)
{
	char buf[64];
	FILE *f;
	size_t n = 0;

	if (cc == NULL || *cc == '\0') {
		return 1;
	}
	if (file_write_str("/proc/sys/net/ipv4/tcp_congestion_control", cc) != 0) {
		return 0;
	}
	f = fopen("/proc/sys/net/ipv4/tcp_congestion_control", "r");
	if (f == NULL) {
		return 0;
	}
	n = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);
	buf[n] = '\0';
	buf[strcspn(buf, " \t\r\n")] = '\0';
	return strcmp(buf, cc) == 0;
}

/* Nest a further user ns that maps the invoking uid back (outer root 0 appears
 * as pn->ruid inside). Call in a freshly forked child
 * that is still outer-root, holding CAP_SETUID/SETGID, so no setgroups=deny is
 * needed. The child then runs as the invoking uid again (a server needs a
 * non-root uid - a root-mapped sshd would demand a privsep account).
 * Returns 0 on success.
 */
static inline int perf_userns_map(const struct perf_net *pn)
{
	char buf[64];

	if (unshare(CLONE_NEWUSER) != 0) {
		return -1;
	}
	snprintf(buf, sizeof(buf), "%u 0 1\n", (unsigned)pn->rgid);
	if (file_write_str("/proc/self/gid_map", buf) != 0) {
		return -1;
	}
	snprintf(buf, sizeof(buf), "%u 0 1\n", (unsigned)pn->ruid);
	if (file_write_str("/proc/self/uid_map", buf) != 0) {
		return -1;
	}
	return 0;
}

/* Configure one veth endpoint (as outer-root, in the current net ns):
 * address, link up, lo up, the TCP buffer ceiling, and a netem qdisc for the
 * per-egress delay/rate (each direction crosses one endpoint's netem, so the
 * RTT is ~2*ms). *rmem_ok reports the ceiling, *cc_ok whether cc was applied.
 *
 * The cap is netem's own 'rate', not a HTB (hierarchical token bucket) shaper:
 * over this veth pair a single raw-TCP flow reaches ~95% of line rate from 1 to
 * 8 gbit (iperf3), and an fq leaf collapses it. cc="bbr" needs no fq leaf
 * either, BBR paces itself.
 */
static inline int perf_cfg_endpoint(const char *ip, const char *tc,
	const char *dev, const char *addr, int ms, int rate, int rmem_mb,
	const char *cc, int *rmem_ok, int *cc_ok)
{
	char cidr[32], delay[32], ratebuf[32];
	char *qd[20];
	int n = 0;
	char *a_addr[] = { (char *)ip, "addr", "add", cidr, "dev", (char *)dev, NULL };
	char *a_up[] = { (char *)ip, "link", "set", (char *)dev, "up", NULL };
	char *a_lo[] = { (char *)ip, "link", "set", "lo", "up", NULL };

	snprintf(cidr, sizeof(cidr), "%s/24", addr);
	if (perf_run_quiet(a_addr) != 0 || perf_run_quiet(a_up) != 0 ||
	    perf_run_quiet(a_lo) != 0) {
		return -1;
	}
	*rmem_ok = perf_set_tcp_buf(rmem_mb);
	*cc_ok = perf_set_cc(cc);
	if (ms <= 0 && rate <= 0) {
		return 0;                       /* unshaped veth: leave default qdisc */
	}
	qd[n++] = (char *)tc;
	qd[n++] = "qdisc"; qd[n++] = "add"; qd[n++] = "dev"; qd[n++] = (char *)dev;
	qd[n++] = "root"; qd[n++] = "netem";
	if (ms > 0) {
		snprintf(delay, sizeof(delay), "%dms", ms);
		qd[n++] = "delay"; qd[n++] = delay;
	}
	if (rate > 0) {
		snprintf(ratebuf, sizeof(ratebuf), "%dmbit", rate);
		qd[n++] = "rate"; qd[n++] = ratebuf;
	}
	qd[n++] = "limit"; qd[n++] = PERF_NETEM_LIMIT;
	qd[n] = NULL;
	return perf_run_quiet(qd);
}

/* Build the veth pair across two net namespaces (topology above). Unprivileged,
 * yet the transfer still runs as the invoking uid:
 *   1. user ns mapping self -> 0 (outer root, holds CAP_NET_ADMIN/SYS_ADMIN)
 *   2. a net ns = CLIENT, a forked holder unshares a second = SERVER (both owned
 *      by outer, the holder's pid names SERVER for `ip link set netns`)
 *   3. veth-c/veth-s pair, move veth-s into SERVER, configure each end's addr +
 *      netem as outer-root (entering SERVER via setns to configure veth-s)
 * Notes:
 *   - the process stays outer-root in CLIENT - pn->server_ns_fd keeps SERVER
 *     alive and lets perf_spawn_ns() setns into it
 *   - server and client drop to the invoking uid per spawn via perf_userns_map()
 *   - pn->ruid/rgid must be set, cli_ip/srv_ip are defaulted if NULL
 *   - cc (e.g. "bbr", NULL = kernel default) sets the congestion control in
 *     both namespaces. *rmem_ok / *cc_ok report whether each was applied
 * Returns 0 on success, -1 otherwise.
 */
static inline int perf_veth_up(struct perf_net *pn, int ms, int rate,
	int rmem_mb, const char *cc, int *rmem_ok, int *cc_ok)
{
	static const char *ip_cands[] = { "/usr/sbin/ip", "/sbin/ip", "ip", NULL };
	static const char *tc_cands[] = { "/usr/sbin/tc", "/sbin/tc", "tc", NULL };
	const char *ip = perf_tool_path(ip_cands);
	const char *tc = perf_tool_path(tc_cands);
	char buf[64], nspid[32], nspath[64];
	int client_fd = -1, server_fd = -1, rc_c = 0, rc_s = 0, sync[2];
	int cc_c = 0, cc_s = 0;
	pid_t holder = -1;
	char *veth_add[] = { (char *)ip, "link", "add", "veth-c", "type", "veth",
		"peer", "name", "veth-s", NULL };
	char *veth_move[] = { (char *)ip, "link", "set", "veth-s", "netns", nspid, NULL };

	if (pn->cli_ip == NULL) {
		pn->cli_ip = PERF_VETH_CLI_IP;
	}
	if (pn->srv_ip == NULL) {
		pn->srv_ip = PERF_VETH_SRV_IP;
	}
	/* 1. become outer-root (map self -> 0) */
	if (unshare(CLONE_NEWUSER) != 0) {
		return -1;
	}
	if (file_write_str("/proc/self/setgroups", "deny") != 0) {
		return -1;
	}
	snprintf(buf, sizeof(buf), "0 %u 1\n", (unsigned)pn->rgid);
	if (file_write_str("/proc/self/gid_map", buf) != 0) {
		return -1;
	}
	snprintf(buf, sizeof(buf), "0 %u 1\n", (unsigned)pn->ruid);
	if (file_write_str("/proc/self/uid_map", buf) != 0) {
		return -1;
	}
	/* 2. CLIENT net ns (this process) + a holder child holding SERVER */
	if (unshare(CLONE_NEWNET) != 0) {
		return -1;
	}
	client_fd = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
	if (client_fd < 0 || pipe(sync) != 0) {
		return -1;
	}
	holder = fork();
	if (holder < 0) {
		return -1;
	}
	if (holder == 0) {
		char c = 1;
		close(sync[0]);
		if (unshare(CLONE_NEWNET) != 0) {
			_exit(1);
		}
		if (write(sync[1], &c, 1) != 1) {       /* signal SERVER is created */
			_exit(1);
		}
		pause();                                /* hold SERVER until killed */
		_exit(0);
	}
	close(sync[1]);
	if (read(sync[0], buf, 1) != 1) {           /* wait for the unshare */
		close(sync[0]);
		goto fail;
	}
	close(sync[0]);
	snprintf(nspid, sizeof(nspid), "%d", (int)holder);
	snprintf(nspath, sizeof(nspath), "/proc/%d/ns/net", (int)holder);
	server_fd = open(nspath, O_RDONLY | O_CLOEXEC);
	if (server_fd < 0) {
		goto fail;
	}
	/* 3. veth pair, move the server end into SERVER, configure both ends */
	if (perf_run_quiet(veth_add) != 0 || perf_run_quiet(veth_move) != 0) {
		goto fail;
	}
	if (perf_cfg_endpoint(ip, tc, "veth-c", pn->cli_ip, ms, rate, rmem_mb, cc, &rc_c, &cc_c) != 0) {
		goto fail;
	}
	if (setns(server_fd, CLONE_NEWNET) != 0) {
		goto fail;
	}
	if (perf_cfg_endpoint(ip, tc, "veth-s", pn->srv_ip, ms, rate, rmem_mb, cc, &rc_s, &cc_s) != 0) {
		(void)setns(client_fd, CLONE_NEWNET);       /* best-effort restore */
		goto fail;
	}
	if (setns(client_fd, CLONE_NEWNET) != 0) {
		goto fail;
	}
	*rmem_ok = rc_c && rc_s;
	*cc_ok = cc_c && cc_s;
	pn->server_ns_fd = server_fd;           /* keeps SERVER alive after holder dies */
	close(client_fd);
	kill(holder, SIGKILL);
	waitpid(holder, NULL, 0);
	return 0;
fail:
	if (holder > 0) {
		kill(holder, SIGKILL);
		waitpid(holder, NULL, 0);
	}
	if (client_fd >= 0) {
		close(client_fd);
	}
	if (server_fd >= 0) {
		close(server_fd);
	}
	return -1;
}

/* Spawn a server (argv, argv[0] the binary) into the server net ns: the child
 * setns into it and drops to the invoking uid before exec, with its own pgrp and
 * stdio to /dev/null. Returns the pid, or -1.
 */
static inline pid_t perf_spawn_ns(const struct perf_net *pn, char *const argv[])
{
	pid_t pid = fork();

	if (pid < 0) {
		return -1;
	}
	if (pid == 0) {
		int dn = open("/dev/null", O_RDWR);

		if (setns(pn->server_ns_fd, CLONE_NEWNET) != 0 ||
		    perf_userns_map(pn) != 0) {
			_exit(126);
		}
		setpgid(0, 0);
		if (dn >= 0) {
			dup2(dn, 0);
			dup2(dn, 1);
			dup2(dn, 2);
			if (dn > 2) {
				close(dn);
			}
		}
		execv(argv[0], argv);
		_exit(127);
	}
	return pid;
}

/* Like run_capture_e but the child drops to the invoking uid (perf_userns_map)
 * before exec, for the client side. stdin <- inpath (NULL = /dev/null). stdout
 * -> outpath if set (for a large binary stream, e.g. a download), else captured
 * into out. stderr -> errpath. Returns the exit code, or -1.
 */
static inline int perf_run_mapped(const struct perf_net *pn, char *const argv[],
	const char *inpath, const char *outpath, char *out, size_t outsz,
	const char *errpath)
{
	int pfd[2], st;
	pid_t pid;
	size_t total = 0;

	if (out != NULL && outsz > 0) {
		out[0] = '\0';
	}
	if (pipe(pfd) < 0) {
		return -1;
	}
	pid = fork();
	if (pid < 0) {
		close(pfd[0]);
		close(pfd[1]);
		return -1;
	}
	if (pid == 0) {
		int dn = open("/dev/null", O_RDWR);
		int ifd = (inpath != NULL) ? open(inpath, O_RDONLY) : -1;
		int ofd = (outpath != NULL) ?
			open(outpath, O_WRONLY | O_CREAT | O_TRUNC, 0644) : -1;
		int efd = (errpath != NULL) ?
			open(errpath, O_WRONLY | O_CREAT | O_TRUNC, 0600) : -1;
		if (perf_userns_map(pn) != 0) {
			_exit(126);
		}
		close(pfd[0]);
		if (ifd >= 0) {
			dup2(ifd, 0);
		} else if (dn >= 0) {
			dup2(dn, 0);
		}
		if (ofd >= 0) {
			dup2(ofd, 1);
		} else {
			dup2(pfd[1], 1);
		}
		if (efd >= 0) {
			dup2(efd, 2);
		} else if (dn >= 0) {
			dup2(dn, 2);
		}
		close(pfd[1]);
		if (ifd > 2) {
			close(ifd);
		}
		if (ofd > 2) {
			close(ofd);
		}
		if (efd > 2) {
			close(efd);
		}
		if (dn > 2) {
			close(dn);
		}
		execv(argv[0], argv);
		_exit(127);
	}
	close(pfd[1]);
	for (;;) {
		char rb[1024];
		ssize_t r = read(pfd[0], rb, sizeof(rb));

		if (r <= 0) {
			break;
		}
		if (out != NULL && total + (size_t)r < outsz) {
			memcpy(out + total, rb, r);
			total += (size_t)r;
			out[total] = '\0';
		}
	}
	close(pfd[0]);
	if (waitpid(pid, &st, 0) < 0) {
		return -1;
	}
	return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

/* wait up to timeout_ms for a connect to addr:port. Returns 0 once accepted,
 * -1 on timeout.
 */
static inline int perf_wait_listen(const char *addr, int port, int timeout_ms)
{
	int waited = 0;

	while (waited < timeout_ms) {
		int fd = socket(AF_INET, SOCK_STREAM, 0);
		struct sockaddr_in a;

		memset(&a, 0, sizeof(a));
		a.sin_family = AF_INET;
		a.sin_port = htons(port);
		inet_pton(AF_INET, addr, &a.sin_addr);
		if (fd >= 0 && connect(fd, (struct sockaddr *)&a, sizeof(a)) == 0) {
			close(fd);
			return 0;
		}
		if (fd >= 0) {
			close(fd);
		}
		usleep(50000);
		waited += 50;
	}
	return -1;
}

/* monotonic seconds as a double, for wall-clock timing */
static inline double perf_mono_now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* Receive total bytes on fd, timed start to end (slow-start included). Returns
 * MiB/s, or 0 on a short read. The receiver is timed because send() returns once
 * data enters the socket buffer, which over-reports.
 */
static inline double perf_recv_rate(int fd, char *buf, size_t bufsz, size_t total)
{
	size_t done = 0;
	double t0 = perf_mono_now(), dt;

	while (done < total) {
		ssize_t n = recv(fd, buf, bufsz, 0);

		if (n <= 0) {
			break;
		}
		done += (size_t)n;
	}
	dt = perf_mono_now() - t0;
	if (done >= total && dt > 0.0) {
		return (double)total / (1024.0 * 1024.0) / dt;
	}
	return 0.0;
}

/* send total bytes from buf on fd (untimed), 0 on success, -1 on error */
static inline int perf_send_all(int fd, const char *buf, size_t bufsz, size_t total)
{
	size_t done = 0;

	while (done < total) {
		ssize_t n = send(fd, buf, bufsz, MSG_NOSIGNAL);

		if (n <= 0) {
			return -1;
		}
		done += (size_t)n;
	}
	return 0;
}

/* Raw-TCP throughput over the veth link: a plain in-memory stream (no ssh, no
 * disk) that measures what the path itself can carry, so the ssh numbers can be
 * read against a measured ceiling. A forked server binds in the server ns, the
 * parent (client ns) is the client. The sender streams mb MiB from a static
 * buffer in one direction (download: server->client, else client->server), and
 * *mibps gets the rate. For an upload the server times the receive and reports
 * it back over the sync pipe. Returns 0 on success, -1 otherwise.
 */
static inline int perf_tcp_bench(const struct perf_net *pn, size_t mb,
	int download, double *mibps)
{
	static char buf[262144];
	size_t total = mb * 1024 * 1024;
	int port = pick_free_port();
	int sync[2], cfd = -1, i;
	struct sockaddr_in sa;
	pid_t srv;
	char c;

	*mibps = 0.0;
	if (pipe(sync) != 0) {
		return -1;
	}
	srv = fork();
	if (srv < 0) {
		close(sync[0]);
		close(sync[1]);
		return -1;
	}
	if (srv == 0) {                         /* server, in the server ns */
		int ls, cs, one = 1;

		close(sync[0]);
		if (setns(pn->server_ns_fd, CLONE_NEWNET) != 0) {
			_exit(1);
		}
		ls = socket(AF_INET, SOCK_STREAM, 0);
		if (ls < 0) {
			_exit(1);
		}
		setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
		memset(&sa, 0, sizeof(sa));
		sa.sin_family = AF_INET;
		sa.sin_port = htons(port);
		inet_pton(AF_INET, pn->srv_ip, &sa.sin_addr);
		if (bind(ls, (struct sockaddr *)&sa, sizeof(sa)) != 0 || listen(ls, 1) != 0) {
			_exit(1);
		}
		c = 1;
		if (write(sync[1], &c, 1) != 1) {       /* signal: listening */
			_exit(1);
		}
		cs = accept(ls, NULL, NULL);
		if (cs >= 0) {
			if (download) {
				perf_send_all(cs, buf, sizeof(buf), total);
			} else {
				double r = perf_recv_rate(cs, buf, sizeof(buf), total);
				(void)write(sync[1], &r, sizeof(r));    /* report receiver rate */
			}
		}
		_exit(0);
	}
	close(sync[1]);
	if (read(sync[0], &c, 1) != 1) {                /* wait for listen */
		goto reap;
	}
	cfd = socket(AF_INET, SOCK_STREAM, 0);
	if (cfd < 0) {
		goto reap;
	}
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	inet_pton(AF_INET, pn->srv_ip, &sa.sin_addr);
	for (i = 0; i < 100; i++) {                     /* connect, retry the race */
		if (connect(cfd, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
			break;
		}
		usleep(20000);
	}
	if (download) {
		*mibps = perf_recv_rate(cfd, buf, sizeof(buf), total);
	} else if (perf_send_all(cfd, buf, sizeof(buf), total) == 0) {
		double r = 0.0;                         /* the server timed the receive */

		if (read(sync[0], &r, sizeof(r)) == (ssize_t)sizeof(r)) {
			*mibps = r;
		}
	}
reap:
	close(sync[0]);
	if (cfd >= 0) {
		close(cfd);
	}
	kill(srv, SIGKILL);
	waitpid(srv, NULL, 0);
	return (*mibps > 0.0) ? 0 : -1;
}

/* Fork a background sampler that appends `ss -tinm` snapshots of the data
 * connection (filtered to port, both directions) to outpath every ~80ms, until
 * killed. Returns the sampler pid (or -1). With ss missing the exec fails per
 * tick and the file stays empty, which perf_winpeak_parse handles.
 *
 * ns_fd selects which net ns to sample: -1 = the current (client) ns, else
 * setns into it (the server ns) - so the sampler watches the sender's socket
 * (client for an upload, server for a download), where cwnd/inflight and the
 * delivery rate are meaningful.
 */
static inline pid_t perf_win_sampler_start(const char *port, const char *outpath,
	int ns_fd)
{
	static const char *ss_cands[] = { "/usr/sbin/ss", "/sbin/ss", "ss", NULL };
	const char *ss = perf_tool_path(ss_cands);
	char sp[32], dp[32];
	pid_t pid;

	(void)truncate(outpath, 0);
	pid = fork();
	if (pid != 0) {
		return pid;                     /* parent (or fork error: -1) */
	}
	if (ns_fd >= 0) {
		(void)setns(ns_fd, CLONE_NEWNET);       /* sample the server ns */
	}
	snprintf(sp, sizeof(sp), ":%s", port);
	snprintf(dp, sizeof(dp), ":%s", port);
	for (;;) {
		int fd = open(outpath, O_WRONLY | O_APPEND | O_CREAT, 0644);
		pid_t c = fork();

		if (c == 0) {
			int dn = open("/dev/null", O_WRONLY);
			char *a[] = { (char *)ss, "-tinm", "state", "established",
				"(", "sport", "=", sp, "or", "dport", "=", dp, ")", NULL };
			if (fd >= 0) {
				dup2(fd, 1);
			}
			if (dn >= 0) {
				dup2(dn, 2);
			}
			execv(a[0], a);
			_exit(127);
		}
		if (fd >= 0) {
			close(fd);
		}
		if (c > 0) {
			waitpid(c, NULL, 0);
		}
		usleep(80000);
	}
}

/* Scan the accumulated `ss` snapshots for the peak of each window metric. Reads
 * at most the first 1 MiB of samples. ss emits each socket as
 * whitespace-separated tokens. skmem is one token
 * (skmem:(r0,rb131072,t0,tb2626560,...)), mss precedes cwnd/unacked within a
 * socket's block, so tracking the last-seen mss pairs them correctly.
 */
static inline void perf_winpeak_parse(const char *path, struct winpeak *wp)
{
	static char buf[1 << 20];
	int fd = open(path, O_RDONLY);
	ssize_t n, tot = 0;
	long mss = 0, v;
	char *tok, *q;

	memset(wp, 0, sizeof(*wp));
	if (fd < 0) {
		return;
	}
	while (tot < (ssize_t)sizeof(buf) - 1 &&
	    (n = read(fd, buf + tot, sizeof(buf) - 1 - tot)) > 0) {
		tot += n;
	}
	close(fd);
	buf[tot] = '\0';
	for (tok = strtok(buf, " \t\r\n"); tok != NULL; tok = strtok(NULL, " \t\r\n")) {
		if (sscanf(tok, "mss:%ld", &v) == 1) {
			mss = v;
		} else if (strncmp(tok, "skmem:", 6) == 0) {
			if ((q = strstr(tok, "rb")) && sscanf(q, "rb%ld", &v) == 1 &&
			    v > wp->rcvbuf) {
				wp->rcvbuf = v;
			}
			if ((q = strstr(tok, "tb")) && sscanf(q, "tb%ld", &v) == 1 &&
			    v > wp->sndbuf) {
				wp->sndbuf = v;
			}
		} else if (sscanf(tok, "cwnd:%ld", &v) == 1) {
			long b = v * (mss > 0 ? mss : 1448);
			if (b > wp->cwndb) {
				wp->cwndb = b;
			}
		} else if (sscanf(tok, "unacked:%ld", &v) == 1) {
			long b = v * (mss > 0 ? mss : 1448);
			if (b > wp->inflight) {
				wp->inflight = b;
			}
		} else if (strncmp(tok, "retrans:", 8) == 0) {
			long cur;    /* retrans:cur/total - take the cumulative total */
			if (sscanf(tok, "retrans:%ld/%ld", &cur, &v) == 2 && v > wp->retrans) {
				wp->retrans = v;
			}
		}
	}
}

#endif /* TEST_PERF_TEST_H */
