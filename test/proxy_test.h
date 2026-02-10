/*
 * test/proxy_test.h - ssh2proxy-specific subprocess harness, on top of the
 * generic ssh_test.h.
 *
 * Everything runs as the invoking, unprivileged user: a freshly-built sshproxy
 * is started on a loopback high port, fed a generated hostkey, and probed with
 * the build-tree ssh/ssh-keyscan. Backend routing is checked without a real
 * sshd: a plain listening socket stands in for the backend, and the proxy's
 * connect lands in its accept backlog (the proxy dials the backend as soon as
 * the client sends its first userauth request, before auth completes).
 *
 * The layering:
 *   - generic helpers (ports, work dirs, key gen, process readiness/teardown,
 *     capture, file/log helpers) live in ssh_test.h, built on struct ssh_env
 *   - struct proxy_env embeds that as .tool and adds the sshproxy tool
 *
 * This header adds the proxy-specific helpers:
 *
 *   proxy_resolve_paths()  fill a proxy_env from argv0 + $VAR overrides
 *   hostkey_path()         build "<dir>/hostkey"
 *   proxy_spawn()          fork + setpgid + exec the proxy
 *   sshd_spawn()           fork + setpgid + exec a real backend sshd
 *   ssh_password_cmd()     password login via askpass + remote command
 *   ssh_password()         password login, no command, no capture
 *   ssh_pubkey_cmd()       pubkey login with -i identity + command
 *   ssh_pubkey_poke()      doomed pubkey probe, just to make the proxy dial
 *   backend_listener()     a stand-in backend socket (bind + listen)
 *   backend_accept_fork()  did the proxy dial here? (select + accept)
 *   backend_hit()          collect that probe's verdict
 *   write_askpass()        write a chmod-0700 askpass script
 *   setup_hostbased_trust() ~/.shosts + ~/.ssh/known_hosts for the hostbased leg
 */
#ifndef TEST_PROXY_TEST_H
#define TEST_PROXY_TEST_H

#include <sys/select.h>

#include "ssh_test.h"

/* The tools a proxy test runs: the common ones in .tool, plus sshproxy.
 * Filled by proxy_resolve_paths().
 */
struct proxy_env {
	struct ssh_env tool;
	char sshproxy[PATH_MAX + 32];
};

/* Fill e: the common tools via ssh_resolve_tools(), then sshproxy from the same
 * <repo> root. $SSHPROXY overrides.
 */
static inline void proxy_resolve_paths(struct proxy_env *e, const char *argv0)
{
	const char *root;
	char d[PATH_MAX + 32];

	ssh_resolve_tools(&e->tool, argv0);
	root = e->tool.root;
	snprintf(d, sizeof(d), "%s/openssh/sshproxy", root);
	snprintf(e->sshproxy, sizeof(e->sshproxy), "%s", env_default("SSHPROXY", d));
}

/* build "<dir>/hostkey" into buf and return it (handy inline in ssh_gen_key()). */
static inline char *hostkey_path(const char *dir, char *buf, size_t bufsz)
{
	snprintf(buf, bufsz, "%s/hostkey", dir);
	return buf;
}

/* fork sshproxy as "sshproxy -d -e -c cfgpath" in a new process group, with
 * stdout/stderr (the -e log) redirected to logpath. The dedicated pgid lets
 * reap_pg() killpg the proxy together with its per-connection forks.
 * Returns pid or -1.
 */
static inline pid_t proxy_spawn(const struct proxy_env *e, const char *cfgpath,
	const char *logpath)
{
	pid_t pid = fork();

	if (pid < 0) {
		return -1;
	}
	if (pid == 0) {
		int dn = open("/dev/null", O_RDONLY);
		int lf = open(logpath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
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
		execl(e->sshproxy, e->sshproxy, "-d", "-e", "-c", cfgpath,
			(char *)NULL);
		_exit(127);
	}
	return pid;
}

/* fork a real backend sshd as "sshd -D -f cfgpath -E logpath" in a new
 * process group (e->tool.sshd is absolute, since sshd re-execs itself).
 * stdin/out/err go to /dev/null; the real log goes to -E logpath. Returns pid.
 */
static inline pid_t sshd_spawn(const struct proxy_env *e, const char *cfgpath,
	const char *logpath)
{
	pid_t pid = fork();

	if (pid < 0) {
		return -1;
	}
	if (pid == 0) {
		int dn = open("/dev/null", O_RDWR);
		setpgid(0, 0);
		if (dn >= 0) {
			dup2(dn, 0);
			dup2(dn, 1);
			dup2(dn, 2);
			if (dn > 2) {
				close(dn);
			}
		}
		execl(e->tool.sshd, e->tool.sshd, "-D", "-f", cfgpath, "-E", logpath,
			(char *)NULL);
		_exit(127);
	}
	return pid;
}

/* run ssh forcing password auth and a remote command, feeding the password via
 * an askpass script (no tty). The child starts a new session (setsid) so ssh
 * uses SSH_ASKPASS, and points SSH_ASKPASS/SSH_ASKPASS_REQUIRE at askpass_path.
 * The remote command's stdout is captured into out (NULL to discard); ssh's
 * stderr/diagnostics are discarded. Returns ssh's exit code, or -1.
 */
static inline int ssh_password_cmd(const struct proxy_env *e, const char *user,
	int port, const char *askpass_path, const char *cmd, char *out, size_t outsz)
{
	char userat[256], portarg[16];
	int pfd[2];
	pid_t pid;
	int st;
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
		setsid();
		close(pfd[0]);
		if (dn >= 0) {
			dup2(dn, 0);
			dup2(dn, 2);
		}
		dup2(pfd[1], 1);
		close(pfd[1]);
		if (dn > 2) {
			close(dn);
		}
		setenv("SSH_ASKPASS", askpass_path, 1);
		setenv("SSH_ASKPASS_REQUIRE", "force", 1);
		snprintf(userat, sizeof(userat), "%s@127.0.0.1", user);
		snprintf(portarg, sizeof(portarg), "%d", port);
		execl(e->tool.ssh, e->tool.ssh, "-F", "/dev/null",
			"-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "GlobalKnownHostsFile=/dev/null",
			"-o", "PreferredAuthentications=password",
			"-o", "NumberOfPasswordPrompts=1",
			"-o", "LogLevel=ERROR",
			"-p", portarg, userat, cmd, (char *)NULL);
		_exit(127);
	}
	close(pfd[1]);
	for (;;) {
		ssize_t r;
		char buf[1024];

		r = read(pfd[0], buf, sizeof(buf));
		if (r <= 0) {
			break;
		}
		if (out != NULL && total + (size_t)r < outsz) {
			memcpy(out + total, buf, r);
			total += r;
			out[total] = '\0';
		}
	}
	close(pfd[0]);
	if (waitpid(pid, &st, 0) < 0) {
		return -1;
	}
	return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

/* ssh_password_cmd with a no-op remote command and no output capture, for
 * tests that only need the proxy to forward a (doomed) password attempt.
 */
static inline int ssh_password(const struct proxy_env *e, const char *user,
	int port, const char *askpass_path)
{
	return ssh_password_cmd(e, user, port, askpass_path, "true", NULL, 0);
}

/* run ssh forcing publickey auth with identity (a private key file, or
 * "/dev/null" for a probe that cannot authenticate) and a remote command. The
 * command's stdout is captured into out (NULL to discard). Returns ssh's exit
 * code, or -1.
 */
static inline int ssh_pubkey_cmd(const struct proxy_env *e, const char *user,
	int port, const char *identity, const char *cmd, char *out, size_t outsz)
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
			"-i", (char *)identity, "-p", portarg, userat,
			(char *)cmd, (char *)NULL
		};
		return run_capture(argv, 0, out, outsz);
	}
}

/* fire a doomed publickey login at the proxy as `user`: it gets far enough for
 * the proxy to select and dial a backend (the username rides the first userauth
 * request), then fails. The routing is observed on the backend listeners, not in
 * ssh's result. Uses an empty identity (/dev/null) so it can never authenticate.
 */
static inline int ssh_pubkey_poke(const struct proxy_env *e, const char *user,
	int port)
{
	return ssh_pubkey_cmd(e, user, port, "/dev/null", "true", NULL, 0);
}

/* a backend stand-in: a listening socket on 127.0.0.1:port. The proxy connects
 * here when it selects this target; the connection sits in the backlog until
 * backend_accept_fork() picks it up. Returns the listen fd or -1.
 */
static inline int backend_listener(int port)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in a;
	int one = 1;

	if (fd < 0) {
		return -1;
	}
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	a.sin_port = htons(port);
	if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0 || listen(fd, 8) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

/* Fork a child that stands in for a backend sshd, so a probe can observe that
 * the proxy dialed this address. It runs concurrently with the ssh probe (the
 * proxy connects mid-handshake), and:
 *
 *   - waits up to timeout_ms for the proxy to connect
 *   - accepts the connection and speaks a minimal SSH banner, so the proxy's
 *     banner read succeeds - it then fails in key exchange instead, which is
 *     fine, since only the connect needs to be observed
 *   - _exit(0) if it accepted a connection, _exit(1) on timeout
 *
 * Returns the child pid; collect the result with backend_hit().
 */
static inline pid_t backend_accept_fork(int listen_fd, int timeout_ms)
{
	pid_t pid = fork();
	struct timeval tv;
	fd_set rfds;

	if (pid != 0) {
		return pid;
	}
	FD_ZERO(&rfds);
	FD_SET(listen_fd, &rfds);
	tv.tv_sec = timeout_ms / 1000;
	tv.tv_usec = (timeout_ms % 1000) * 1000;
	if (select(listen_fd + 1, &rfds, NULL, NULL, &tv) > 0) {
		int c = accept(listen_fd, NULL, NULL);
		if (c >= 0) {
			/* speak a minimal SSH ident so the proxy's banner read
			 * succeeds (it then fails later in key exchange instead,
			 * which is fine - only the connect needs observing)
			 */
			static const char banner[] = "SSH-2.0-sshproxy_test\r\n";
			ssize_t w = write(c, banner, sizeof(banner) - 1);
			(void)w;
			close(c);
			_exit(0);
		}
	}
	_exit(1);
}

/* Collect a backend_accept_fork() child after the probe ran. Returns 1 if it
 * accepted a connection (the proxy routed here), 0 otherwise. A child still
 * blocked in accept() means no connection arrived: kill and reap it.
 */
static inline int backend_hit(pid_t pid)
{
	int st, waited = 0;

	/* small grace for the child to exit after accepting */
	while (waited < 500) {
		if (waitpid(pid, &st, WNOHANG) == pid) {
			return (WIFEXITED(st) && WEXITSTATUS(st) == 0) ? 1 : 0;
		}
		usleep(50000);
		waited += 50;
	}
	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);
	return 0;
}

/* write a chmod-0700 askpass script that echoes `pass`, for the password tests
 * (ssh runs it via SSH_ASKPASS). Returns 0 on success.
 */
static inline int write_askpass(const char *path, const char *pass)
{
	FILE *f = fopen(path, "w");

	if (f == NULL) {
		return -1;
	}
	fprintf(f, "#!/bin/sh\necho %s\n", pass);
	fclose(f);
	return chmod(path, 0700);
}

/* Set up the backend's host trust so it accepts the proxy's hostbased leg:
 *  - ~/.shosts trusts the proxy's chost "localhost" (it dials from loopback);
 *  - ~/.ssh/known_hosts pins the proxy's hostkey_auth public key (read from
 *    pubpath) as that host's key.
 * home is the login user's pw_dir, sshdir its ~/.ssh. Returns 0 on success.
 */
static inline int setup_hostbased_trust(const char *home, const char *sshdir,
	const char *pubpath)
{
	char shosts[PATH_MAX + 16], known[PATH_MAX + 24];
	char idpub[PATH_MAX], line[PATH_MAX + 16];
	FILE *f;

	snprintf(shosts, sizeof(shosts), "%s/.shosts", home);
	f = fopen(shosts, "w");
	if (f == NULL) {
		return -1;
	}
	fputs("localhost\n", f);
	fclose(f);
	if (file_slurp(pubpath, idpub, sizeof(idpub)) != 0) {
		return -1;
	}
	snprintf(known, sizeof(known), "%s/known_hosts", sshdir);
	f = fopen(known, "w");
	if (f == NULL) {
		return -1;
	}
	snprintf(line, sizeof(line), "localhost %s\n", idpub);
	fputs(line, f);
	fclose(f);
	return 0;
}

#endif /* TEST_PROXY_TEST_H */
