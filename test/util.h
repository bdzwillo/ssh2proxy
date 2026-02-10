/*
 * test/util.h - generic, environment-free test helpers
 *   - no ssh / struct ssh_env coupling
 *   - ssh_test.h includes util.h and adds the ssh-specific layer.
 *
 * The helpers, by group:
 *
 *   env_default()          $VAR-or-default lookup
 *
 *   pick_free_port()       bind(0) to grab an ephemeral TCP port
 *   wait_for_listen()      TCP readiness probe (a proxy or a backend coming up)
 *
 *   wait_exit()            wait for a pid, return its exit code
 *   reap_pg()              killpg teardown (grace_ms between SIGTERM and SIGKILL)
 *   run_capture_e()        fork/exec a command, capture stdout (optional setsid/stderr)
 *   run_capture()          run_capture_e() with stderr discarded
 *   run_stdin()            run_capture with stdin from a file (always setsid)
 *
 *   make_tmpdir()          per-run /tmp work dir, kept for inspection
 *   resolve_sibling()      absolute path to a file next to the test binary
 *   mkdirs()               mkdir -p for the directory components of a path
 *
 *   file_write_str()       write a string to a file (create/truncate)
 *   file_writef()          printf-style write to a file (create/truncate)
 *   file_copy()            copy a file preserving mode
 *   file_slurp()           read a whole file, trim a trailing newline
 *   file_contains()        whole-file substring search (log assertions)
 *   file_dump()            print a file as a TAP diagnostic
 */
#ifndef TEST_UTIL_H
#define TEST_UTIL_H

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static inline const char *env_default(const char *k, const char *dflt)
{
	const char *v = getenv(k);
	return (v && *v) ? v : dflt;
}

static inline int pick_free_port(void)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in a;
	socklen_t al = sizeof(a);
	int port;

	if (fd < 0) {
		return -1;
	}
	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0) {
		close(fd);
		return -1;
	}
	getsockname(fd, (struct sockaddr *)&a, &al);
	port = ntohs(a.sin_port);
	close(fd);
	return port;
}

/* Wait up to timeout_ms for something to accept on 127.0.0.1:port - a proxy or
 * a backend sshd coming up. Returns 0 once a connect succeeds, -1 on timeout.
 */
static inline int wait_for_listen(int port, int timeout_ms)
{
	int waited = 0;

	while (waited < timeout_ms) {
		int fd = socket(AF_INET, SOCK_STREAM, 0);
		struct sockaddr_in a;

		memset(&a, 0, sizeof(a));
		a.sin_family = AF_INET;
		a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		a.sin_port = htons(port);
		if (connect(fd, (struct sockaddr *)&a, sizeof(a)) == 0) {
			close(fd);
			return 0;
		}
		close(fd);
		usleep(50000);
		waited += 50;
	}
	return -1;
}

/* Per-run work dir /tmp/<name>.<pid>, created and kept for inspection. The path
 * is printed as a diagnostic when run directly; under prove (HARNESS_ACTIVE)
 * stay quiet. Returns 0 on success.
 */
static inline int make_tmpdir(const char *name, char *buf, size_t bufsz)
{
	snprintf(buf, bufsz, "/tmp/%s.%d", name, (int)getpid());
	if (mkdir(buf, 0755) < 0 && errno != EEXIST) {
		return -1;
	}
	if (getenv("HARNESS_ACTIVE") == NULL) {
		fprintf(stderr, "# tmpdir %s\n", buf);
	}
	return 0;
}

/* Wait up to timeout_ms for pid to exit; return its exit code (128 if it died
 * on a signal), or -1 if it is still running - then killpg it.
 */
static inline int wait_exit(pid_t pid, int timeout_ms)
{
	int waited = 0, st;

	while (waited < timeout_ms) {
		if (waitpid(pid, &st, WNOHANG) == pid) {
			return WIFEXITED(st) ? WEXITSTATUS(st) : 128;
		}
		usleep(50000);
		waited += 50;
	}
	killpg(pid, SIGKILL);
	waitpid(pid, NULL, 0);
	return -1;
}

static inline void reap_pg(pid_t pid, int grace_ms)
{
	if (pid > 0) {
		killpg(pid, SIGTERM);
		waitpid(pid, NULL, 0);
		usleep(grace_ms * 1000);
		killpg(pid, SIGKILL);
	}
}

/* fork a child with a pseudo-terminal as its controlling tty, like forkpty(3)
 * but using only libc primitives (no -lutil). In the child, stdin/stdout/stderr
 * are the pty slave; in the parent, *master is the pty master. Returns the child
 * pid, 0 in the child, or -1 on error.
 */
static inline pid_t pty_fork(int *master)
{
	int m, s;
	char *name;
	pid_t pid;

	if ((m = posix_openpt(O_RDWR | O_NOCTTY)) < 0) {
		return -1;
	}
	if (grantpt(m) != 0 || unlockpt(m) != 0 || (name = ptsname(m)) == NULL) {
		close(m);
		return -1;
	}
	if ((s = open(name, O_RDWR)) < 0) {
		close(m);
		return -1;
	}
	if ((pid = fork()) < 0) {
		close(m);
		close(s);
		return -1;
	}
	if (pid == 0) {
		close(m);
		setsid();
		if (ioctl(s, TIOCSCTTY, 0) < 0) {
			_exit(127);
		}
		dup2(s, 0);
		dup2(s, 1);
		dup2(s, 2);
		if (s > 2) {
			close(s);
		}
		return 0;
	}
	close(s);
	*master = m;
	return pid;
}

/* fork/exec argv (path in argv[0]), optionally in a new session (so ssh has no
 * controlling tty and uses SSH_ASKPASS). stdin from /dev/null, stdout captured
 * into out. stderr goes to errpath if non-NULL (so a failing test can file_dump()
 * the client's stderr), else to /dev/null. Returns the exit code, or -1.
 */
static inline int run_capture_e(char *const argv[], int do_setsid,
	char *out, size_t outsz, const char *errpath)
{
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
		int efd = (errpath != NULL) ?
			open(errpath, O_WRONLY | O_CREAT | O_TRUNC, 0600) : -1;
		if (do_setsid) {
			setsid();
		}
		close(pfd[0]);
		if (dn >= 0) {
			dup2(dn, 0);
		}
		dup2(pfd[1], 1);
		if (efd >= 0) {
			dup2(efd, 2);
		} else if (dn >= 0) {
			dup2(dn, 2);
		}
		close(pfd[1]);
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

/* run_capture_e with stderr discarded (stderr -> /dev/null). */
static inline int run_capture(char *const argv[], int do_setsid,
	char *out, size_t outsz)
{
	return run_capture_e(argv, do_setsid, out, outsz, NULL);
}

/* Like run_capture but with stdin read from stdin_path instead of /dev/null
 * (for commands fed a batch on stdin); always runs in a new session. stdout is
 * captured into out, stderr discarded. Returns the exit code, or -1.
 */
static inline int run_stdin(char *const argv[], const char *stdin_path,
	char *out, size_t outsz)
{
	int pfd[2], st;
	pid_t pid;
	size_t tot = 0;
	ssize_t r;

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
		int in = open(stdin_path, O_RDONLY);
		int dn = open("/dev/null", O_WRONLY);

		setsid();
		if (in >= 0) {
			dup2(in, 0);
		}
		dup2(pfd[1], 1);
		if (dn >= 0) {
			dup2(dn, 2);
		}
		close(pfd[0]);
		close(pfd[1]);
		execv(argv[0], argv);
		_exit(127);
	}
	close(pfd[1]);
	while (out != NULL &&
	    (r = read(pfd[0], out + tot, outsz - 1 - tot)) > 0) {
		tot += (size_t)r;
		out[tot] = '\0';
	}
	close(pfd[0]);
	if (waitpid(pid, &st, 0) < 0) {
		return -1;
	}
	return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

/* Absolute path to a file (e.g. the setgroups shim) sitting next to the test
 * binary, derived from realpath(argv0); falls back to a cwd-relative name.
 */
static inline void resolve_sibling(const char *argv0, const char *name,
	char *buf, size_t bufsz)
{
	char resolved[PATH_MAX], *slash;

	if (realpath(argv0, resolved) && (slash = strrchr(resolved, '/'))) {
		*slash = '\0';
		snprintf(buf, bufsz, "%s/%s", resolved, name);
	} else {
		snprintf(buf, bufsz, "./%s", name);
	}
}

/* Write a string to a file, creating and truncating it (mode 0644); also used
 * on /proc control files, which ignore O_CREAT/O_TRUNC. Returns 0 on success.
 */
static inline int file_write_str(const char *path, const char *s)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	ssize_t n;

	if (fd < 0) {
		return -1;
	}
	n = write(fd, s, strlen(s));
	close(fd);
	return (n == (ssize_t)strlen(s)) ? 0 : -1;
}

/* printf-style write to a file, creating and truncating it (mode 0644), for the
 * harness's generated config files. Returns 0 on success, -1 on open failure or
 * a short/failed write.
 */
static inline int file_writef(const char *path, const char *fmt, ...)
{
	va_list ap;
	FILE *f = fopen(path, "w");
	int rc;

	if (f == NULL) {
		return -1;
	}
	va_start(ap, fmt);
	rc = vfprintf(f, fmt, ap);
	va_end(ap);
	if (fclose(f) != 0 || rc < 0) {
		return -1;
	}
	return 0;
}

static inline int file_copy(const char *src, const char *dst, mode_t mode)
{
	char buf[65536];
	int in, out;
	ssize_t n;

	in = open(src, O_RDONLY);
	if (in < 0) {
		return -1;
	}
	out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, mode);
	if (out < 0) {
		close(in);
		return -1;
	}
	while ((n = read(in, buf, sizeof(buf))) > 0) {
		if (write(out, buf, n) != n) {
			close(in);
			close(out);
			return -1;
		}
	}
	close(in);
	close(out);
	return (n < 0) ? -1 : 0;
}

/* mkdir -p for the directory components of a file path */
static inline int mkdirs(const char *path)
{
	char tmp[PATH_MAX];
	char *p;

	if (strlen(path) >= sizeof(tmp)) {
		return -1;
	}
	strcpy(tmp, path);
	for (p = tmp + 1; *p != '\0'; p++) {
		if (*p == '/') {
			*p = '\0';
			if (mkdir(tmp, 0755) < 0 && errno != EEXIST) {
				return -1;
			}
			*p = '/';
		}
	}
	return 0;
}

/* read a file's whole contents into buf (NUL-terminated), trimming a trailing
 * newline. Returns 0 on success.
 */
static inline int file_slurp(const char *path, char *buf, size_t bufsz)
{
	int fd = open(path, O_RDONLY);
	ssize_t n;

	if (fd < 0) {
		return -1;
	}
	n = read(fd, buf, bufsz - 1);
	close(fd);
	if (n < 0) {
		return -1;
	}
	buf[n] = '\0';
	buf[strcspn(buf, "\r\n")] = '\0';
	return 0;
}

/* Whole-file substring search (log assertions). Reads up to 1 MiB - enough for
 * a single-session DEBUG3 log - looping so a short read never truncates the
 * scan. Returns 1 if needle is present, 0 otherwise.
 */
static inline int file_contains(const char *path, const char *needle)
{
	static char buf[1 << 20];       /* 1 MiB; static - too big for the stack */
	int fd = open(path, O_RDONLY);
	size_t tot = 0;
	ssize_t n;

	if (fd < 0) {
		return 0;
	}
	while (tot < sizeof(buf) - 1 &&
	    (n = read(fd, buf + tot, sizeof(buf) - 1 - tot)) > 0) {
		tot += (size_t)n;
	}
	close(fd);
	buf[tot] = '\0';
	return strstr(buf, needle) != NULL;
}

static inline void file_dump(const char *path, const char *label)
{
	char buf[8192];
	int fd = open(path, O_RDONLY);
	int n;

	if (fd < 0) {
		return;
	}
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0) {
		return;
	}
	buf[n] = '\0';
	fprintf(stderr, "# --- %s ---\n%s\n", label, buf);
}

#endif /* TEST_UTIL_H */
