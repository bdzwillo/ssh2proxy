/*
 * test/chroot_ns.h - unprivileged user+mount-namespace scaffolding for the
 * C tests that need sshd to run as uid 0 without real root.
 *
 * The includer must define _GNU_SOURCE before any system header, for unshare()
 * and the CLONE_* flags.
 *
 * The approach (explained per-helper below): run the whole harness inside a
 * nested user+mount namespace that maps the caller to uid 0. Then:
 *   - the backend sshd's privsep startup and post-auth setuid become no-ops
 *   - a test-supplied /etc/passwd and /var/empty can be bound in
 *
 *   - enter_userns()       nested user+mount ns, self -> uid/gid 0
 *   - ns_bind_passwd()     bind a test-supplied /etc/passwd
 *   - ns_bind_var_empty()  bind a 0755 /var/empty for sshd privsep
 *   - ns_setup_pty()       private devpts for an interactive backend session
 *
 * file_write_str() (util.h) writes the namespace maps.
 */
#ifndef TEST_CHROOT_NS_H
#define TEST_CHROOT_NS_H

#include <sched.h>
#include <sys/mount.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "util.h"   /* file_write_str */

/* Become uid/gid 0 in a user namespace, so the backend sshd's setuid/setgid
 * calls are no-ops and CAP_SYS_ADMIN is held for the bind mounts below.
 * Returns 0, or -1 if user namespaces are unavailable.
 *
 * Done in two nested namespaces, because mapping an unprivileged id forces
 * setgroups=deny but sshd's privsep child calls setgroups():
 *   - ns1: map self -> 0 (setgroups denied)
 *   - ns2: now holding CAP_SETGID, map 0 -> 0 without denying setgroups, so it
 *     stays usable
 */
static inline int enter_userns(void)
{
	uid_t uid = getuid();
	gid_t gid = getgid();
	char buf[64];

	/* ns1: unprivileged -> setgroups must be denied to write gid_map */
	if (unshare(CLONE_NEWUSER) != 0) {
		return -1;
	}
	if (file_write_str("/proc/self/setgroups", "deny") != 0) {
		return -1;
	}
	snprintf(buf, sizeof(buf), "0 %u 1\n", (unsigned)gid);
	if (file_write_str("/proc/self/gid_map", buf) != 0) {
		return -1;
	}
	snprintf(buf, sizeof(buf), "0 %u 1\n", (unsigned)uid);
	if (file_write_str("/proc/self/uid_map", buf) != 0) {
		return -1;
	}
	/* ns2: now root in ns1 (CAP_SETGID there) -> map 0->0 with setgroups
	 * left enabled, and get a mount ns for the bind mounts below.
	 */
	if (unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0) {
		return -1;
	}
	if (file_write_str("/proc/self/gid_map", "0 0 1\n") != 0) {
		return -1;
	}
	if (file_write_str("/proc/self/uid_map", "0 0 1\n") != 0) {
		return -1;
	}
	/* keep the bind mounts from propagating to / leaking out of this ns */
	if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
		return -1;
	}
	return 0;
}

/* Write a fake /etc/passwd (body, e.g. the login user as uid 0 plus the sshd
 * privsep user) under tmp and bind-mount it over the real /etc/passwd, so the
 * backend sshd resolves the test's accounts and its setuid is a no-op.
 * Returns 0 on success.
 */
static inline int ns_bind_passwd(const char *tmp, const char *body)
{
	char path[PATH_MAX];
	FILE *f;

	snprintf(path, sizeof(path), "%s/passwd", tmp);
	f = fopen(path, "w");
	if (f == NULL) {
		return -1;
	}
	fputs(body, f);
	fclose(f);
	return mount(path, "/etc/passwd", NULL, MS_BIND, NULL);
}

/* Provide a 0755 sshd privsep chroot dir (/var/empty) owned by uid 0.
 *   - sshd requires /var/empty to be uid-0-owned and not group/world-writable
 *   - if the host has one, it is host-root-owned, which maps to "nobody"
 *     (unmapped) inside the namespace, so bind a fresh uid-0-owned dir over it
 *   - if the host has none, instead mount a fresh uid-0-owned tmpfs over /var
 *     and create the privsep dir inside it (the bind target is missing, so
 *     CAP_DAC_OVERRIDE does not apply)
 * Returns 0 on success.
 */
static inline int ns_bind_var_empty(const char *tmp)
{
	char empty[PATH_MAX];

	snprintf(empty, sizeof(empty), "%s/empty", tmp);
	if (mkdir(empty, 0755) < 0 && errno != EEXIST) {
		return -1;
	}
	if (mount(empty, "/var/empty", NULL, MS_BIND, NULL) == 0) {
		return 0;
	}
	if (errno != ENOENT) {
		return -1;
	}
	if (mount("tmpfs", "/var", "tmpfs", 0, "mode=0755") != 0) {
		return -1;
	}
	return mkdir("/var/empty", 0755);
}

/* Give the sandbox a usable pty for an interactive backend session: a private
 * devpts with /dev/ptmx pointed at it, plus a tty group at gid 0 (the only
 * mapped gid) so sshd can chown the pty.
 * Returns 0, or -1 if unavailable.
 */
static inline int ns_setup_pty(const char *tmp)
{
	char gpath[PATH_MAX];

	if (mount("devpts", "/dev/pts", "devpts", 0,
	    "newinstance,ptmxmode=0666,mode=0620") != 0) {
		return -1;
	}
	if (mount("/dev/pts/ptmx", "/dev/ptmx", NULL, MS_BIND, NULL) != 0) {
		return -1;
	}
	snprintf(gpath, sizeof(gpath), "%s/group", tmp);
	if (file_write_str(gpath, "root:x:0:\ntty:x:0:\nsshd:x:0:\n") != 0) {
		return -1;
	}
	return mount(gpath, "/etc/group", NULL, MS_BIND, NULL);
}

#endif /* TEST_CHROOT_NS_H */
