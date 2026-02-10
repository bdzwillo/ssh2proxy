/*
 * test/setgroups_stub.c - LD_PRELOAD shim for the full-login proxy tests
 * (proxy_password.c, proxy_pubkey.c).
 *
 * In an unprivileged user namespace the kernel forces /proc/self/setgroups to
 * "deny" before gid_map may be written. That permanently disables setgroups()
 * in the namespace and every descendant, so sshd would abort before completing
 * the login under test:
 *   - the privsep child calls setgroups() directly
 *   - uidswap calls initgroups() (which sets the supplementary list too)
 *
 * Both are stubbed to no-ops:
 *   - they only drop supplementary groups a single mapped id never had, so a
 *     no-op is faithful here
 *   - initgroups() needs a separate stub: glibc routes it through an internal
 *     setgroups alias the PLT interposition below would otherwise miss
 *
 * The fork/privsep and auth are unchanged. The tests set LD_PRELOAD to this
 * object for the backend sshd child only.
 */
#include <sys/types.h>

int setgroups(size_t n, const void *list)
{
	(void)n;
	(void)list;
	return 0;
}

int initgroups(const char *user, gid_t group)
{
	(void)user;
	(void)group;
	return 0;
}
