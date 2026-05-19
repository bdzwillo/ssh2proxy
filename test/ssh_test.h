/*
 * test/ssh_test.h - ssh-specific test helpers, layered on the generic helpers
 * in util.h.
 *
 * Defines struct ssh_env (the build-tree tool paths) and ssh_resolve_tools()
 * to fill it. struct proxy_env embeds it as its .tool member; see proxy_test.h.
 *
 *   ssh_resolve_tools()    fill a struct ssh_env from argv0 + $VAR overrides
 *                          (ssh, keygen, keyscan, sshd, sftp, scp; each has a
 *                          $VAR override)
 *   ssh_gen_key_type()     run ssh-keygen for a throwaway key (type + optional bits)
 *   ssh_gen_key()          ssh_gen_key_type() shorthand for ed25519
 *   ssh_dump_log_reason()  print a server log's auth/session refusal lines
 *   ssh_enable_legacy_rsa_sha1() re-enable ssh-rsa (SHA-1) for spawned tools
 *
 * The generic, ssh-agnostic helpers (ports, work dirs, process spawn, file/path
 * utilities) live in util.h, which this header includes.
 */
#ifndef TEST_SSH_TEST_H
#define TEST_SSH_TEST_H

#include "util.h"

/* Re-enable legacy ssh-rsa (SHA-1) signatures in spawned ssh/sshproxy/sshd:
 * - recent EL9 openssl disables SHA-1 signing via crypto-policy
 * - harmless elsewhere (Debian permits SHA-1, ignores this variable)
 * - needed for ssh-rsa legacy auth (modern rsa-sha2 is unaffected)
 */
static inline void ssh_enable_legacy_rsa_sha1(void)
{
	setenv("OPENSSL_ENABLE_SHA1_SIGNATURES", "1", 1);
}

/* Build-tree paths, embedded as the .tool member of struct proxy_env:
 *   - root         <repo> root the tools were derived from (for extra tools)
 *   - ssh..scp     absolute tool paths, so the execs work from any cwd
 *   - argv0        the path the test was run as (for resolve_sibling())
 */
struct ssh_env {
	char root[PATH_MAX];
	char ssh[PATH_MAX + 32];
	char keygen[PATH_MAX + 32];
	char keyscan[PATH_MAX + 32];
	char sshd[PATH_MAX + 32];
	char sshd_session[PATH_MAX + 32];
	char sftp[PATH_MAX + 32];
	char scp[PATH_MAX + 32];
	const char *argv0;
};

/* Fill the tool paths in t from realpath(argv0):
 *   - <repo>/test/<bin> -> <repo>/openssh/<tool>
 *   - $SSH/$KEYGEN/$SSHD/$SFTP/$SCP override the derived paths
 *   - t->root keeps the derived <repo> for proxy-specific tools
 * So manual runs like `./test/proxy_basic` work without env, from any cwd.
 */
static inline void ssh_resolve_tools(struct ssh_env *t, const char *argv0)
{
	char resolved[PATH_MAX], *slash;
	const char *root = ".";
	char d_ssh[PATH_MAX + 32], d_keygen[PATH_MAX + 32], d_keyscan[PATH_MAX + 32];
	char d_sshd[PATH_MAX + 32], d_sftp[PATH_MAX + 32], d_scp[PATH_MAX + 32];
	char d_sshd_session[PATH_MAX + 32];

	if (argv0 && realpath(argv0, resolved)) {
		slash = strrchr(resolved, '/');     /* strip the binary name */
		if (slash) {
			*slash = '\0';              /* <repo>/test */
			slash = strrchr(resolved, '/');
			if (slash) {
				*slash = '\0';      /* <repo> */
				root = resolved;
			}
		}
	}
	snprintf(t->root, sizeof(t->root), "%s", root);
	snprintf(d_ssh,     sizeof(d_ssh),     "%s/openssh/ssh", root);
	snprintf(d_keygen,  sizeof(d_keygen),  "%s/openssh/ssh-keygen", root);
	snprintf(d_keyscan, sizeof(d_keyscan), "%s/openssh/ssh-keyscan", root);
	snprintf(d_sshd,    sizeof(d_sshd),    "%s/openssh/sshd", root);
	snprintf(d_sshd_session, sizeof(d_sshd_session), "%s/openssh/sshd-session", root);
	snprintf(d_sftp,    sizeof(d_sftp),    "%s/openssh/sftp", root);
	snprintf(d_scp,     sizeof(d_scp),     "%s/openssh/scp", root);
	snprintf(t->ssh,     sizeof(t->ssh),     "%s", env_default("SSH", d_ssh));
	snprintf(t->keygen,  sizeof(t->keygen),  "%s", env_default("KEYGEN", d_keygen));
	snprintf(t->keyscan, sizeof(t->keyscan), "%s", env_default("KEYSCAN", d_keyscan));
	snprintf(t->sshd,    sizeof(t->sshd),    "%s", env_default("SSHD", d_sshd));
	snprintf(t->sshd_session, sizeof(t->sshd_session), "%s", env_default("SSHD_SESSION", d_sshd_session));
	snprintf(t->sftp,    sizeof(t->sftp),    "%s", env_default("SFTP", d_sftp));
	snprintf(t->scp,     sizeof(t->scp),     "%s", env_default("SCP", d_scp));
	t->argv0 = argv0;
}

/* generate a throwaway key of the given type at path (path and path.pub) using
 * t->keygen; bits > 0 adds -b <bits> (for RSA), bits == 0 omits it (ed25519
 * ignores key size).
 */
static inline int ssh_gen_key_type(const struct ssh_env *t, const char *path,
	const char *type, int bits)
{
	pid_t pid = fork();
	int st;
	char bitsbuf[16];

	if (pid < 0) {
		return -1;
	}
	if (pid == 0) {
		int dn = open("/dev/null", O_WRONLY);
		if (dn >= 0) {
			dup2(dn, 1);
			dup2(dn, 2);
		}
		if (bits > 0) {
			snprintf(bitsbuf, sizeof(bitsbuf), "%d", bits);
			execl(t->keygen, t->keygen, "-q", "-t", type, "-b", bitsbuf,
				"-f", path, "-N", "", (char *)NULL);
		} else {
			execl(t->keygen, t->keygen, "-q", "-t", type, "-f", path,
				"-N", "", (char *)NULL);
		}
		_exit(127);
	}
	if (waitpid(pid, &st, 0) < 0) {
		return -1;
	}
	return (WIFEXITED(st) && WEXITSTATUS(st) == 0) ? 0 : -1;
}

/* generate a throwaway ed25519 key at path (path and path.pub). */
static inline int ssh_gen_key(const struct ssh_env *t, const char *path)
{
	return ssh_gen_key_type(t, path, "ed25519", 0);
}

/* Print the lines of a server log that explain an auth/session refusal. The
 * reason is server-side (the client only ever sees "Permission denied") and at
 * DEBUG2 it usually sits past file_dump()'s 8 KB head, so scan the whole file
 * for the known refusal markers instead.
 */
static inline void ssh_dump_log_reason(const char *path)
{
	static const char *needles[] = {
		"refusing", "not allowed", "sftp connections only",
		"access denied", "Access Denied", "lacks privileges",
		"Invalid key length", "Disconnecting:", "fatal:", NULL
	};
	char line[1024];
	FILE *f = fopen(path, "r");
	int i, hits = 0;

	if (f == NULL) {
		return;
	}
	while (fgets(line, sizeof(line), f) != NULL) {
		for (i = 0; needles[i] != NULL; i++) {
			if (strstr(line, needles[i]) != NULL) {
				if (hits++ == 0) {
					fprintf(stderr, "# --- sshd.log (reason) ---\n");
				}
				fprintf(stderr, "# %s", line);
				break;
			}
		}
	}
	fclose(f);
}

#endif /* TEST_SSH_TEST_H */
