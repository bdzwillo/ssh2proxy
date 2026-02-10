/*
 * test_tap.h - minimal TAP (Test Anything Protocol) producer
 *
 * Single-header test harness. Include in each test_*.c file.
 * Produces TAP output on stdout. Exit status: 0 on all-pass, 1 on any failure.
 */
#ifndef TEST_TAP_H
#define TEST_TAP_H

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>

#define TAP_UNUSED __attribute__((unused))

static int tap_test_num;
static int tap_failures;
static int tap_planned;

TAP_UNUSED static void
tap_plan(int n)
{
	tap_planned = n;
	tap_test_num = 0;
	tap_failures = 0;
	printf("1..%d\n", n);
}

TAP_UNUSED static int
tap_ok(int cond, const char *fmt, ...)
{
	va_list ap;

	tap_test_num++;
	if (cond) {
		printf("ok %d - ", tap_test_num);
	} else {
		printf("not ok %d - ", tap_test_num);
		tap_failures++;
	}
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
	return cond;
}

TAP_UNUSED static int
tap_is_int(long long got, long long expected, const char *name)
{
	int ok = (got == expected);

	tap_test_num++;
	if (ok) {
		printf("ok %d - %s\n", tap_test_num, name);
	} else {
		printf("not ok %d - %s\n", tap_test_num, name);
		printf("# got:      %lld\n", got);
		printf("# expected: %lld\n", expected);
		tap_failures++;
	}
	return ok;
}

TAP_UNUSED static int
tap_is_str(const char *got, const char *expected, const char *name)
{
	int ok;

	if (got == NULL && expected == NULL)
		ok = 1;
	else if (got == NULL || expected == NULL)
		ok = 0;
	else
		ok = (strcmp(got, expected) == 0);

	tap_test_num++;
	if (ok) {
		printf("ok %d - %s\n", tap_test_num, name);
	} else {
		printf("not ok %d - %s\n", tap_test_num, name);
		printf("# got:      '%s'\n", got ? got : "(null)");
		printf("# expected: '%s'\n", expected ? expected : "(null)");
		tap_failures++;
	}
	return ok;
}

TAP_UNUSED static int
tap_is_mem(const void *got, const void *expected, size_t len,
	const char *name)
{
	int ok = (memcmp(got, expected, len) == 0);

	tap_test_num++;
	if (ok) {
		printf("ok %d - %s\n", tap_test_num, name);
	} else {
		printf("not ok %d - %s\n", tap_test_num, name);
		tap_failures++;
	}
	return ok;
}

TAP_UNUSED static void
tap_skip(int n, const char *reason)
{
	int i;

	for (i = 0; i < n; i++) {
		tap_test_num++;
		printf("ok %d - # SKIP %s\n", tap_test_num, reason);
	}
}

TAP_UNUSED static int
tap_done(void)
{
	if (tap_test_num != tap_planned) {
		printf("# planned %d tests but ran %d\n",
			tap_planned, tap_test_num);
		return 1;
	}
	if (tap_failures) {
		printf("# %d test(s) failed\n", tap_failures);
		return 1;
	}
	return 0;
}

#endif /* TEST_TAP_H */
