#
# sshproxy - openssh based ssh2 proxy for multiple ssh backend hosts
#
# need to download openssh tar-archive first, like:
# > wget https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-10.3p1.tar.gz
#
INSTDIR =		/opt
PACKAGE_NAME =		ssh2proxy
OPENSSH =		openssh-10.3p1

PATCH = patch
SSH_PATCHES = Makefile.in.patch ssh-hpn.patch ssh-hpn-fix.patch
ADD_CFLAGS = -DOPENSSL_SUPPRESS_DEPRECATED

all: sshproxy

# ssh-hpn.patch touches configure.ac (--with-hpn), so the tree is
# regenerated with autoreconf after patching
ssh-patch:
ifneq ($(SSH_PATCHES),)
	(cd $(OPENSSH) && [ "$(SSH_PATCHES)" ] && \
		FAIL=0; \
		for PATCHFILE in $(SSH_PATCHES); \
		do \
			echo "patch apply $$PATCHFILE"; \
			$(PATCH) -p2 -b -i ../$$PATCHFILE; \
			if [ $$? -ne 0 ]; then \
				echo "patch $$PATCHFILE failed: $$?"; \
				FAIL=1; \
			fi \
		done ;\
		if [ $$FAIL -ne 0 ]; then \
			echo "patch exit - please fix rejects now"; \
			exit 1; \
		fi \
	)
	(cd $(OPENSSH) && autoreconf)
endif

$(OPENSSH):
	tar zxf $(OPENSSH).tar.gz
	ln -s ../sshproxy.c $(OPENSSH)/
	ln -s ../sshproxy.h $(OPENSSH)/
	ln -s ../proxyconf.c $(OPENSSH)/
	ln -s ../proxyconf.h $(OPENSSH)/
	ln -s ../proxyauth.c $(OPENSSH)/
	ln -s ../proxyauth.h $(OPENSSH)/
	ln -s ../ssh2.c $(OPENSSH)/
	ln -s ../switch.h $(OPENSSH)/
	ln -s ../switch-fixed.c $(OPENSSH)/
	ln -s ../check.h $(OPENSSH)/
	ln -s ../filter.h $(OPENSSH)/
	ln -s ../filter-mitm.c $(OPENSSH)/
	make ssh-patch
	make ssh-configure

# --with-hpn only; the NONE cipher that the HPN patch also carries would need
# --with-nonecipher and is deliberately left out of the build
ssh-configure:
	-(cd $(OPENSSH) && [ -f Makefile ] && make clean)
	( cd $(OPENSSH) && \
	 	./configure \
		--prefix=$(INSTDIR)/$(PACKAGE_NAME) \
		--with-hpn \
		--with-cflags="-O3 $(ADD_CFLAGS)" \
		--with-default-path=/bin \
	)

sshproxy: $(OPENSSH)
	(cd $(OPENSSH) && \
		make sshproxy)

# Unprivileged integration tests against the freshly-built sshproxy (see test/).
TEST_BINS = test/proxy_basic test/proxy_password test/proxy_pubkey test/proxy_hpn

test/proxy_basic: test/proxy_basic.c test/proxy_test.h test/ssh_test.h test/util.h test/tap.h
	gcc -g -Wall $< -o $@

# password/pubkey also do a full login via a real backend sshd; -lcrypt for it
test/proxy_password: test/proxy_password.c test/proxy_test.h test/ssh_test.h test/util.h test/chroot_ns.h test/tap.h test/setgroups_stub.so
	gcc -g -Wall $< -o $@ -lcrypt

test/proxy_pubkey: test/proxy_pubkey.c test/proxy_test.h test/ssh_test.h test/util.h test/chroot_ns.h test/tap.h test/setgroups_stub.so
	gcc -g -Wall $< -o $@

# HPN test: an end-to-end window-growth check through a real backend sshd
# behind the proxy; skips on a stock build
test/proxy_hpn: test/proxy_hpn.c test/proxy_test.h test/ssh_test.h test/util.h test/chroot_ns.h test/tap.h test/setgroups_stub.so
	gcc -g -Wall $< -o $@

test/setgroups_stub.so: test/setgroups_stub.c
	gcc -shared -fPIC $< -o $@

# HPN throughput benchmark through the proxy (HPN endpoints vs the stock 2MB
# window), not in "make test". Runs over a netem-shaped veth pair across two
# net namespaces - a real forwarding path that streams at window/RTT, so the
# window shows - with the proxy and its backend sshd in the server namespace.
# A raw-TCP link ceiling runs first, then ssh-pipe download and upload.
# - run:              make perf
# - HPN_PERF_MB       transfer size in MiB (default 512)
# - HPN_PERF_RTT_MS   round-trip time in ms (default 200; 0 = none)
# - HPN_PERF_RATE     per-endpoint rate cap in Mbit/s (default 1000; 0 = none)
# - HPN_PERF_RMEM_MB  TCP buffer ceiling in MiB (default auto ~2*BDP, min 64)
# - HPN_PERF_CC       TCP congestion control, both ns (default kernel default)
# Shaping needs iproute2; runs in unprivileged user+net namespaces, raising the
# buffers needs a writable /proc/sys/net.
PERF_BINS = test/proxy_hpn_perf

test/proxy_hpn_perf: test/proxy_hpn_perf.c test/proxy_test.h test/ssh_test.h test/util.h test/chroot_ns.h test/tap.h test/perf_test.h
	gcc -g -Wall $< -o $@

perf: test-tools $(PERF_BINS)
	@for t in $(PERF_BINS); do echo "== $$t =="; ./$$t; done

# repoint the openssh symlink at $(OPENSSH) so tests run the freshly-built sshd
.PHONY: openssh
openssh:
	ln -sfn $(OPENSSH) openssh

# the tests run ssh/ssh-keygen/ssh-keyscan/sshd as well as sshproxy
test-tools: sshproxy openssh
	(cd $(OPENSSH) && make ssh ssh-keygen ssh-keyscan sshd sshd-session sshd-auth)

# tests resolve tools by path ($SSHPROXY/$SSH/$KEYGEN/$KEYSCAN override); each
# keeps a /tmp/<name>.<pid> work dir for inspection
test: test-tools $(TEST_BINS)
	prove --exec '' $(TEST_BINS)

clean:
	( cd $(OPENSSH) && \
		make clean)
	rm -f openssh

distclean:
	rm -rf $(OPENSSH) openssh

# ssh-hpn.patch is the FreeBSD ports HPN patch, carried verbatim so that it can
# be refreshed from the port; ssh-hpn-fix.patch holds the corrections on top.
# Re-run 'make hpn-patch' after an openssh update and fix any rejects in
# ssh-hpn-fix.patch only.
FBSD_HPN_URL =		https://raw.githubusercontent.com/freebsd/freebsd-ports/main/security/openssh-portable/files
FBSD_HPN_SRC =		extra-patch-no-blocklistd-hpn-glue extra-patch-hpn
HPN_PATCH =		ssh-hpn.patch

# fetch each FreeBSD HPN patch and rewrite its ---/+++ paths to a|b/$(OPENSSH)/<file>
# (the port carries .orig suffixes and its own prefixes), so the result applies
# with the same 'patch -p2' as every other patch here
hpn-patch:
	@echo "# generated by 'make hpn-patch' from FreeBSD ports openssh-portable:" > $(HPN_PATCH)
	@echo "#   $(FBSD_HPN_SRC)" >> $(HPN_PATCH)
	@for p in $(FBSD_HPN_SRC); do \
		echo "fetch $$p"; \
		curl -fsSL $(FBSD_HPN_URL)/$$p -o .hpn.tmp || \
			{ echo "fetch failed: $$p"; rm -f .hpn.tmp; exit 1; }; \
		awk '/^(---|\+\+\+) /{ \
			tag=substr($$0,1,4); rest=substr($$0,5); t=index(rest,"\t"); \
			pfx=(substr($$0,1,1)=="-"?"a/":"b/"); \
			pa=(t>0?substr(rest,1,t-1):rest); ts=(t>0?substr(rest,t):""); \
			sub(/\.orig$$/,"",pa); n=split(pa,a,"/"); \
			print tag pfx"$(OPENSSH)/"a[n]ts; next }{ print }' \
			.hpn.tmp >> $(HPN_PATCH); \
	done
	@rm -f .hpn.tmp
	@echo "wrote $(HPN_PATCH)"

