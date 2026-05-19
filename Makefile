#
# sshproxy - openssh based ssh2 proxy for multiple ssh backend hosts
#
# need to download openssh tar-archive first, like:
# > wget https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-9.9p2.tar.gz
#
INSTDIR =		/opt
PACKAGE_NAME =		ssh2proxy
OPENSSH =		openssh-9.9p2

PATCH = patch
SSH_PATCHES = Makefile.in.patch
ADD_CFLAGS = -DOPENSSL_SUPPRESS_DEPRECATED

all: sshproxy

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

ssh-configure:
	-(cd $(OPENSSH) && [ -f Makefile ] && make clean)
	( cd $(OPENSSH) && \
	 	./configure \
		--prefix=$(INSTDIR)/$(PACKAGE_NAME) \
		--with-cflags="-O3 $(ADD_CFLAGS)" \
		--with-default-path=/bin \
	)

sshproxy: $(OPENSSH)
	(cd $(OPENSSH) && \
		make sshproxy)

# Unprivileged integration tests against the freshly-built sshproxy (see test/).
TEST_BINS = test/proxy_basic test/proxy_password test/proxy_pubkey

test/proxy_basic: test/proxy_basic.c test/proxy_test.h test/ssh_test.h test/util.h test/tap.h
	gcc -g -Wall $< -o $@

# password/pubkey also do a full login via a real backend sshd; -lcrypt for it
test/proxy_password: test/proxy_password.c test/proxy_test.h test/ssh_test.h test/util.h test/chroot_ns.h test/tap.h test/setgroups_stub.so
	gcc -g -Wall $< -o $@ -lcrypt

test/proxy_pubkey: test/proxy_pubkey.c test/proxy_test.h test/ssh_test.h test/util.h test/chroot_ns.h test/tap.h test/setgroups_stub.so
	gcc -g -Wall $< -o $@

test/setgroups_stub.so: test/setgroups_stub.c
	gcc -shared -fPIC $< -o $@

# repoint the openssh symlink at $(OPENSSH) so tests run the freshly-built sshd
.PHONY: openssh
openssh:
	ln -sfn $(OPENSSH) openssh

# the tests run ssh/ssh-keygen/ssh-keyscan/sshd as well as sshproxy
test-tools: sshproxy openssh
	(cd $(OPENSSH) && make ssh ssh-keygen ssh-keyscan sshd sshd-session)

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

