#
# sshproxy - openssh based ssh2 proxy for multiple ssh backend hosts
#
# need to download openssh tar-archive first, like:
# > wget https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-8.2p1.tar.gz
#
INSTDIR =		/opt
PACKAGE_NAME =		ssh2proxy
OPENSSH =		openssh-8.2p1

PATCH = patch
SSH_PATCHES = Makefile.in.patch

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
		--with-cflags="-O3 $(PROF)" \
		--with-default-path=/bin \
	)

sshproxy: $(OPENSSH)
	(cd $(OPENSSH) && \
		make sshproxy)

clean:
	( cd $(OPENSSH) && \
		make clean)

