
#
# (C) BSD, Vas Soshnikov
#

.PHONY = all fetch configure build test clean distclean

# The nginx version to build with: 1.19.4, 1.30.8 or 1.31.10.
#
#     $ make NGX_VERSION=1.30.8
#
NGX_VERSION ?= 1.19.4

ifeq ($(NGX_VERSION),1.19.4)
NGX_SHA256 = 61df546927905a0d624f9396bb7a8bc7ca7fd26522ce9714d56a78b73284000e
else ifeq ($(NGX_VERSION),1.30.8)
NGX_SHA256 = f867314ada32e717b949930859656c48a72dc6657aec598db58af2f98a40e1c1
else ifeq ($(NGX_VERSION),1.31.10)
NGX_SHA256 = a9b690957fca84abdae8a9b52d66b1bb459282d7f01fe4b94b498ed8e977bdb3
else
$(error nginx $(NGX_VERSION) is not known here, add its sha256 to the Makefile)
endif

NGX_PATH     = ./nginx
NGX_TARBALL  = nginx-$(NGX_VERSION).tar.gz
NGX_URL      = https://nginx.org/download/$(NGX_TARBALL)

# nginx 1.19.4 needs PCRE, not PCRE2: it is built together with nginx.
# The other versions use the PCRE2 of the system.
ifeq ($(NGX_VERSION),1.19.4)
PCRE_VERSION = 8.45
PCRE_PATH    = ./pcre-$(PCRE_VERSION)
PCRE_TARBALL = pcre-$(PCRE_VERSION).tar.bz2
PCRE_URL     = https://downloads.sourceforge.net/project/pcre/pcre/$(PCRE_VERSION)/$(PCRE_TARBALL)
PCRE_SHA256  = 4dae6fdcd2bb0bb6c37b5f97c33c2be954da743985369cddac3546e3218bffb8
PCRE_FLAGS   = --with-pcre=../$(PCRE_PATH)
endif

PREFIX_PATH = $(PWD)/test-root
MODULE_PATH = $(PWD)

# What ./configure gets. The values are used when nginx is configured,
# "make clean" configures it again, for example
#
#     $ make DEV_CFLAGS=-O2 NGX_DEBUG=
#
DEV_CFLAGS  ?= -ggdb3 -O0 -Wall
DEV_LDFLAGS ?=
NGX_DEBUG   ?= --with-debug
NGX_EXTRA   ?=

all: build

#
# Download and unpack the sources, unless they are here already. A download
# is tried up to five times with a pause in between: a download that fails
# usually fails because of the network.
#
fetch:
ifdef PCRE_VERSION
	@test -d $(PCRE_PATH) || { \
		echo "fetching $(PCRE_TARBALL)"; \
		for try in 1 2 3 4 5; do curl -fsSLO "$(PCRE_URL)" && { ok=1; break; }; sleep 5; done; \
		[ "$$ok" = 1 ] && \
		echo "$(PCRE_SHA256)  $(PCRE_TARBALL)" | (shasum -a 256 -c - || sha256sum -c -) && \
		tar -xjf $(PCRE_TARBALL); \
	}
endif
	@test -d $(NGX_PATH) || { \
		echo "fetching $(NGX_TARBALL)"; \
		for try in 1 2 3 4 5; do curl -fsSLO "$(NGX_URL)" && { ok=1; break; }; sleep 5; done; \
		[ "$$ok" = 1 ] && \
		echo "$(NGX_SHA256)  $(NGX_TARBALL)" | (shasum -a 256 -c - || sha256sum -c -) && \
		tar -xzf $(NGX_TARBALL) && \
		mv nginx-$(NGX_VERSION) $(NGX_PATH); \
	}

#
# nginx is configured once: the rule below runs while objs/Makefile does not
# exist, "make clean" removes it together with the object files. fetch is
# its only prerequisite, so the sources are there before ./configure runs,
# "make -j" included.
#
configure: | $(NGX_PATH)/objs/Makefile

$(NGX_PATH)/objs/Makefile: | fetch
	cd $(NGX_PATH) && \
		./configure \
			--with-cc-opt="$(DEV_CFLAGS)" \
			--with-ld-opt="$(DEV_LDFLAGS)" \
			$(NGX_DEBUG) \
			--prefix=$(PREFIX_PATH) \
			$(PCRE_FLAGS) \
			--with-http_slice_module \
			--add-module=$(MODULE_PATH)/proxy_folder_purge \
			$(NGX_EXTRA)

build: configure
	$(MAKE) -C $(NGX_PATH)

test: build
	NGINX_BIN=$(PWD)/$(NGX_PATH)/objs/nginx ./t/run.sh

clean:
	[ ! -e $(NGX_PATH)/objs/Makefile ] || $(MAKE) -C $(NGX_PATH) clean
	rm -rf t/.run

# The downloaded tarballs stay, so the next build does not need the network.
distclean:
	rm -rf $(NGX_PATH) $(PREFIX_PATH) t/.run $(PCRE_PATH)
