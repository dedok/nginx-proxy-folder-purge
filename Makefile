
#
# Copyright (C) BSDv2
#

.PHONY = all fetch configure build test clean distclean

NGX_VERSION  = 1.19.4
NGX_PATH     = ./nginx
NGX_TARBALL  = nginx-$(NGX_VERSION).tar.gz
NGX_URL      = https://nginx.org/download/$(NGX_TARBALL)
NGX_SHA256   = 61df546927905a0d624f9396bb7a8bc7ca7fd26522ce9714d56a78b73284000e
NGX_PATCH    = patches/nginx.ver_1019004.patch

# nginx 1.19.4 needs the first PCRE, not PCRE2. The library is not installed
# on a modern system anymore, so it is built together with nginx.
PCRE_VERSION = 8.45
PCRE_PATH    = ./pcre-$(PCRE_VERSION)
PCRE_TARBALL = pcre-$(PCRE_VERSION).tar.bz2
PCRE_URL     = https://downloads.sourceforge.net/project/pcre/pcre/$(PCRE_VERSION)/$(PCRE_TARBALL)
PCRE_SHA256  = 4dae6fdcd2bb0bb6c37b5f97c33c2be954da743985369cddac3546e3218bffb8

PREFIX_PATH = $(PWD)/test-root
MODULE_PATH = $(PWD)

DEV_CFLAGS  = -ggdb3 -O0 -Wall

all: build

#
# Download and unpack the sources, unless they are here already.
#
fetch:
	@test -d $(PCRE_PATH) || { \
		echo "fetching $(PCRE_TARBALL)"; \
		curl -sSLO "$(PCRE_URL)" && \
		echo "$(PCRE_SHA256)  $(PCRE_TARBALL)" | (shasum -a 256 -c - || sha256sum -c -) && \
		tar -xjf $(PCRE_TARBALL); \
	}
	@test -d $(NGX_PATH) || { \
		echo "fetching $(NGX_TARBALL)"; \
		curl -sSLO "$(NGX_URL)" && \
		echo "$(NGX_SHA256)  $(NGX_TARBALL)" | (shasum -a 256 -c - || sha256sum -c -) && \
		tar -xzf $(NGX_TARBALL) && \
		mv nginx-$(NGX_VERSION) $(NGX_PATH); \
	}

#
# nginx is configured when nginx/objs/Makefile exists, the rule below runs
# only when it does not: "make clean" in ./nginx removes it together with
# the object files.
#
configure: | fetch $(NGX_PATH)/objs/Makefile

$(NGX_PATH)/objs/Makefile:
	@if ! grep -q NGX_MASKS_STORAGE $(NGX_PATH)/src/core/ngx_file.h; then \
		echo "applying $(NGX_PATCH)"; \
		patch -d $(NGX_PATH) -N -p1 < $(NGX_PATCH) || exit 1; \
	fi
	cd $(NGX_PATH) && \
		./configure \
			--with-cc-opt="$(DEV_CFLAGS)" \
			--with-debug \
			--prefix=$(PREFIX_PATH) \
			--with-pcre=../$(PCRE_PATH) \
			--with-http_slice_module \
			--add-module=$(MODULE_PATH)/proxy_folder_purge

build: configure
	$(MAKE) -C $(NGX_PATH)

test: build
	NGINX_BIN=$(PWD)/$(NGX_PATH)/objs/nginx ./t/run.sh

clean:
	[ ! -e $(NGX_PATH)/objs/Makefile ] || $(MAKE) -C $(NGX_PATH) clean
	rm -rf t/.run

# The downloaded tarballs stay, so the next build does not need the network.
distclean:
	rm -rf $(NGX_PATH) $(PCRE_PATH) $(PREFIX_PATH) t/.run
