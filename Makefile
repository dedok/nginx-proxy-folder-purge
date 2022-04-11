
#
# Copyright (C) BSDv2
#

.PHONY = all

NGX_PATH      = ./nginx
NGX_CONFIGURE = ./auto/configure
## Some versions of nginx have different path of the configure,
## following lines are handle it {{
ifeq ($(shell [ -e "$(NGX_PATH)/configure" ] && echo 1 || echo 0 ), 1)
NGX_CONFIGURE=./configure
endif
## }}

PREFIX_PATH = $(PWD)/test-root
MODULE_PATH = $(PWD)

DEV_CFLAGS  = -ggdb3 -O0 -Wall -Werror -I /usr/local/Cellar/openssl/1.0.2j/include/

all: build

build:
	rm -f $(NGX_PATH)/objs/nginx
	$(MAKE) -C $(NGX_PATH)

# Note: Debug only
configure:
#	cd $(NGX_PATH) && \
#		git apply $(MODULE_PATH)/patches/nginx.ver_1019004.patch
	cd $(NGX_PATH) && \
		$(NGX_CONFIGURE) \
						--with-cc-opt="$(DEV_CFLAGS)" \
						--with-debug \
						--prefix=$(PREFIX_PATH) \
						--with-http_slice_module \
						--add-module=$(MODULE_PATH)/masks_storage \
						--add-module=$(MODULE_PATH)/proxy_folder_purge

#	mkdir -p $(PREFIX_PATH)/conf $(PREFIX_PATH)/logs
#	cp -Rf $(NGX_PATH)/conf/* $(PREFIX_PATH)/conf
#	cp -f $(MODULE_PATH)/conf/*.conf $(PREFIX_PATH)/conf/

