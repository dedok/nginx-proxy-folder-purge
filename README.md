About
=====
`ngx_masks_storage` is `nginx` module which adds ability to store masks
for purging direcotory content from `FastCGI`, `proxy`, `SCGI` and `uWSGI` caches.

Notice:
(!) If you wish to see this module in action, then you need to patch NGINX
using `patches/*`. For example: patches/nginx.ver_1019004.patch

Build
=====

```bash
$ wget  https://nginx.org/download/nginx-1.19.4.tar.gz
$ tar xf nginx-1.19.4.tar.gz
$ mv nginx-1.19.4 nginx
$ cd nginx
$ patch -p1 <../nginx_folder_purge/patches/nginx.ver_1019004.patch
```

Testing
=======
The ideology behind the test is: a test is a logical unit which does test some external feature.
All tests could be found in the directory 't/'. nginx configurations could be
found in the direcory 'conf/'.

Note(!). Expects that nginx will be built within NGX_DEBUG option.

#Implemented tests:
-------------------
##t/add_mask_test.py:
---------------------
Allows adding random masks to the masks storage, and also the test checks the result of this action.
The test requires that nginx will be started with `conf/foreground_purge.conf`.
The goal of this test is checking that parallel requests will not affect `masks_storage` work.

##t/background_purge_test.py:
-----------------------------
Allows adding masks for the background purge:
adding some content to the nginx cache and checking the background purge execution.
The test requires that nginx will be started with `conf/background_purge.conf`.
The goal of this test is checking that the background purge work. 

##t/foreground_purge_test.py:
-----------------------------
Allows adding masks for the foreground purge:
adding some content to the nginx cache and checking the foreground purge execution.
The test requires that nginx will be started with `conf/foreground_purge.conf`
The goal of this test is checking that the foreground purge work.

##t/purge_folder_api_test.py:
-----------------------------
The test is checking PURGE api. That includes: checking some good cases, checking some bad cases.
The test requires that nginx will be started with `conf/foreground_purge.conf`.

##t/cache_purge_origin.js:
An origin server emulation. It helps to have a prod-like behavior.

##Run tests:
------------
Step 1: compile nginx with the module and with `ngx_cache_purge_module`.
Step 2: run ./t/cache_purge_origin.js - an origin server emulation.
Step 3: run the script: ./t/run.sh
Step 4: getting result.

Configuration directives
========================
masks_storage
-----------------
* **syntax**: `shared_memory_size max_allowed_masks_per_domain masks_storage_path [purger_sleep=MSEC purger_files=NUM purger_threshold=MSEC purger_server=STR purger_off]`
* **default**: `none`
* **context**: `http`

Enable masks_storage and background|foreground purger, if purger_off is set,
then background purger will not start (means it will be disable as a feature).

shared_memory_size - sets the size of the shared memory, it uses for storing masks and meta information. Example: 10m - 10 megabytes, 1g - 1 gygabyte.

max_allowed_masks_per_domain - sets max allowed masks per domain (number of
parallels running purge folder for one domain).

The domain will receive an error (an HTTP code 429), if the limit was reached.

masks_storage_path - sets a path to masks storage files.

Background purge settings

The special “Background purge process” process does purge files and also it does
clean of masks storage, if all files were purged. Since this operation cloud be
very heavy for disk I/O it has some configuration parameter.

The data is removed in iterations configured by purger_files,
purger_threshold, and purger_sleep parameters. During one
iteration no more than purger_files items are deleted (by default, 100).
The duration of one iteration is limited by the purger_threshold parameter
(by default, 200 milliseconds). Between iterations, a pause configured by
the purger_sleep parameter (by default, 50 milliseconds) is made.

Also, the module uses `purge module` for purging files, it calls `purge module`
using HTTP. This module has a parameter `purge_server` for configuring a `purge
module` endpoint.

Configuration directives
========================
foreground_purge [on|off]
-----------------------------
* **syntax**: `[on|off]`
* **default**: `on`
* **context**: `http`, `server`, `location`, `location if`

The option does enable or disable foreground purge. If the option is set, then
all GET request will not be able to update or clean nginx's cache.

Sample configuration (separate location syntax)
===============================================
```bash
    http {

        masks_storage 10m 20 /tmp/ purger_server=localhost:80;

        proxy_cache_path  /tmp/cache  keys_zone=tmpcache:10m;

        server {
            location / {
                proxy_pass         http://127.0.0.1:8000;
                proxy_cache        tmpcache;
                proxy_cache_key    $uri$is_args$args;
                proxy_folder_purge on;
            }
        }
    }
```

HTTP API
========

Header **X-Purge-Options** must be one of options
-------------------------------------------------

* **dump**: Dump gets last tasks after call invalidate command
* **flush**: Flush history at dump
* **delete**: deleting files from the cache server

See also
========
