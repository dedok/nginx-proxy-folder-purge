About
=====
`nginx-proxy-pattern-purge` is `nginx` module which adds feature to invalidate (purge) cache via pattern like: `/*`, `/abc/xyz.*`. All incomming purge operations persist on disk, means nginx migth be perform start, stop and even `sign -9`, nginx won't lost purge operations all restorable from the disk at the momemnt start.

Notice:
- If you wish to see this module in action, then you need to patch apply one of [patches](patches/*).
- This module not the best solution to purge a single object (file or cache entry).
- This module does not respect some of nginx's internal structure, so cache zone meta information (like fs_size, number of keys, etc) updated only via nginx's `cache manager`.

Build
=====
The module needs a patched `nginx`, see the [patches](patches/*). The tested
version is `nginx-1.19.4`, the `Makefile` does everything:

```bash
$ make        # downloads nginx and PCRE, applies the patch, builds nginx with the module
$ make test   # runs the tests against ./nginx/objs/nginx
```

The same by hand:

```bash
$ wget  https://nginx.org/download/nginx-1.19.4.tar.gz
$ tar xf nginx-1.19.4.tar.gz
$ mv nginx-1.19.4 nginx
$ cd nginx
$ patch -p1 <../patches/nginx.ver_1019004.patch
$ ./configure --add-module=../proxy_folder_purge
$ make
```

`nginx-1.19.4` needs the first `PCRE` library, not `PCRE2`. When it is not
installed, add `--with-pcre=<a directory with the PCRE sources>` to the
`configure`, the library is built together with `nginx`.

Testing
=======
The tests are [python scripts](./t), they need `python3` only. Every
`t/test_*.py` is a suite, for every test it starts its own origin server
([t/origin.py](./t/origin.py)) and its own `nginx` with the module, see
[t/harness.py](./t/harness.py).

```bash
$ ./t/run.sh                      # all suites
$ ./t/run.sh foreground           # the suites with "foreground" in the file name
$ TEST="crash host" ./t/run.sh    # only the tests with "crash" or "host" in the name
```

A failed test keeps its sandbox in `t/.run/`, the `nginx` log is there.
`NGINX_BIN` points the tests to another `nginx` binary.

Configuration examples
======================
A set of examples could be found in this repo, here is a short index:
- [demo configuration with comments](examples/nginx.conf)
- [foreground purge configuration example](t/conf/foreground.conf)
- [background purge configuration example](t/conf/background.conf)

Configuration directives
========================
folder_purge
-------------
* **syntax**: `shared_memory_size=SIZE max_allowed_masks_per_domain=INT masks_storage_path=PATH [purger_sleep=MSEC purger_files=NUM purger_threshold=MSEC purger_server=STR purger_off]`
* **default**: `none`
* **context**: `http`

Configuration for the on-disk and in-memory pattern (i.e. masks) storage for purge operations. If purger_off is configured, then background purge would be disabled, and to flush in-memory storage please use X-Purge-Options: flush, example:

```bash
$> curl -H"Host: HOST" -H"X-Purge-Options: flush" -XPURGE endpoint
```
where:
- shared_memory_size - sets the size of the shared memory, it uses for storing patterns and its meta information. Example: 10m - 10 megabytes, 1g - 1 gygabyte.
- max_allowed_masks_per_domain - sets max allowed _active_ performing patterns per domain, in other words it's a number of parallels running purge operation per domain (aka vhost). If limit is reached, the new operation performs an error (an HTTP code 429) until at leas one active operation is not done.
- masks_storage_path - sets a path to masks storage files.

Example of the configuration:
```
http {
	folder_purge
    	100m
    	30
    	.
    	purger_sleep=1
    	purger_files=1
    	purger_threshold=1
	;
}
```

### Background purge settings explanation
The first background purge is an nginx's process managed by nginx's master process, and it does deleting of the cache and also it does cleanup shared memory that uses for on demand (i.e. foreground purge) cache deletion. So there are two type of storage: in memory storage, that compare requested vhost and patterns, and on disk storage that uses by background purge and restoring process, most of `purger_` parameters should be used to tune disk I/O load.

Configuration directives
========================
proxy_folder_purge_on_request [on|off]
--------------------------------------
* **syntax**: `[on|off]`
* **default**: `on`
* **context**: `http`, `server`, `location`, `location if`

Enable or disable `foreground purge`. If it sets to `on`, then cache would be updated on demand during to perform of GET requests for the vhost.

```bash
    http {

        proxy_cache_path  /tmp/cache  keys_zone=tmpcache:10m;

        server {
            location / {
                proxy_pass         http://127.0.0.1:8000;
                proxy_cache        tmpcache;
                proxy_cache_key    $uri$is_args$args;
				proxy_folder_purge_on_request on;
            }
			location /off {
                proxy_folder_purge_on_request off;
                ...
			}
        }
    }
```

HTTP API
========
PURGE request
-------------
For trigger pattern purge required meet the following condition:
- the request SHOULD be HTTP PURGE, [HTTP DELETE](https://developer.mozilla.org/ru/docs/Web/HTTP/Reference/Methods/DELETE) is _not_ supported.
- the request SHOULD send [Host](https://developer.mozilla.org/ru/docs/Web/HTTP/Reference/Headers/Host) header directly or via SNI.
- the request SHOULD contains pattern in URI or via special HTTP header.

Example:
```bash
$> curl -XPURGE -H"Host: my.domain.com" 127.0.0.1:80/please/remove/from/*
```

Header **X-Purge-Options** must be one of options
-------------------------------------------------
* **dump**: gets all active purges
* **flush**: flushes all active purges from the shared memory

See also
========
