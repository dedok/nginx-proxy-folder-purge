About
=====
`nginx-proxy-pattern-purge` is `nginx` module which adds feature to invalidate (purge) cache via pattern like: `/*`, `/abc/xyz.*`. All incomming purge operations persist on disk, means nginx migth be perform start, stop and even `sign -9`, nginx won't lost purge operations all restorable from the disk at the momemnt start.

Notice:
- The foreground purge is switched on by `proxy_cache_bypass $folder_purge_bypass;`, see [$folder_purge_bypass](#folder_purge_bypass).
- The background purge runs in nginx's `cache manager` process and deletes cache files. `open_file_cache` keeps nginx serving a deleted file for some time, see [open_file_cache](#open_file_cache).
- This module not the best solution to purge a single object (file or cache entry).
- This module does not respect some of nginx's internal structure, so cache zone meta information (like fs_size, number of keys, etc) updated only via nginx's `cache manager`.

Build
=====
```bash
$ make        # builds nginx-1.19.4 with the module
$ make test   # runs the tests against ./nginx/objs/nginx
```

The version of nginx is chosen with `NGX_VERSION`:

```bash
$ make NGX_VERSION=1.30.8
$ make test NGX_VERSION=1.30.8
```

The same by hand:

```bash
$ wget  https://nginx.org/download/nginx-1.19.4.tar.gz
$ tar xf nginx-1.19.4.tar.gz
$ mv nginx-1.19.4 nginx
$ cd nginx
$ ./configure --add-module=../proxy_folder_purge
$ make
```

`nginx-1.19.4` needs the `PCRE` library, not `PCRE2`. When it is not installed,
add `--with-pcre=<a directory with the PCRE sources>` to the `configure`, the
library is built together with `nginx`. The other versions use the `PCRE2` of
the system.

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
`NFP_KEEP=1` keeps the sandboxes of the passed tests too. `NGINX_BIN` points
the tests to another `nginx` binary.

[GitHub Actions](.github/workflows/tests.yml) builds the module with
`1.19.4`, `1.30.8` and `1.31.10` on Linux and on macOS and runs the tests.
On Linux the tests also run against a build with `-O2` and without the debug
logging of `nginx`, and against one with AddressSanitizer in the module.

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
* **syntax**: `shared_memory_size max_allowed_masks_per_domain masks_storage_path [purger_sleep=MSEC purger_files=NUM purger_threshold=MSEC purger_poll=MSEC startup_lock_delay=SEC purger_off]`
* **default**: `none`
* **context**: `http`

Configuration for the on-disk and in-memory pattern (i.e. masks) storage for purge operations. If purger_off is configured, then background purge would be disabled, and to flush in-memory storage please use X-Purge-Options: flush, example:

```bash
$> curl -H"Host: HOST" -H"X-Purge-Options: flush" -XPURGE endpoint
```
where:
- shared_memory_size - sets the size of the shared memory, it uses for storing patterns and its meta information. Example: 10m - 10 megabytes, 1g - 1 gygabyte.
- max_allowed_masks_per_domain - sets max allowed _active_ performing patterns per domain, in other words it's a number of parallels running purge operation per domain (aka vhost). If limit is reached, the new operation performs an error (an HTTP code 429) until at leas one active operation is not done.
- masks_storage_path - the directory the masks are stored in: its `masks_storage` subdirectory is used. Its `masks_storage_tmp` subdirectory is for the temporary files of a dump.

Options of the background purge:
- purger_sleep - a pause between two portions of the purge while there is something to purge. The default is `50ms`.
- purger_files - how many cache files are looked at in one portion at most. The default is `100`.
- purger_threshold - for how long one portion may go on. The default is `20ms`, `0` means no limit of time.
- purger_poll - how often the purger looks for new masks when it has nothing to do. The default is `1s`.
- startup_lock_delay - how long to wait before a message says that the lock of the masks storage is taken by another nginx. The default is `120` seconds, `off` means no lock at all.
- purger_off - switches the background purge off: the masks are restored when nginx starts, and nothing is deleted.

Example of the configuration:
```
http {
    folder_purge
        100m
        30
        /var/cache/nginx
        purger_sleep=50ms
        purger_files=100
        purger_threshold=20ms
        purger_poll=1s
    ;
}
```

### Background purge
The background purge is the manager of the masks storage path, so it is
nginx's `cache manager` process that does it, and the master process starts,
respawns and stops the cache manager as it always does. There are two storages behind it: the masks are compared
with the requests in the shared memory, and they are kept on the disk for the
background purge and for restoring when nginx starts.

A purge is done in portions: at most `purger_files` cache files, or
`purger_threshold` of time, then the purger says when to call it again. The
cache manager has its own work to do between the calls, so a long purge does
not keep nginx's cache maintenance waiting. One thing is not cut into
portions: reading the list of files of a directory. A cache directory with
hundreds of thousands of files in it, that is a cache without `levels`, stops
the cache manager for the time of that; `levels=1:2` keeps it short.

The purger saves its position once in a second. When nginx stops, is reloaded
or crashes in the middle of a purge, the next cache manager goes on from
there: the queue file of the masks and the position are kept until the purge
is over.

The lock file of the masks storage, `.lock`, makes it one purger per masks
storage, for example while a new nginx and the old one are running together.

A purge that makes the cache manager stop is given up when the cache manager
has been stopped 3 times in a row in the middle of it: otherwise a cache file
that crashes the cache manager would also stop nginx's own cache maintenance
that often. An `alert` in the log says which purge it is and where the cache
manager stopped, the masks of the purge are dropped, and the purges that come
after go on. A start of nginx, or a new configuration, resets the count: a
purge that goes on after a reload is not a crash.

### open_file_cache
The background purge deletes cache files. With `open_file_cache` switched on,
nginx keeps the descriptors of open files, cache files included, and goes on
serving a deleted file from the kept descriptor until `open_file_cache_valid`
runs out, 60 seconds by default.

`open_file_cache_events on` makes nginx notice the deletion at once with the
`kqueue` event method only, that is on FreeBSD and on macOS. On Linux do not
switch `open_file_cache` on for the locations that serve from the cache. The
module logs a warning when it sees a location with `open_file_cache` where
the deleted file would go on being served.

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
                proxy_cache_bypass $folder_purge_bypass;
				proxy_folder_purge_on_request on;
            }
			location /off {
                proxy_folder_purge_on_request off;
                ...
            }
        }
    }
```

$folder_purge_bypass
--------------------
The variable does the foreground purge. Add it to `proxy_cache_bypass` (or to
the `*_cache_bypass` of another upstream module) of the locations that have to
purge.

The variable is `1` for a request whose cached copy is covered by an active
mask and is not newer than that purge: the copy is not taken from the cache,
the one fetched from the origin is cached as usual. For any other request the
variable is empty. Without the directive a purged object is served from the
cache, i.e. `proxy_folder_purge_on_request` has nothing to switch on there.

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
