# nginx-proxy-folder-purge

Purge the cache of nginx by pattern: `/img/*`, `/videos/2026/*.mp4`, `*.jpg`.

[![tests](https://github.com/dedok/nginx-proxy-folder-purge/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/dedok/nginx-proxy-folder-purge/actions/workflows/tests.yml?query=branch%3Amain)
[![nginx](https://img.shields.io/badge/nginx-1.19.4%20--%201.31.10-blue)](https://nginx.org/)
[![License: BSD-2-Clause](https://img.shields.io/badge/License-BSD_2--Clause-blue.svg)](LICENSE)

## Why

The open source nginx has no purge at all. `ngx_cache_purge` removes one
object per request. NGINX Plus, the commercial nginx, purges by the start of
a key.

This module takes a pattern instead of one object:

```bash
curl -XPURGE 'https://cdn.example.com/img/*'
```

- **Patterns where they belong.** A folder, an extension, any `fnmatch`
  pattern: `/img/*` covers `/img/a.png` and `/img/2026/b.png`.
- **A purge survives a restart.** Every purge is written to the disk before
  it is answered. nginx can be stopped, reloaded or killed, the purge goes on
  from where it was.
- **A long purge does not stall nginx.** The files are removed in small
  portions by nginx's own `cache manager` process, so nginx's cache
  maintenance goes on between them.
- **Two purges in one.** The files are removed in the background, and an
  object asked for while its purge is active is renewed at once.

## Try it in two minutes

The demo is one nginx with two origins and a caching proxy in front of them.
It needs `make`, a C compiler, `curl` and `bzip2`.

```bash
git clone https://github.com/dedok/nginx-proxy-folder-purge
cd nginx-proxy-folder-purge
make                                   # nginx 1.19.4 with the module
mkdir -p /tmp/fp-demo/logs
./nginx/objs/nginx -p /tmp/fp-demo -c "$PWD/examples/nginx.conf"
```

nginx stays in the foreground. In another terminal, three requests fill the
cache and the fourth one is served from it:

```bash
curl -sD- http://localhost:8082/folder/a   # X-Cache-Status: MISS
curl -sD- http://localhost:8082/folder/b   # MISS
curl -sD- http://localhost:8082/other/c    # MISS
curl -sD- http://localhost:8082/folder/a   # HIT
```

Purge a folder and ask again. The quotes keep the shell from expanding the
asterisk:

```bash
curl -sD- -XPURGE 'http://localhost:8082/folder/*'
curl -sD- http://localhost:8082/folder/b   # BYPASS: renewed at once
curl -sD- http://localhost:8082/other/c    # HIT: the mask is for /folder/
```

The background purge removes the files of `/folder/` from the cache, and its
steps are in the log:

```bash
tail -n 20 /tmp/fp-demo/logs/error.log
```

The active purges can be listed at any moment:

```bash
curl -s -XPURGE -H 'X-Purge-Options: dump' http://localhost:8082/
```

In a hurry? The configuration of the demo is
[examples/nginx.conf](examples/nginx.conf), and every directive of it is
explained in [Configuration](#configuration). Read
[When to use it](#when-to-use-it) before you put it under production
traffic.

## How it works

A purge is a mask: a pattern plus the time of the purge. It lives in two
places, in the shared memory of nginx and in a file, and it is dropped when
the purge is over.

```text
PURGE /img/*

foreground purge                     background purge
in the worker, on the request        in the cache manager process
GET /img/a.png is renewed from       the files of /img/ are removed,
the origin at once                   a portion at a time
```

**The background purge** removes the cache files. It runs in nginx's
`cache manager` process and looks at the files of the cache directory, a
portion at a time: it reads the key a cache file begins with and removes the
file when a mask covers it.

**The foreground purge** renews an object on the request. The variable
`$folder_purge_bypass` is `1` for a request whose cached copy is covered by
an active mask: the copy is not taken from the cache, and the one fetched
from the origin is cached as usual.

## When to use it

Use it when a change on the origin invalidates many cached objects at once:
a folder of images, the segments of a video, the pages of a shop.

Use something else when:

- **One object has to go.** `ngx_cache_purge` is made for that, this module
  is not.
- **The cache key starts with a scheme**, like `$scheme://$host$uri`. The
  purges read the hostname and the url out of the key, and a key of that
  form has its scheme read as the hostname, so no mask is applied. The keys
  the module reads are listed in
  [How a mask is matched](#how-a-mask-is-matched).
- **The bookkeeping of the cache zone has to be exact at once.** The module
  removes cache files itself. The size of the zone and the number of its
  keys are brought up to date by nginx's `cache manager`, the way it is done
  for expired files.

The times are compared with a resolution of one second: an object that was
cached in the same second as its purge is renewed, or removed, one more time,
and the next request fetches it again.

## Configuration

The demo in [examples/nginx.conf](examples/nginx.conf) has every directive of
the module. The smallest working configuration of a location that caches and
purges:

```nginx
http {
    proxy_folder_purge  on  from  10.0.0.0/8;

    proxy_cache_path  /var/cache/nginx/cache  levels=1:2  keys_zone=c:10m;

    folder_purge  100m  30  /var/cache/nginx;

    server {
        listen              8082;

        proxy_cache         c;
        proxy_cache_key     $host:$uri;
        proxy_cache_valid   200  10m;

        proxy_folder_purge_cache_path  cache;

        location / {
            proxy_cache_bypass  $folder_purge_bypass;
            add_header          X-Cache-Status  $upstream_cache_status  always;
            proxy_pass          http://origin;
        }
    }
}
```

- `proxy_folder_purge on from 10.0.0.0/8` switches the module on and says
  that only this network may send PURGE requests. See
  [proxy_folder_purge](#proxy_folder_purge).
- `folder_purge 100m 30 /var/cache/nginx` is the storage of the masks: 100 MB
  of shared memory, at most 30 masks per hostname at the same time, the
  directory to keep them in. See [folder_purge](#folder_purge).
- `proxy_folder_purge_cache_path cache` names the cache the background purge
  works on. It is the last part of the directory of the `proxy_cache_path`.
  Without it the background purge removes nothing, and the module logs a
  warning for every purge it accepts.
- `proxy_cache_key $host:$uri` is a layout of the key the purges read.
- `proxy_cache_bypass $folder_purge_bypass` switches the foreground purge on
  for the location, see [$folder_purge_bypass](#folder_purge_bypass).
- `add_header X-Cache-Status $upstream_cache_status always` shows in every
  response where its copy came from: `MISS`, `HIT` or `BYPASS`.

The purge is not only for `proxy_cache`. It works the same way with
`fastcgi_cache`, `uwsgi_cache` and `scgi_cache`: the variable goes into
`fastcgi_cache_bypass` and so on.

## Directives

### proxy_folder_purge

* **syntax**: `off` | `on | METHOD [from all | from ADDRESS ...]`
* **default**: `off`
* **context**: `http`, `server`, `location`

Switches the module on where purge requests have to be accepted, and says
who may send them.

- `on` makes `PURGE` the purge method. Another word makes that word the
  purge method: after `proxy_folder_purge MPURGE;` the requests are sent
  with `curl -XMPURGE`.
- `from all` lets every client purge. It is the same as no `from`.
- `from` followed by addresses or networks lets only these clients purge,
  IPv4 and IPv6. A purge request from any other client gets `403`. The
  address is the one of the connection. With `set_real_ip_from` configured,
  nginx replaces it with the address from the header: list your load
  balancers there and nobody else.

```nginx
proxy_folder_purge  on  from  10.0.0.0/8  192.168.0.0/16  2001:db8::/32;
```

The servers and locations below the directive accept purge requests from
then on. A location that accepts them needs a handler of its own, like
`proxy_pass`: the requests with other methods go to that handler as before.

### folder_purge

* **syntax**: `shared_memory_size max_masks_per_hostname masks_storage_path [purger_sleep=MSEC purger_files=NUM purger_threshold=MSEC purger_poll=MSEC startup_lock_delay=SEC purger_off]`
* **default**: none
* **context**: `http`

The storage of the masks: in the shared memory, for the foreground purge, and
in files, for the background purge and for restoring when nginx starts.

- `shared_memory_size` is the size of the shared memory, `100m` for example.
- `max_masks_per_hostname` is how many masks a hostname can have at the same
  time. A purge that would exceed it gets `429` until one of the masks is
  done.
- `masks_storage_path` is the directory the files are kept in. Its
  `masks_storage` subdirectory is used; a relative path is relative to the
  prefix of nginx. The temporary files of a dump go to its `masks_storage_tmp`
  subdirectory.

The options of the background purge:

- `purger_sleep` is the pause between two portions while there is something
  to purge. The default is `50ms`.
- `purger_files` is how many cache files one portion looks at at most. The
  default is `100`.
- `purger_threshold` is how long one portion may take. The default is `20ms`,
  `0` means no limit.
- `purger_poll` is how often the purger looks for new masks when it has
  nothing to do. The default is `1s`.
- `startup_lock_delay` is how long to wait before a message says that another
  nginx has the lock of the storage, see
  [The background purge](#the-background-purge). The default is `120`
  seconds, `off` means no lock.
- `purger_off` switches the background purge off: the masks are restored when
  nginx starts, and nothing is removed.

```nginx
http {
    folder_purge  100m  30  /var/cache/nginx
        purger_sleep=50ms
        purger_files=100
        purger_threshold=20ms
        purger_poll=1s;
}
```

### proxy_folder_purge_on_request

* **syntax**: `on` | `off`
* **default**: `on`
* **context**: `http`, `server`, `location`, `location if`

Switches the foreground purge on or off. It has an effect only in the
locations that have `$folder_purge_bypass` in their `proxy_cache_bypass`.

### proxy_folder_purge_cache_path

* **syntax**: `name`
* **default**: none
* **context**: `server`, `location`, `location if`

The name of the cache the background purge works on: the last part of the
directory of the `proxy_cache_path`. The background purge removes the files
of the directories with this name. Without it the background purge removes
nothing, and the module logs a warning for every purge it accepts where the
directive is empty, as long as the background purge is switched on.

```nginx
proxy_cache_path  /var/cache/nginx/img  levels=1:2  keys_zone=img:10m;

server {
    proxy_cache  img;
    proxy_folder_purge_cache_path  img;
}
```

### $folder_purge_bypass

The variable is `1` for a request whose cached copy is covered by an active
mask and is not newer than that purge. For any other request it is empty. Add
it to `proxy_cache_bypass`, or to the `*_cache_bypass` of another upstream
module, of the locations that have to purge:

```nginx
location / {
    proxy_cache_bypass  $folder_purge_bypass;
    proxy_pass          http://origin;
}
```

## PURGE request

A purge request carries the mask.

* **The method** is the one named by `proxy_folder_purge`, `PURGE` by
  default.
* **The `Host` header** says which hostname the mask belongs to. A mask made
  for `cdn.example.com` is applied to the requests for that hostname only.
* **The mask** is the uri of the request, or the `X-Purge-Key` header when
  the request has one.

```bash
curl -XPURGE -H 'Host: cdn.example.com' 'http://127.0.0.1:8082/img/*'
curl -XPURGE -H 'Host: cdn.example.com' -H 'X-Purge-Key: /img/*.jpg' \
     'http://127.0.0.1:8082/purge'
```

The answers:

- `200` with `{"status": "ok"}`: the mask is accepted.
- `403`: the client is not in the `from` list of `proxy_folder_purge`.
- `429`: the hostname has `max_masks_per_hostname` masks already.
- `503`: there is no `folder_purge` in the `http` block, or nginx runs with
  `master_process off`.

### X-Purge-Options

The header `X-Purge-Options` works with any uri:

- `dump` answers with the active purges as JSON.
- `flush` drops all the active purges from the shared memory.

```bash
curl -s -XPURGE -H 'Host: cdn.example.com' -H 'X-Purge-Options: dump' \
     'http://127.0.0.1:8082/'
```

## How a mask is matched

A mask is a pattern for urls, `*` and `?` have their `fnmatch` meaning, and
it covers the urls of its folder at any depth: `/img/*` covers `/img/a.png`
and `/img/2026/b.png`.

Both purges read the url of an object out of its cache key: the foreground
purge out of the key of the request, the background purge out of the key a
cache file begins with. So the two decide the same about an object.

The hostname of a key is the text before the last `:` before its first `/`,
there is none when the key has no `:` there. The url starts at that `/` and
ends at `|`, at a new line or at `[`. A mask belongs to the hostname of its
PURGE request: the foreground purge applies it to the reads that come with
that hostname, the background purge removes the files whose key names that
hostname, and every file with the url when the key names none.

`$host:$uri` is the layout the module is tested with.

```nginx
proxy_cache_key $host:$uri;              # hostname $host, url $uri
proxy_cache_key $uri;                    # no hostname in the key
proxy_cache_key $host:$uri$is_args$args; # the url has the arguments in it
```

Whatever the key carries after the uri is a part of the url for both purges:
a mask with a fixed tail, `*.jpg`, does not cover `/a.jpg?v=2`, and a mask
can be made for the arguments. A key that starts with a scheme,
`$scheme://$host$uri`, has the scheme read as its hostname, so no mask is
applied to the objects of such a cache.

## The background purge

The background purge is the manager of the masks storage path, so it is
nginx's `cache manager` process that does it, and the master process starts,
respawns and stops the cache manager as it always does.

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

## Build and test

```bash
make          # downloads nginx 1.19.4 and builds it with the module
make test     # runs the tests against ./nginx/objs/nginx
```

The version of nginx is chosen with `NGX_VERSION`; `1.19.4`, `1.30.8` and
`1.31.10` are known to the `Makefile`:

```bash
make NGX_VERSION=1.31.10
make test NGX_VERSION=1.31.10
```

The same by hand:

```bash
wget  https://nginx.org/download/nginx-1.19.4.tar.gz
tar xf nginx-1.19.4.tar.gz
mv nginx-1.19.4 nginx
cd nginx
./configure --add-module=../proxy_folder_purge
make
```

`nginx-1.19.4` needs the `PCRE` library, not `PCRE2`. When it is not
installed, add `--with-pcre=<a directory with the PCRE sources>` to the
`configure`, the library is built together with nginx. The other versions use
the `PCRE2` of the system.

The tests are [python scripts](./t), they need `python3` only. Every
`t/test_*.py` is a suite, for every test it starts its own origin server
([t/origin.py](./t/origin.py)) and its own nginx with the module, see
[t/harness.py](./t/harness.py).

```bash
./t/run.sh                      # all suites
./t/run.sh foreground           # the suites with "foreground" in the file name
TEST="crash host" ./t/run.sh    # only the tests with "crash" or "host" in the name
```

A failed test keeps its sandbox in `t/.run/`, the nginx log is there.
`NFP_KEEP=1` keeps the sandboxes of the passed tests too. `NGINX_BIN` points
the tests to another nginx binary.

[GitHub Actions](.github/workflows/tests.yml) builds the module with
`1.19.4`, `1.30.8` and `1.31.10` on Linux and on macOS and runs the tests.
On Linux the tests also run against a build with `-O2` and without the debug
logging of nginx, and against one with AddressSanitizer in the module.

## Compatibility

- nginx `1.19.4`, `1.30.8` and `1.31.10`, tested on every push. The module
  needs no patch of nginx.
- Linux and macOS are tested. The module does not talk to the event system of
  nginx itself, so the BSDs should work the way macOS does; tell us if they
  do not.
- `master_process on`, which is the default. Without the master process
  there is no cache manager, and PURGE requests get `503`.

## License

BSD-2-Clause, see [LICENSE](LICENSE). `uthash.h` in `proxy_folder_purge/` is
by Troy D. Hanson, under the BSD-1-Clause license.

## See also

- [`ngx_cache_purge`](https://github.com/FRiCKLE/ngx_cache_purge): purges one
  object by its key.
- [Purging content from the cache, NGINX Plus](https://docs.nginx.com/nginx/admin-guide/content-cache/content-caching/#purging-content-from-the-cache):
  the purge of the commercial nginx.
