#!/usr/bin/env python3

#
# (C) BSD, Vas Soshnikov
#

#
# Description:
# The foreground purge: a request for an object that is covered by an active
# mask is not served from the cache, the object is fetched from the origin
# again ("renewed on demand").
#
# It is the $folder_purge_bypass variable that does it: a location purges
# when it has "proxy_cache_bypass $folder_purge_bypass".
#
# The background purger is off here (t/conf/foreground.conf): nothing is
# deleted from the disk and masks stay active until they are flushed.
#
# Run:  ./t/run.sh  |  python3 t/test_foreground_purge.py [name fragments]
#
# Purge timestamps and cache dates have one-second resolution and an object
# counts as purged while its cache date is <= the purge time. Tests that
# cache an object *after* a purge use ctx.purge_across_second(), so that
# object is newer than the purge.
#

import os
import re
import time

import harness
from harness import fail

HOST_A = 'host_a.example'
HOST_B = 'host_b.example'


def masks_of(ctx, mask):
    return [m for m in ctx.dump() if m['mask'] == mask]


def test_hit_is_served_from_cache(ctx):
    """Without any mask the second request is a hit, the origin is asked once."""
    first = ctx.expect('/hit/a.txt', 'MISS')
    ctx.expect('/hit/a.txt', 'HIT', first.body)

    if ctx.origin_hits('/hit/a.txt') != 1:
        fail('the origin was asked %d times for /hit/a.txt, expected 1' % (
            ctx.origin_hits('/hit/a.txt')))


def test_purge_renews_cached_object(ctx):
    """An object covered by a mask is fetched from the origin again."""
    cached = ctx.expect('/renew/a.txt', 'MISS').body
    ctx.purge_ok('/renew/*')

    fresh = ctx.expect('/renew/a.txt', 'BYPASS')

    if fresh.body == cached:
        fail('GET /renew/a.txt after the purge: expected a fresh body, '
             'got the cached one %r' % cached)

    if ctx.origin_hits('/renew/a.txt') != 2:
        fail('the origin was asked %d times for /renew/a.txt, expected 2' % (
            ctx.origin_hits('/renew/a.txt')))


def test_renewed_object_is_cached_again(ctx):
    """The renewed copy is served from the cache by the following requests."""
    ctx.expect('/renewed/a.txt', 'MISS')
    ctx.purge_across_second('/renewed/*')

    fresh = ctx.expect('/renewed/a.txt', 'BYPASS').body

    ctx.expect('/renewed/a.txt', 'HIT', fresh)


def test_new_purge_renews_the_renewed_object(ctx):
    """A copy that answered one purge is renewed again by a later purge.

    A copy known to be newer than a purge is remembered, so the cache file
    is not read again for the following requests: what is remembered must
    not outlive that purge.
    """
    cached = ctx.expect('/twice/a.txt', 'MISS').body

    for nth in ('first', 'second'):
        ctx.purge_across_second('/twice/*')

        fresh = ctx.expect('/twice/a.txt', 'BYPASS')

        if fresh.body == cached:
            fail('GET /twice/a.txt after the %s purge: expected a fresh '
                 'body, got the previous one %r' % (nth, cached))

        ctx.expect('/twice/a.txt', 'HIT', fresh.body)
        cached = fresh.body

    if ctx.origin_hits('/twice/a.txt') != 3:
        fail('the origin was asked %d times for /twice/a.txt, expected 3: '
             'once per purge and once for the first request' % (
                 ctx.origin_hits('/twice/a.txt')))


def test_object_cached_after_purge_is_kept(ctx):
    """An object cached after the purge is newer than it and is not renewed."""
    ctx.purge_across_second('/later/*')

    body = ctx.expect('/later/b.txt', 'MISS').body

    ctx.expect('/later/b.txt', 'HIT', body)


def test_exact_mask_renews_its_object(ctx):
    """A mask without wildcards renews exactly that object."""
    cached = ctx.expect('/exact/a.txt', 'MISS').body
    ctx.purge_ok('/exact/a.txt')

    if ctx.expect('/exact/a.txt', 'BYPASS').body == cached:
        fail('GET /exact/a.txt after the purge: expected a fresh body, got '
             'the cached one %r' % cached)


def test_exact_mask_keeps_other_objects(ctx):
    """A mask without wildcards leaves other objects of the folder alone."""
    bodies = ctx.prime('/exact2/a.txt', '/exact2/b.txt')
    ctx.purge_across_second('/exact2/a.txt')

    ctx.expect('/exact2/b.txt', 'HIT', bodies['/exact2/b.txt'])


def test_folder_mask_renews_all_objects_below_it(ctx):
    """A folder mask renews files of any depth and folder URLs as well."""
    paths = ['/tree/', '/tree/child.txt', '/tree/sub/deeper/', '/tree/sub/deep/file.txt']
    bodies = ctx.prime(*paths)
    ctx.purge_ok('/tree/*')

    for path in paths:
        if ctx.expect(path, 'BYPASS').body == bodies[path]:
            fail('%s: expected a fresh body after the purge, got the cached '
                 'one' % path)


def test_folder_mask_keeps_look_alike_paths(ctx):
    """A folder mask does not renew paths that only look like the folder."""
    kept = ['/look', '/lookalike/file.txt', '/elsewhere/look/file.txt',
            '/elsewhere/file.txt']
    bodies = ctx.prime(*kept)
    ctx.purge_across_second('/look/*')

    for path in kept:
        ctx.expect(path, 'HIT', bodies[path])


def test_extension_mask_renews_matching_objects(ctx):
    """A mask with a wildcard in the file name renew objects of that type."""
    matching = ['/ext/t1.html', '/ext/t2.html']
    bodies = ctx.prime(*matching)
    ctx.purge_ok('/ext/*.html')

    for path in matching:
        if ctx.expect(path, 'BYPASS').body == bodies[path]:
            fail('%s: expected a fresh body after the purge, got the cached '
                 'one' % path)


def test_extension_mask_keeps_other_objects(ctx):
    """Objects of other types, or with a similar name, stay cached."""
    kept = ['/ext2/', '/ext2/html', '/ext2/t2.htm', '/ext2/t2.tml',
            '/ext2/t2html', '/ext2/t2.txt', '/ext2/t2']
    bodies = ctx.prime(*kept)
    ctx.purge_across_second('/ext2/*.html')

    for path in kept:
        ctx.expect(path, 'HIT', bodies[path])


def test_purge_renews_objects_of_its_host(ctx):
    """A purge sent for a host renews objects of that host."""
    ctx.expect('/host/a.txt', 'MISS', host=HOST_A)
    ctx.purge_across_second('/host/*', host=HOST_A)

    ctx.expect('/host/a.txt', 'BYPASS', host=HOST_A)


def test_purge_keeps_objects_of_other_hosts(ctx):
    """The same URL of another host is another object, it stays cached."""
    body = ctx.expect('/host2/a.txt', 'MISS', host=HOST_B).body
    ctx.purge_across_second('/host2/*', host=HOST_A)

    ctx.expect('/host2/a.txt', 'HIT', body, host=HOST_B)


def test_mask_in_x_purge_key_header(ctx):
    """The mask can be passed in the X-Purge-Key header instead of the URI."""
    ctx.expect('/header/a.txt', 'MISS')
    ctx.purge_across_second('/not/an/object', key='/header/*')

    ctx.expect('/header/a.txt', 'BYPASS')

    if len(masks_of(ctx, '/header/*')) != 1:
        fail('expected the mask "/header/*" in the dump, got %r' % ctx.dump())


def test_purge_is_off_where_on_request_is_off(ctx):
    """Masks are accepted, but objects are served from the cache."""
    bodies = ctx.prime('/off/a.txt', '/off/b.txt')
    ctx.purge_across_second('/off/*')

    if len(masks_of(ctx, '/off/*')) != 1:
        fail('expected the mask "/off/*" in the dump, got %r' % ctx.dump())

    ctx.expect('/off/a.txt', 'HIT', bodies['/off/a.txt'])
    ctx.expect('/off/b.txt', 'HIT', bodies['/off/b.txt'])


def test_bypass_variable_is_set_for_the_renewing_request_only(ctx):
    """$folder_purge_bypass is "1" for the request that renews an object only."""
    first = ctx.expect('/var/a.txt', 'MISS')
    ctx.purge_across_second('/var/*')

    renewed = ctx.expect('/var/a.txt', 'BYPASS')
    cached = ctx.expect('/var/a.txt', 'HIT', renewed.body)

    for what, r, expected in (('the first request', first, None),
                              ('the request that renews the purged object',
                               renewed, '1'),
                              ('the request served from the cache', cached,
                               None)):
        if r.headers.get('x-folder-purge-bypass') != expected:
            fail('%s: expected X-Folder-Purge-Bypass %r, got %r' % (
                what, expected, r.headers.get('x-folder-purge-bypass')))


def test_purge_needs_proxy_cache_bypass(ctx):
    """A purged object is served from the cache where the directive is missing."""
    cached = ctx.expect('/unconfigured/a.txt', 'MISS').body
    ctx.purge_across_second('/unconfigured/*')

    r = ctx.expect('/unconfigured/a.txt', 'HIT', cached)

    # The variable still asks for the bypass, the location just does not use it
    if r.headers.get('x-folder-purge-bypass') != '1':
        fail('GET /unconfigured/a.txt: expected X-Folder-Purge-Bypass 1, '
             'got %r' % r.headers.get('x-folder-purge-bypass'))


def test_purge_reads_the_object_out_of_the_cache_key(ctx):
    """The foreground purge reads the url and the hostname out of the cache key.

    It reads them the way the background purge reads them out of the keys of
    the cache files, so the two decide the same about an object. The
    hostname of a key is the text before the last ":" before its first "/",
    and a mask belongs to one hostname. The key of the /keyed/ location
    starts with a scheme, so its hostname is read as "http": the mask made
    for purge_folder is not applied to the object, and the background purge
    would not remove the file of the object either.
    """
    cached = ctx.expect('/keyed/a.txt', 'MISS').body
    ctx.purge_across_second('/keyed/*')

    ctx.expect('/keyed/a.txt', 'HIT', cached)


def test_mask_is_compared_with_the_url_of_the_cache_key(ctx):
    """The mask has to cover the url of the cache key, arguments included.

    The key of the /args/ location has the arguments of the request after
    the uri. The background purge compares the mask with the same text.
    """
    bodies = ctx.prime('/args/a.jpg?v=2', '/args/b.txt?n=1')
    ctx.purge_across_second('/args/*.jpg')
    ctx.purge_across_second('/args/b*1')

    # The mask ends with ".jpg", the url of the key goes on after it
    ctx.expect('/args/a.jpg?v=2', 'HIT', bodies['/args/a.jpg?v=2'])

    # The mask covers the arguments, the uri of the request has none
    cached = bodies['/args/b.txt?n=1']
    fresh = ctx.expect('/args/b.txt?n=1', 'BYPASS')

    if fresh.body == cached:
        fail('GET /args/b.txt?n=1 after the purge: expected a fresh body, '
             'got the cached one %r' % cached)


def test_expired_object_is_left_to_nginx(ctx):
    """An expired object is renewed by nginx itself, the purge does not step in."""
    ctx.expect('/ttl/a.txt', 'MISS')
    ctx.purge_across_second('/ttl/*')

    # longer than proxy_cache_valid of the /ttl/ location
    time.sleep(2.5 * harness.TIMEOUT_SCALE)

    ctx.expect('/ttl/a.txt', 'EXPIRED')
    ctx.expect('/ttl/a.txt', 'HIT')


def test_masks_survive_nginx_restart(ctx):
    """Masks are restored from the disk when nginx starts."""
    cached = ctx.expect('/restart/a.txt', 'MISS').body
    ctx.purge_across_second('/restart/*')

    ctx.restart()

    # The masks are restored by a separate process right after the start.
    def renewed():
        r = ctx.get('/restart/a.txt')
        return r if r.cache_status == 'BYPASS' else None

    fresh = ctx.wait_until(
        renewed, 10, 'renewal of the purged object after the restart')

    if fresh.body == cached:
        fail('GET /restart/a.txt after the restart: expected a fresh body, '
             'got the one cached before the purge %r' % cached)

    ctx.expect('/restart/a.txt', 'HIT', fresh.body)


def test_flush_drops_masks(ctx):
    """X-Purge-Options: flush forgets all masks, objects stay cached."""
    cached = ctx.expect('/flush/a.txt', 'MISS').body
    ctx.purge_ok('/flush/*')

    if len(masks_of(ctx, '/flush/*')) != 1:
        fail('expected the mask "/flush/*" in the dump, got %r' % ctx.dump())

    ctx.flush()

    if ctx.dump() != []:
        fail('expected an empty dump after the flush, got %r' % ctx.dump())

    ctx.expect('/flush/a.txt', 'HIT', cached)


def test_purger_off_keeps_files_and_masks(ctx):
    """With purger_off nothing is deleted and masks are not consumed."""
    ctx.prime('/offbg/a.txt', '/offbg/b.txt')
    ctx.purge_ok('/offbg/*')

    files = ctx.cache_count()
    time.sleep(7 * harness.TIMEOUT_SCALE)

    if ctx.cache_count() != files:
        fail('%d cache files before, %d after 7 seconds: the background '
             'purger is off and must not delete anything' % (
                 files, ctx.cache_count()))

    if len(masks_of(ctx, '/offbg/*')) != 1:
        fail('expected the mask "/offbg/*" to stay in the dump, got %r' % (
            ctx.dump()))


def test_purge_is_acknowledged_and_persisted(ctx):
    """A purge answers 200 {"status": "ok"} and the mask is on the disk."""
    now = int(time.time())
    r = ctx.purge_ok('/api/*')

    if r.headers.get('content-type') != 'plain/text':
        fail('PURGE /api/*: expected Content-Type plain/text, got %r' % (
            r.headers.get('content-type')))

    masks = masks_of(ctx, '/api/*')
    if len(masks) != 1:
        fail('expected one mask "/api/*" in the dump, got %r' % ctx.dump())

    mask = masks[0]
    if sorted(mask) != ['domain', 'mask', 'pst']:
        fail('expected the keys domain, mask, pst in the dump, got %r' % mask)

    if mask['domain'] != 'cache:purge_folder':
        fail('expected the domain "cache:purge_folder" (the cache path of '
             'proxy_folder_purge_cache_path and the host), got %r' % (
                 mask['domain']))

    if abs(mask['pst'] - now) > 2:
        fail('expected the purge time around %d, got %r' % (now, mask['pst']))

    persisted = ''
    for name in ctx.masks_files():
        if name.startswith('masks.in.'):
            with open(os.path.join(ctx.masks_dir, name)) as f:
                persisted += f.read()

    if 'cache:purge_folder,/api/*,%d' % mask['pst'] not in persisted:
        fail('expected "cache:purge_folder,/api/*,%d" in the masks.in file '
             'of %s, got %r' % (mask['pst'], ctx.masks_dir, persisted))


def test_masks_per_domain_limit(ctx):
    """The 11th active mask of a domain is refused with 429."""
    for i in range(10):
        ctx.purge_ok('/limit/%d/*' % i)

    r = ctx.purge('/limit/over/*')
    if r.status != 429:
        fail('PURGE /limit/over/*: expected 429 when 10 masks are already '
             'active, got %d %r' % (r.status, r.body))

    # A mask that is already active does not take a new slot
    ctx.purge_ok('/limit/0/*')
    if len(ctx.dump()) != 10:
        fail('expected 10 masks in the dump, got %d' % len(ctx.dump()))

    # A flushed mask frees its slot
    ctx.flush()
    ctx.purge_ok('/limit/over/*')


# The minimum that folder_purge accepts is 10 masks per domain
test_masks_per_domain_limit.vars = {'MAX_MASKS': 10}


def test_log_names_the_file_of_the_mask(ctx):
    """The log names the file the mask is written to as it is on the disk.

    The name ends with the number of the worker process, and the line has
    no zero bytes in it.
    """
    ctx.purge_across_second('/logfile/*')

    with open(os.path.join(ctx.sandbox, 'logs', 'error.log'), 'rb') as f:
        log = f.read()

    zeros = log.count(b'\x00')
    if zeros:
        fail('the log of nginx has %d zero bytes in it' % zeros)

    written = re.search(rb'write to "([^"]*)", fd = \d+, bytes = \d+', log)

    if written is None:
        fail('the log has no line about the file the mask was written to')

    workers = ctx.workers()
    if len(workers) != 1:
        fail('expected one worker process, found %r' % workers)

    name = os.path.join(ctx.masks_dir, 'masks.in.%d' % workers[0])
    logged = written.group(1).decode()

    if logged != name:
        fail('expected the name %s in the log, got %r' % (name, logged))

    if not os.path.exists(name):
        fail('there is no file %s: the name in the log is not the one on '
             'the disk' % name)


def test_no_warning_about_the_cache_path_with_purger_off(ctx):
    """The warning about the cache path is for the background purge only.

    This configuration has the background purge switched off: nothing is
    warned about where no cache path is named.
    """
    ctx.expect('/nocachepath/a.txt', 'MISS')
    ctx.purge_across_second('/nocachepath/*')
    ctx.expect('/nocachepath/a.txt', 'BYPASS')

    warned = ctx.log_lines('proxy_folder_purge_cache_path is not set')
    if warned:
        fail('the background purge is off, the log warns about the cache '
             'path anyway:\n%s' % warned[0].strip())



if __name__ == '__main__':
    harness.main(globals(), conf='foreground.conf')
