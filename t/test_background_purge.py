#!/usr/bin/env python3

#
# (C) BSD v2
#

#
# Description:
# The background purge: a separate process deletes cached files that are
# covered by active masks.
#
# The purger is on here (t/conf/background.conf). It looks for new masks
# every 6 seconds when it is idle, so tests wait for its work instead of
# sleeping: the purger removes the masks from the shared memory when it is
# done, hence "the dump is empty" means "the purge is finished".
#
# Run:  ./t/run.sh  |  python3 t/test_background_purge.py [name fragments]
#

import os
import time

import harness
from harness import fail

HOST_A = 'host_a.example'
HOST_B = 'host_b.example'

CHECKPOINT = '.bg-purge.checkpoint'


def wait_consumed(ctx):
    """Wait until the background purger has processed all masks."""
    ctx.wait_until(lambda: not ctx.dump(), harness.BG_PURGE_TIMEOUT,
                   'the processing of the masks by the background purger')


def wait_cache_count(ctx, expected, zone='cache'):
    """Wait until a cache zone has exactly "expected" files."""
    deadline = time.time() + harness.BG_PURGE_TIMEOUT * harness.TIMEOUT_SCALE
    while ctx.cache_count(zone) != expected:
        if time.time() >= deadline:
            fail('%d files left in the %s zone, expected %d: the background '
                 'purger did not finish within %d seconds' % (
                     ctx.cache_count(zone), zone, expected,
                     harness.BG_PURGE_TIMEOUT))
        time.sleep(0.05)


def test_purge_removes_cached_object(ctx):
    """A purged object is deleted and fetched from the origin again."""
    cached = ctx.expect('/object/a.txt', 'MISS').body
    ctx.expect('/object/b.txt', 'MISS')

    left = ctx.cache_count() - 1
    ctx.purge_ok('/object/a.txt')
    wait_cache_count(ctx, left)

    fresh = ctx.expect('/object/a.txt', 'MISS').body
    if fresh == cached:
        fail('GET /object/a.txt after the purge: expected a fresh body, got '
             'the cached one %r' % cached)

    ctx.expect('/object/a.txt', 'HIT', fresh)


def test_purge_keeps_objects_outside_the_mask(ctx):
    """Objects that the mask does not cover stay in the cache."""
    bodies = ctx.prime('/outside/a.txt', '/outside/b.txt', '/outside2/a.txt')

    left = ctx.cache_count() - 1
    ctx.purge_ok('/outside/a.txt')
    wait_cache_count(ctx, left)

    ctx.expect('/outside/b.txt', 'HIT', bodies['/outside/b.txt'])
    ctx.expect('/outside2/a.txt', 'HIT', bodies['/outside2/a.txt'])


def test_folder_purge_removes_all_objects_below_it(ctx):
    """A folder mask removes files of any depth and folder URLs as well."""
    removed = ['/tree/', '/tree/child.txt', '/tree/sub/deep/file.txt']
    kept = ['/treelike/file.txt', '/elsewhere/tree/file.txt']
    bodies = ctx.prime(*(removed + kept))

    left = ctx.cache_count() - len(removed)
    ctx.purge_ok('/tree/*')
    wait_cache_count(ctx, left)

    for path in removed:
        ctx.expect(path, 'MISS')

    for path in kept:
        ctx.expect(path, 'HIT', bodies[path])


def test_extension_mask_removes_only_that_extension(ctx):
    """A mask with a wildcard in the file name is matched to the whole name."""
    bodies = ctx.prime('/ext/f_1.ext', '/ext/f_1.ext2', '/ext/f_2.ext',
                       '/ext/ext')

    left = ctx.cache_count() - 2
    ctx.purge_ok('/ext/*.ext')
    wait_cache_count(ctx, left)

    ctx.expect('/ext/f_1.ext', 'MISS')
    ctx.expect('/ext/f_2.ext', 'MISS')
    ctx.expect('/ext/f_1.ext2', 'HIT', bodies['/ext/f_1.ext2'])
    ctx.expect('/ext/ext', 'HIT', bodies['/ext/ext'])


def test_object_cached_after_purge_is_kept(ctx):
    """An object cached after the purge is newer than it and is not removed."""
    ctx.purge_across_second('/later/*')

    body = ctx.expect('/later/b.txt', 'MISS').body

    wait_consumed(ctx)

    ctx.expect('/later/b.txt', 'HIT', body)


def test_masks_are_consumed_after_purge(ctx):
    """Once processed, masks are gone from the memory and from the disk."""
    ctx.prime('/consumed/a.txt')
    ctx.purge_ok('/consumed/*')

    if len(ctx.dump()) != 1:
        fail('expected one mask in the dump, got %r' % ctx.dump())

    if len(ctx.masks_files()) != 1:
        fail('expected one masks.in file in %s, got %r' % (
            ctx.masks_dir, ctx.masks_files()))

    wait_consumed(ctx)

    if ctx.dump() != []:
        fail('expected an empty dump after the purge, got %r' % ctx.dump())

    if ctx.masks_files() != []:
        fail('expected no masks or checkpoint files in %s after the purge, '
             'got %r' % (ctx.masks_dir, ctx.masks_files()))


def test_repeated_purge_is_a_single_mask(ctx):
    """Purging the same mask again does not add a second mask."""
    ctx.prime('/again/a.txt')

    for _ in range(3):
        ctx.purge_ok('/again/*')

    if len(ctx.dump()) != 1:
        fail('expected one mask in the dump after three identical purges, '
             'got %r' % ctx.dump())

    wait_consumed(ctx)

    ctx.expect('/again/a.txt', 'MISS')


def test_purge_removes_objects_of_its_host_only(ctx):
    """The same URL of another host is another object, it is kept."""
    body_b = ctx.expect('/host/a.txt', 'MISS', host=HOST_B).body
    ctx.expect('/host/a.txt', 'MISS', host=HOST_A)

    left = ctx.cache_count() - 1
    ctx.purge_ok('/host/*', host=HOST_A)
    wait_cache_count(ctx, left)

    ctx.expect('/host/a.txt', 'MISS', host=HOST_A)
    ctx.expect('/host/a.txt', 'HIT', body_b, host=HOST_B)


def test_mask_is_not_applied_to_another_cache_zone(ctx):
    """A mask of one cache zone never deletes objects of another zone."""
    ctx.prime('/other/shared/a.txt', '/shared/a.txt')

    ctx.purge_ok('/not/an/object', key='/other/shared/*')
    wait_consumed(ctx)

    if ctx.cache_count('other_cache') != 1:
        fail('the mask belongs to the "cache" zone, but the "other_cache" '
             'zone has %d files instead of 1' % ctx.cache_count('other_cache'))

    ctx.expect('/other/shared/a.txt', 'HIT')
    ctx.expect('/shared/a.txt', 'HIT')


def test_purge_of_the_second_cache_zone(ctx):
    """A purge sent from the location of another zone purges that zone."""
    ctx.prime('/other/shared/b.txt', '/shared/b.txt')

    ctx.purge_ok('/other/shared/*')

    wait_cache_count(ctx, 0, zone='other_cache')

    ctx.expect('/other/shared/b.txt', 'MISS')
    ctx.expect('/shared/b.txt', 'HIT')


def test_purged_object_is_renewed_before_the_background_purge(ctx):
    """With both purges on, a request for a purged object is renewed at once."""
    cached = ctx.expect('/fg/a.txt', 'MISS').body
    ctx.expect('/fg/a.txt', 'HIT', cached)

    if ctx.uptime() > 3:
        fail('the test took too long: it has to be over before the first '
             'poll of the background purger 6 seconds after the start')

    ctx.purge_ok('/fg/*')

    fresh = ctx.expect('/fg/a.txt', 'BYPASS')
    if fresh.body == cached:
        fail('GET /fg/a.txt right after the purge: expected a fresh body, '
             'got the cached one %r' % cached)


def test_masks_survive_a_crash(ctx):
    """Masks that are on the disk when nginx is killed are processed later."""
    cached = ctx.expect('/crash/a.txt', 'MISS').body
    ctx.expect('/crash/a.txt', 'HIT', cached)
    ctx.purge_ok('/crash/*')

    if len(ctx.masks_files()) != 1:
        fail('expected the mask on the disk before the crash, got %r' % (
            ctx.masks_files()))

    ctx.crash()
    ctx.start()

    def removed():
        r = ctx.get('/crash/a.txt')
        return r if r.cache_status == 'MISS' else None

    fresh = ctx.wait_until(
        removed, harness.BG_PURGE_TIMEOUT,
        'the removal of the purged object after the restart')

    if fresh.body == cached:
        fail('GET /crash/a.txt after the restart: expected a fresh body, '
             'got the cached one %r' % cached)


def test_crash_during_purge_is_resumed(ctx):
    """A purge that a crash interrupted is finished after the start.

    The purger walks the cache slowly on purpose (it sleeps 1 ms after every
    file past the first hundred) and saves its position once a second. With
    3000 files the walk takes about 3 seconds, long enough to kill nginx in
    the middle of it, after the position has been saved at least once.
    """
    gone = ['/walk/gone/%04d.txt' % i for i in range(1500)]
    kept = ['/walk/kept/%04d.txt' % i for i in range(1500)]
    bodies = ctx.prime(*(gone + kept))

    total = ctx.cache_count()
    ctx.purge_ok('/walk/gone/*')

    def removed():
        return total - ctx.cache_count()

    # 900 deleted files are about 1800 walked ones, i.e. almost 2 seconds
    ctx.wait_until(lambda: 900 <= removed() < 1400, harness.BG_PURGE_TIMEOUT,
                   'the start of the purge (the purger polls every 6 seconds)')

    ctx.crash()

    if not os.path.exists(os.path.join(ctx.masks_dir, CHECKPOINT)):
        fail('expected the saved position %s in %s after the crash, got %r' % (
            CHECKPOINT, ctx.masks_dir, ctx.masks_files()))

    ctx.start()

    wait_cache_count(ctx, len(kept))

    sample = list(range(0, 1500, 150))
    for i in sample:
        ctx.expect(gone[i], 'MISS')
        ctx.expect(kept[i], 'HIT', bodies[kept[i]])

    wait_consumed(ctx)


if __name__ == '__main__':
    harness.main(globals(), conf='background.conf')
