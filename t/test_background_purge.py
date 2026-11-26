#!/usr/bin/env python3

#
# (C) BSD, Vas Soshnikov
#

#
# Description:
# The background purge: cached files that are covered by active masks are
# deleted.
#
# The purge is the manager of the masks storage path, nginx's cache manager
# process calls it. A purge is done in
# slices, one per call, and when there is nothing to do the purger looks for
# new masks every purger_poll. Tests wait for its work instead of sleeping:
# the purger removes the masks from the shared memory when it is done, hence
# "the dump is empty" means "the purge is finished".
#
# Run:  ./t/run.sh  |  python3 t/test_background_purge.py [name fragments]
#

import os
import time

import harness
from harness import fail, http_request, HOST

HOST_A = 'host_a.example'
HOST_B = 'host_b.example'

# What the purger keeps in the masks storage besides the masks
CHECKPOINT = harness.CHECKPOINT
ATTEMPTS = '.purger.attempts'

# A slow purge: one cache file per 300 ms, a test has time to act in the
# middle of it
SLOW = {'PURGER_FILES': 1, 'PURGER_SLEEP': '300ms'}


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


def finished(ctx):
    """Log lines of the purges that are over."""
    return ctx.log_lines('finished purge queue')


def wait_finished(ctx):
    """Wait until a purge is over."""
    ctx.wait_until(lambda: finished(ctx), harness.BG_PURGE_TIMEOUT,
                   'the end of the purge')


def slow_purge(ctx, prefix, count=20):
    """Cache count objects and purge them slowly, one file per 300 ms."""
    paths = ['%s/%02d.txt' % (prefix, i) for i in range(count)]
    bodies = ctx.prime(*paths)
    ctx.purge_ok(prefix + '/*')
    return paths, bodies


def attempts(ctx):
    """How many times the purge of the masks has been started."""
    try:
        with open(os.path.join(ctx.masks_dir, ATTEMPTS)) as f:
            return int(f.read().split()[1])
    except (IOError, IndexError, ValueError):
        return 0


def masks_state(ctx):
    """Everything there is in the masks storage, the lock included.

    The saved position of the purge is in it by its name only: the running
    purge rewrites the position once in a second.
    """
    state = {}
    for name in sorted(os.listdir(ctx.masks_dir)):
        if name.startswith(CHECKPOINT):
            state[name] = None
            continue
        with open(os.path.join(ctx.masks_dir, name), 'rb') as f:
            state[name] = f.read()
    return state


def test_purge_runs_in_the_cache_manager(ctx):
    """The purge is done by nginx's cache manager process."""
    managers = ctx.cache_managers()
    if len(managers) != 1:
        fail('expected one cache manager process, found %r' % managers)

    started = ctx.log_lines('the background purge has started in the '
                            'cache manager process')

    if len(started) != 1:
        fail('expected one log line about the start of the background '
             'purge, got %r' % started)

    if ('process %d,' % managers[0]) not in started[0]:
        fail('the background purge has not started in the cache manager '
             'process %d: %s' % (managers[0], started[0]))

    if ctx.nginx.children('background purge'):
        fail('there is a process of the background purge: %r'
             % ctx.nginx.children('background purge'))


def test_dump_temporary_files_have_their_own_directory(ctx):
    """The temporary files of a dump are written to a directory of their own.

    The directory is a path of nginx: nginx makes it the property of the
    user the workers run as, so the dump works when the workers are not the
    user the master process runs as.
    """
    ctx.prime('/dumpdir/a.txt')
    ctx.purge_ok('/dumpdir/*')

    directory = os.path.join(ctx.sandbox, 'masks_storage_tmp')

    if not os.path.isdir(directory):
        fail('expected the directory of the temporary files of a dump, %s'
             % directory)

    masks = ctx.dump()

    if [m['mask'] for m in masks] != ['/dumpdir/*']:
        fail('expected the mask "/dumpdir/*" in the dump, got %r' % masks)

    if os.listdir(directory) != []:
        fail('expected no temporary file to be left in %s, got %r' % (
            directory, os.listdir(directory)))


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


# The purger looks for masks every 5 seconds here: it must not get the
# masks before the test has looked at them
QUIET = {'PURGER_POLL': '5s'}



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
test_masks_are_consumed_after_purge.vars = QUIET



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
test_repeated_purge_is_a_single_mask.vars = QUIET


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
    """With both purges on, a request for a purged object is renewed at once.

    The purger looks for masks every 5 seconds here, the purged copy is
    still in the cache when the request comes.
    """
    cached = ctx.expect('/fg/a.txt', 'MISS').body
    ctx.expect('/fg/a.txt', 'HIT', cached)

    ctx.purge_ok('/fg/*')

    fresh = ctx.expect('/fg/a.txt', 'BYPASS')
    if fresh.body == cached:
        fail('GET /fg/a.txt right after the purge: expected a fresh body, '
             'got the cached one %r' % cached)
test_purged_object_is_renewed_before_the_background_purge.vars = QUIET



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
test_masks_survive_a_crash.vars = QUIET


def test_both_purges_read_the_cache_key_the_same_way(ctx):
    """The foreground and the background purge decide the same about an object.

    Both read the url out of the cache key. With the arguments of the request
    in the key, a mask with a fixed tail does not cover an object that has
    arguments, and a mask can match the arguments. The objects under
    /fg/same/read/ are asked for while the masks live: the foreground purge
    answers. The objects under /fg/same/files/ are asked for once the
    background purge is over: the ones it removed are fetched again.
    """
    read = ['/fg/same/read/a.jpg', '/fg/same/read/a.jpg?v=2',
            '/fg/same/read/b.txt?n=1']
    files = ['/fg/same/files/a.jpg', '/fg/same/files/a.jpg?v=2',
             '/fg/same/files/b.txt?n=1']
    bodies = ctx.prime(*(read + files))

    for prefix in ('/fg/same/read/', '/fg/same/files/'):
        ctx.purge_ok(prefix + '*.jpg')
        ctx.purge_ok(prefix + 'b*1')

    ctx.expect('/fg/same/read/a.jpg', 'BYPASS')
    ctx.expect('/fg/same/read/b.txt?n=1', 'BYPASS')
    ctx.expect('/fg/same/read/a.jpg?v=2', 'HIT',
               bodies['/fg/same/read/a.jpg?v=2'])

    wait_consumed(ctx)

    ctx.expect('/fg/same/files/a.jpg', 'MISS')
    ctx.expect('/fg/same/files/b.txt?n=1', 'MISS')
    ctx.expect('/fg/same/files/a.jpg?v=2', 'HIT',
               bodies['/fg/same/files/a.jpg?v=2'])


test_both_purges_read_the_cache_key_the_same_way.vars = dict(
    QUIET, CACHE_KEY='$host:$uri$is_args$args')


# 50 cache files per slice, 60 ms between the slices

def test_crash_during_purge_is_resumed(ctx):
    """A purge that a crash interrupted is finished after the start.

    The purger looks at 50 files per slice and is called again 60 ms later,
    so the walk of the 3000 files takes at least 3.6 seconds, whatever the
    disk is: long enough to kill nginx in the middle of it. The purger
    saves its position once in a second, and the first one comes up to a
    second after the walk begins, so the position is on the disk long
    before 900 files are gone.
    """
    gone = ['/walk/gone/%04d.txt' % i for i in range(1500)]
    kept = ['/walk/kept/%04d.txt' % i for i in range(1500)]
    bodies = ctx.prime(*(gone + kept))

    total = ctx.cache_count()
    ctx.purge_ok('/walk/gone/*')

    def removed():
        return total - ctx.cache_count()

    def in_the_middle():
        """From 900 to 1400 files are gone, and the position is saved."""
        return (900 <= removed() < 1400
                and os.path.exists(ctx.checkpoint))

    # 900 deleted files are about 1800 walked ones, i.e. 36 slices
    ctx.wait_until(in_the_middle, harness.BG_PURGE_TIMEOUT,
                   'the purge in the middle of the walk, with its position '
                   'saved (the purger looks for masks once in a second when '
                   'it is idle)')

    ctx.crash()

    ctx.start()

    wait_cache_count(ctx, len(kept))

    sample = list(range(0, 1500, 150))
    for i in sample:
        ctx.expect(gone[i], 'MISS')
        ctx.expect(kept[i], 'HIT', bodies[kept[i]])

    wait_consumed(ctx)


test_crash_during_purge_is_resumed.vars = {'PURGER_FILES': 50,
                                           'PURGER_SLEEP': '60ms'}


def test_purge_is_done_in_slices(ctx):
    """A slow purge does not hold nginx's own cache maintenance up.

    The purge and nginx's cache manager live in one process. 300 objects
    that nobody asks for have to be removed by nginx while a purge that
    takes more than 12 seconds is running: one long walk would keep nginx's
    own work waiting for it.
    """
    hot = ['/slice/hot/%02d.txt' % i for i in range(30)]
    ctx.prime(*['/slice/old/%03d.txt' % i for i in range(300)])
    ctx.prime(*hot)
    ctx.prime(*['/slice/target/%02d.txt' % i for i in range(30)])

    ctx.purge_ok('/slice/target/*')

    # The objects that are asked for stay cached, so the purge has 30 files
    # to go one by one. Nobody asks for the other 330: nginx removes them
    # after 3 seconds of inactivity, if its cache manager gets to it.
    started = time.time()
    while time.time() - started < 7:
        for path in hot:
            ctx.get(path)
        time.sleep(1.5)

    if finished(ctx):
        fail('the purge is over 7 seconds after the PURGE, it has to take '
             'at least 12 seconds')

    if ctx.cache_count() > 150:
        fail('%d cache files are left 7 seconds after the PURGE: nginx\'s '
             'cache manager could not remove the 300 inactive objects while '
             'the purge was running' % ctx.cache_count())

    wait_finished(ctx)

    wait_consumed(ctx)


test_purge_is_done_in_slices.vars = dict(SLOW, PURGER_SLEEP='400ms',
                                         CACHE_INACTIVE='3s')


def test_reload_during_purge_continues_it(ctx):
    """A purge goes on where it stopped when nginx is reloaded.

    The configuration is reloaded three times in the middle of the purge:
    the work is not lost, and the reloads are not taken for crashes of the
    cache manager.
    """
    paths, _ = slow_purge(ctx, '/reload', count=40)

    for _ in range(3):
        time.sleep(1.2)
        ctx.reload()

    if finished(ctx):
        fail('the purge is over before the third reload: the test has to '
             'catch the purge in the middle')

    managers = ctx.cache_managers()
    wait_finished(ctx)

    if '%d#0:' % managers[0] not in finished(ctx)[0]:
        fail('the purge has not been finished by the last cache manager '
             'process %d: %s' % (managers[0], finished(ctx)[0]))

    for path in paths:
        ctx.expect(path, 'MISS')

    given_up = ctx.log_lines('is given up')
    if given_up:
        fail('the purge was given up, the reloads were taken for crashes of '
             'the cache manager: %s' % given_up[0])

    wait_consumed(ctx)


test_reload_during_purge_continues_it.vars = SLOW


def test_stop_during_purge_continues_it_after_start(ctx):
    """A purge that a stop of nginx interrupts is finished by the next start.

    The queue file and the checkpoint of the purge are kept on the disk.
    """
    paths, _ = slow_purge(ctx, '/stop')

    ctx.wait_until(lambda: os.path.exists(ctx.checkpoint),
                   harness.BG_PURGE_TIMEOUT, 'the checkpoint of the purge')

    ctx.stop()

    queue = [f for f in ctx.masks_files() if f.startswith('masks.purger')]
    if not queue:
        fail('the queue file of the purge is gone after the stop, the rest '
             'of the purge is lost, the files are %r' % ctx.masks_files())

    if not os.path.exists(ctx.checkpoint):
        fail('the checkpoint of the purge is gone after the stop')

    ctx.start()
    wait_finished(ctx)

    for path in paths:
        ctx.expect(path, 'MISS')


test_stop_during_purge_continues_it_after_start.vars = SLOW


def test_crash_loop_is_stopped(ctx):
    """A purge that keeps stopping nginx's cache manager is given up.

    The cache manager process is killed three times in the middle of a
    purge. The fourth start leaves the purge alone: an ALERT is logged and
    the masks are dropped, so that nginx's own cache maintenance goes on. A
    new purge works as before.
    """
    paths, _ = slow_purge(ctx, '/crashloop', count=40)

    for i in range(3):
        ctx.wait_until(lambda: attempts(ctx) == i + 1,
                       harness.BG_PURGE_TIMEOUT,
                       'the start of the purge by the cache manager')
        time.sleep(0.6)
        ctx.crash_cache_manager()

    ctx.wait_until(lambda: ctx.log_lines('is given up'),
                   harness.BG_PURGE_TIMEOUT,
                   'giving up the purge that keeps stopping the cache '
                   'manager')

    # The masks are dropped a moment after the line about it is written
    ctx.wait_until(lambda: not ctx.dump(), harness.BG_PURGE_TIMEOUT,
                   'the dropping of the masks of the purge that is given up')

    cached = sum(1 for path in paths
                 if ctx.get(path).cache_status == 'HIT')
    if cached < 10:
        fail('%d of the %d objects are still cached after the purge was '
             'given up: it went on instead' % (cached, len(paths)))

    managers = ctx.cache_managers()
    if len(managers) != 1:
        fail('expected one cache manager process, found %r' % managers)

    ctx.prime('/crashloop/next.txt')
    ctx.purge_ok('/crashloop/next.txt')

    def removed():
        r = ctx.get('/crashloop/next.txt')
        return r if r.cache_status == 'MISS' else None

    ctx.wait_until(removed, harness.BG_PURGE_TIMEOUT,
                   'the purge of a new object after the given up one')


test_crash_loop_is_stopped.vars = SLOW


def test_second_nginx_waits_for_the_lock(ctx):
    """One purger per masks storage: a second nginx waits for the lock.

    The second nginx has the same masks storage and a cache of its own, the
    way a new nginx and the old one run together while nginx is upgraded.
    """
    ctx.expect('/lock/a.txt', 'MISS')
    second = ctx.second_instance({'LOCK_WAIT': '2s'})

    def second_log():
        return harness.read_log(second.log_path)

    if http_request(second.port, 'GET', '/lock/a.txt', HOST).cache_status \
            != 'MISS':
        fail('expected a miss in the second nginx')

    ctx.wait_until(lambda: 'waits for the lock' in second_log(),
                   harness.BG_PURGE_TIMEOUT,
                   'the second nginx waiting for the lock')
    ctx.wait_until(lambda: 'is still taken by pid' in second_log(),
                   harness.BG_PURGE_TIMEOUT,
                   'the warning that the second nginx waits for long')

    # The first nginx holds the lock: the purge goes through its cache only
    r = http_request(second.port, 'PURGE', '/lock/*', HOST)
    if r.status != 200:
        fail('PURGE /lock/* in the second nginx: expected 200, got %d %r'
             % (r.status, r.body))

    def removed(port):
        r = http_request(port, 'GET', '/lock/a.txt', HOST)
        return r if r.cache_status == 'MISS' else None

    ctx.wait_until(lambda: removed(ctx.nginx.port),
                   harness.BG_PURGE_TIMEOUT,
                   'the purge of the object by the nginx holding the lock')

    r = http_request(second.port, 'GET', '/lock/a.txt', HOST)
    if r.cache_status != 'HIT':
        fail('the second nginx served X-Cache-Status %s: it has purged its '
             'copy without holding the lock' % r.cache_status)

    # The first nginx stops: the lock is free, the second nginx purges
    ctx.stop()

    ctx.wait_until(lambda: 'the background purge has started in the cache '
                           'manager process' in second_log(),
                   harness.BG_PURGE_TIMEOUT,
                   'the second nginx taking the lock')

    http_request(second.port, 'PURGE', '/lock/*', HOST)

    ctx.wait_until(lambda: removed(second.port), harness.BG_PURGE_TIMEOUT,
                   'the purge of the object by the second nginx')


def test_no_lock_when_startup_lock_delay_is_off(ctx):
    """startup_lock_delay=off: the purger neither takes nor waits for a lock.

    The option is for an nginx that has the masks storage for itself alone.
    """
    second = ctx.second_instance({'LOCK_WAIT': 'off'})

    ctx.wait_until(lambda: 'the background purge has started in the cache '
                           'manager process' in harness.read_log(second.log_path),
                   harness.BG_PURGE_TIMEOUT,
                   'the start of the background purge in the second nginx')

    log = harness.read_log(second.log_path)

    if 'is taken by pid' in log:
        fail('the second nginx has taken the lock although '
             'startup_lock_delay is off')

    if 'waits for the lock' in log:
        fail('the second nginx waits for the lock although '
             'startup_lock_delay is off')


def test_config_test_leaves_the_purge_alone(ctx):
    """"nginx -t" in the middle of a purge changes nothing and does not wait."""
    slow_purge(ctx, '/configtest')

    ctx.wait_until(lambda: attempts(ctx) == 1
                   and os.path.exists(ctx.checkpoint),
                   harness.BG_PURGE_TIMEOUT,
                   'the start of the purge by the cache manager')
    before = masks_state(ctx)

    started = time.time()
    rc = ctx.nginx.test_config()
    elapsed = time.time() - started

    if rc != 0:
        fail('nginx -t exited with code %d' % rc)

    if elapsed > 5:
        fail('nginx -t took %.1f seconds, it must not wait for the lock'
             % elapsed)

    if masks_state(ctx) != before:
        fail('"nginx -t" has changed the files of the purge:\nbefore %r\n'
             'after %r' % (before, masks_state(ctx)))

    wait_finished(ctx)


test_config_test_leaves_the_purge_alone.vars = SLOW


def test_purger_poll_paces_the_search_for_masks(ctx):
    """purger_poll is how often the purger looks for masks when it is idle."""
    ctx.prime('/poll/a.txt')
    ctx.purge_ok('/poll/*')

    time.sleep(2)

    if ctx.get('/poll/a.txt').cache_status != 'HIT':
        fail('the object is purged 2 seconds after the PURGE, although the '
             'purger looks for masks every 4 seconds')

    def removed():
        r = ctx.get('/poll/a.txt')
        return r if r.cache_status == 'MISS' else None

    ctx.wait_until(removed, harness.BG_PURGE_TIMEOUT, 'the purge of the object')


test_purger_poll_paces_the_search_for_masks.vars = {'PURGER_POLL': '4s'}


def test_purge_is_seen_with_open_file_cache_events(ctx):
    """With open_file_cache_events on nginx notices at once what is deleted.

    That needs the kqueue event method of nginx, the test is skipped with
    the other ones. nginx keeps the file open in the location, and without
    the events it goes on serving the deleted copy from the kept descriptor.
    """
    ctx.skip_unless_kqueue(
        'open_file_cache_events makes nginx notice a deleted file with the '
        'kqueue event method only')

    cached = ctx.expect('/ofc/a.txt', 'MISS').body
    for _ in range(5):
        ctx.expect('/ofc/a.txt', 'HIT', cached)

    ctx.purge_ok('/ofc/*')

    def removed():
        r = ctx.get('/ofc/a.txt')
        return r if r.cache_status == 'MISS' else None

    fresh = ctx.wait_until(removed, harness.BG_PURGE_TIMEOUT,
                           'the purge of the file nginx keeps open')

    if fresh.body == cached:
        fail('GET /ofc/a.txt after the purge: expected a fresh body, got '
             'the deleted copy %r' % cached)


def test_open_file_cache_is_warned_about(ctx):
    """open_file_cache in a location is warned about once."""
    ctx.prime('/noevents/a.txt', '/noevents/b.txt')
    ctx.expect('/noevents/a.txt', 'HIT')
    ctx.expect('/noevents/b.txt', 'HIT')

    warnings = ctx.log_lines('open_file_cache is used')

    if len(warnings) != 1:
        fail('expected one warning about open_file_cache, got %d'
             % len(warnings))

    if 'open_file_cache_valid' not in warnings[0]:
        fail('the warning does not say how long the deleted file is served: %s'
             % warnings[0])


def test_open_file_cache_events_silence_the_warning_with_kqueue_only(ctx):
    """open_file_cache_events is enough where the event method is kqueue.

    With the other event methods the warning stays: the switch does not
    make nginx notice a deleted file there.
    """
    ctx.prime('/events/a.txt')
    ctx.expect('/events/a.txt', 'HIT')

    warnings = ctx.log_lines('open_file_cache is used')

    if ctx.uses_kqueue():
        if warnings:
            fail('the warning is logged although the kqueue event method '
                 'makes nginx notice deleted files: %s' % warnings[0])

    elif len(warnings) != 1:
        fail('expected one warning about open_file_cache with the events on, '
             'got %d' % len(warnings))


def test_open_file_cache_delays_the_purge_without_kqueue(ctx):
    """Without kqueue the deleted file is served until open_file_cache_valid.

    open_file_cache_events is on in the location and does not help.
    """
    if ctx.uses_kqueue():
        harness.skip('the kqueue event method notices the deletion')

    cached = ctx.expect('/ofc/a.txt', 'MISS').body
    for _ in range(5):
        ctx.expect('/ofc/a.txt', 'HIT', cached)

    ctx.purge_ok('/ofc/*')

    # The file is deleted, the kept descriptor goes on serving the copy
    ctx.wait_until(lambda: ctx.cache_count() == 0, harness.BG_PURGE_TIMEOUT,
                   'the deletion of the file by the purge')

    ctx.expect('/ofc/a.txt', 'HIT', cached)

    # Five seconds after the file was opened the descriptor is not used
    def removed():
        r = ctx.get('/ofc/a.txt')
        return r if r.cache_status == 'MISS' else None

    fresh = ctx.wait_until(removed, harness.BG_PURGE_TIMEOUT,
                           'the refetch of the object once open_file_cache_valid '
                           'is over')

    if fresh.body == cached:
        fail('GET /ofc/a.txt after open_file_cache_valid: expected a fresh '
             'body, got the deleted copy %r' % cached)


test_open_file_cache_delays_the_purge_without_kqueue.vars = {'OFC_VALID': '5s'}


def test_cache_key_without_url_is_left_alone(ctx):
    """A cache file whose key says nothing about the url is left alone."""
    cached = ctx.expect('/keyless/a.txt', 'MISS').body
    managers = ctx.cache_managers()

    ctx.purge_ok('/keyless/*')
    wait_finished(ctx)

    ctx.expect('/keyless/a.txt', 'HIT', cached)

    if ctx.cache_managers() != managers:
        fail('the cache manager process has been respawned: %r -> %r'
             % (managers, ctx.cache_managers()))


def test_unreadable_cache_file_does_not_stop_the_purge(ctx):
    """A cache file that can't be read is skipped, the purge goes on.

    The file is looked at first: its name sorts before the names of the
    cached objects.
    """
    ctx.prime('/garbage/target.txt')
    managers = ctx.cache_managers()

    junk = os.path.join(ctx.cache_dir, '0', '00', '0' * 32)
    os.makedirs(os.path.dirname(junk))
    with open(junk, 'wb') as f:
        f.write(b'too short to be a cache file')

    ctx.purge_ok('/garbage/*')
    wait_finished(ctx)

    ctx.expect('/garbage/target.txt', 'MISS')

    if ctx.cache_managers() != managers:
        fail('the cache manager process has been respawned: %r -> %r'
             % (managers, ctx.cache_managers()))


if __name__ == '__main__':
    harness.main(globals(), conf='background.conf')
