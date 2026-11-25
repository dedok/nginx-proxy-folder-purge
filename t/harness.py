#!/usr/bin/env python3

#
# (C) BSD v2
#

#
# Description:
# The common part of the purge tests (standard library only).
#
# A test module defines test_xxx(ctx) functions and ends with:
#
#     if __name__ == '__main__':
#         harness.main(globals(), conf='foreground.conf')
#
# Every test gets a brand-new sandbox under t/.run/<suite>/<test>/ : its own
# origin server, its own nginx (prefix = the sandbox, hence its own cache and
# masks storage) and free ports, so tests never see each other's state.
#
# Environment:
#   NFP_NGINX_BIN     nginx binary, default ./nginx/objs/nginx
#   NFP_LOG_LEVEL     error_log level of the tested nginx, default notice
#   NFP_TIMEOUT_SCALE multiply every timeout (slow machines, debuggers), default 1
#   NFP_TRACEBACK     1 = print a traceback for every failed test
#   NFP_KEEP          1 = keep sandboxes of passed tests too
#

import glob
import http.client
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import traceback
from urllib.parse import quote

from origin import start_origin

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
CONF_DIR = os.path.join(HERE, 'conf')
RUN_DIR = os.path.join(HERE, '.run')

DEFAULT_NGINX_BIN = os.path.join(REPO, 'nginx', 'objs', 'nginx')

HOST = 'purge_folder'

TIMEOUT_SCALE = float(os.environ.get('NFP_TIMEOUT_SCALE', '1'))
LOG_LEVEL = os.environ.get('NFP_LOG_LEVEL', 'notice')
TRACEBACK = os.environ.get('NFP_TRACEBACK', '') == '1'
KEEP = os.environ.get('NFP_KEEP', '') == '1'

# The background purger polls its queue every 6 seconds when it is idle
BG_PURGE_TIMEOUT = 30

# Cache entry dates and purge timestamps both have one-second resolution
SECOND_MARGIN = 0.03


class TestFailure(AssertionError):
    pass


def fail(message):
    raise TestFailure(message)


class Response(object):

    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers
        self.body = body

    @property
    def cache_status(self):
        return self.headers.get('x-cache-status')

    def __repr__(self):
        return 'Response(status=%d, cache_status=%r, body=%r)' % (
            self.status, self.cache_status, self.body)


def http_request(port, method, path, host=HOST, headers=None, conn=None,
                 timeout=30):
    """One HTTP request, a new connection unless "conn" is given."""
    own = conn is None
    if own:
        conn = http.client.HTTPConnection(
            '127.0.0.1', port, timeout=timeout * TIMEOUT_SCALE)

    try:
        h = {'Host': host}
        if headers:
            h.update(headers)
        conn.request(method, quote(path, safe='/?=&%*'), headers=h)
        resp = conn.getresponse()
        body = resp.read()
        return Response(resp.status,
                        dict((k.lower(), v) for k, v in resp.getheaders()),
                        body.decode('utf-8', 'replace'))

    finally:
        if own:
            conn.close()


def free_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def nginx_version(binary):
    out = subprocess.check_output([binary, '-V'], stderr=subprocess.STDOUT)
    return out.decode('utf-8', 'replace')


def read_log(path):
    """The module writes NUL bytes into its log, so read it byte-wise."""
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except IOError:
        return ''
    return data.decode('utf-8', 'replace').replace('\x00', '')


class Nginx(object):

    def __init__(self, binary, sandbox, conf, origin_port, port, variables):
        self.binary = binary
        self.sandbox = sandbox
        self.port = port
        self.proc = None

        with open(os.path.join(CONF_DIR, conf)) as f:
            text = f.read()

        values = {'@NGINX_PORT@': port,
                  '@ORIGIN_PORT@': origin_port,
                  '@SANDBOX@': sandbox,
                  '@LOG_LEVEL@': LOG_LEVEL,
                  '@MAX_MASKS@': 1000}
        values.update(('@%s@' % k, v) for k, v in (variables or {}).items())

        for name, value in values.items():
            text = text.replace(name, str(value))

        self.conf_path = os.path.join(sandbox, 'nginx.conf')
        with open(self.conf_path, 'w') as f:
            f.write(text)

        self.log_path = os.path.join(sandbox, 'logs', 'error.log')

    @property
    def log(self):
        return read_log(self.log_path)

    def start(self):
        self.started = time.time()
        with open(os.path.join(self.sandbox, 'logs', 'stderr.log'), 'ab') as err:
            self.proc = subprocess.Popen(
                [self.binary, '-p', self.sandbox, '-c', self.conf_path,
                 '-g', 'daemon off;'],
                stdout=err, stderr=err, start_new_session=True)

        deadline = time.time() + 20 * TIMEOUT_SCALE
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise TestFailure(
                    'nginx exited with code %d during the startup:\n%s' % (
                        self.proc.returncode, self.log_tail()))

            try:
                r = http_request(self.port, 'PURGE', '/', HOST,
                                 {'X-Purge-Options': 'dump'}, timeout=2)
                if r.status == 200:
                    return
            except OSError:
                pass

            time.sleep(0.02)

        fail('nginx is not answering on 127.0.0.1:%d:\n%s' % (
            self.port, self.log_tail()))

    def log_tail(self, lines=15):
        lines_ = [l for l in self.log.split('\n') if l.strip()]
        return '\n'.join(lines_[-lines:])

    def signal(self, signo):
        if self.proc is not None and self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signo)
            except OSError:
                pass

    def wait(self, timeout=20):
        try:
            self.proc.wait(timeout * TIMEOUT_SCALE)
        except subprocess.TimeoutExpired:
            self.signal(signal.SIGKILL)
            self.proc.wait()
            fail('nginx did not exit %d seconds after a signal' % timeout)

    def uptime(self):
        return time.time() - self.started


class Context(object):
    """Everything a test needs to talk to its nginx, origin and files."""

    def __init__(self, suite, name, conf, variables=None):
        self.sandbox = os.path.join(RUN_DIR, suite, name)

        # A sandbox of a previous run may still be there (failed tests keep
        # theirs), a test must not start with its cache or masks
        shutil.rmtree(self.sandbox, ignore_errors=True)

        for d in ('', 'logs', 'cache', 'masks_storage'):
            os.makedirs(os.path.join(self.sandbox, d))

        self.cache_dir = os.path.join(self.sandbox, 'cache')
        self.masks_dir = os.path.join(self.sandbox, 'masks_storage')

        self.origin, self.origin_port = start_origin()
        self.nginx = Nginx(os.environ.get('NFP_NGINX_BIN', DEFAULT_NGINX_BIN),
                           self.sandbox, conf, self.origin_port, free_port(),
                           variables)
        self.conn = None

    # Process control {{{

    def start(self):
        self.nginx.start()

    def stop(self):
        """Graceful stop (SIGQUIT), returns the exit code of the master."""
        self.close_conn()
        self.nginx.signal(signal.SIGQUIT)
        self.nginx.wait()
        code = self.nginx.proc.returncode
        self.nginx.proc = None
        return code

    def restart(self):
        self.stop()
        self.start()

    def crash(self):
        """SIGKILL the master and all its helper processes."""
        self.close_conn()
        self.nginx.signal(signal.SIGKILL)
        self.nginx.wait()
        self.nginx.proc = None

    def uptime(self):
        return self.nginx.uptime()

    # }}}

    # HTTP {{{

    def close_conn(self):
        if self.conn is not None:
            try:
                self.conn.close()
            except OSError:
                pass
            self.conn = None

    def request(self, method, path, host=HOST, headers=None):
        """Request through nginx. GETs reuse a keep-alive connection."""
        try:
            if self.conn is None:
                self.conn = http.client.HTTPConnection(
                    '127.0.0.1', self.nginx.port, timeout=30 * TIMEOUT_SCALE)
            return http_request(self.nginx.port, method, path, host, headers,
                                self.conn)

        except OSError:
            # a connection that nginx has already closed, retry once
            self.close_conn()
            return http_request(self.nginx.port, method, path, host, headers)

    def get(self, path, host=HOST, headers=None):
        return self.request('GET', path, host, headers)

    def purge(self, path, host=HOST, headers=None):
        return self.request('PURGE', path, host, headers)

    def purge_ok(self, path, host=HOST, key=None):
        """PURGE and check that the mask has been accepted."""
        headers = {}
        if key is not None:
            headers['X-Purge-Key'] = key
        r = self.purge(path, host, headers)
        if r.status != 200 or r.body != '{"status": "ok"}':
            fail('PURGE %s: expected 200 {"status": "ok"}, got %d %r' % (
                path, r.status, r.body))
        return r

    def dump(self, host=HOST):
        """All masks of the shared memory, as a list."""
        r = self.purge('/', host, {'X-Purge-Options': 'dump'})
        if r.status != 200:
            fail('PURGE with X-Purge-Options: dump: expected 200, got %d %r' % (
                r.status, r.body))
        return json.loads(r.body)

    def flush(self, host=HOST):
        """Drop all masks from the shared memory."""
        r = self.purge('/', host, {'X-Purge-Options': 'flush'})
        if r.status != 200:
            fail('PURGE with X-Purge-Options: flush: expected 200, got %d %r' % (
                r.status, r.body))
        return r

    def origin_hits(self, path):
        return self.origin.stats()['paths'].get(path, 0)

    # }}}

    # Checks {{{

    def expect(self, path, cache_status, body=None, host=HOST):
        """GET path and check X-Cache-Status (and the body, if given)."""
        r = self.get(path, host)
        what = 'GET %s%s' % (path, '' if host == HOST else ' for %s' % host)

        if r.status != 200:
            fail('%s: expected 200, got %d %r' % (what, r.status, r.body))

        if r.cache_status != cache_status:
            fail('%s: expected X-Cache-Status %s, got %s' % (
                what, cache_status, r.cache_status))

        if body is not None and r.body != body:
            fail('%s: expected the cached body %r, got a fresh one %r' % (
                what, body, r.body))

        return r

    def prime(self, *paths, **kw):
        """Fetch paths through nginx, they must all be cache misses.

        Returns {path: body} of the cached copies.
        """
        host = kw.get('host', HOST)
        bodies = {}
        for path in paths:
            r = self.expect(path, 'MISS', host=host)
            bodies[path] = r.body
        return bodies

    def wait_until(self, predicate, timeout, what):
        """Poll predicate every 50 ms, returns its value."""
        deadline = time.time() + timeout * TIMEOUT_SCALE
        while True:
            value = predicate()
            if value:
                return value
            if time.time() >= deadline:
                fail('%s did not happen within %d seconds' % (what, timeout))
            time.sleep(0.05)

    def cache_files(self, zone='cache'):
        """Names of the files of a cache zone (the zone is its directory)."""
        return sorted(os.path.basename(p)
                      for p in glob.glob(os.path.join(self.sandbox, zone,
                                                      '*', '*', '*')))

    def cache_count(self, zone='cache'):
        return len(self.cache_files(zone))

    def masks_files(self):
        return sorted(p for p in os.listdir(self.masks_dir) if p != '.lock')

    def log_lines(self, pattern):
        rx = re.compile(pattern)
        return [l for l in self.nginx.log.split('\n') if rx.search(l)]

    # }}}

    # Time {{{

    def next_second(self):
        """Sleep until the current wall-clock second is over.

        A purge timestamp and a cache entry date both have one-second
        resolution and an entry counts as purged when its date is less than
        or equal to the purge timestamp. So an object that was cached in the
        same second as its purge is purged again. Call this after a purge
        when an object cached afterwards has to be newer than the purge.
        """
        now = time.time()
        target = int(now) + 1 + SECOND_MARGIN
        time.sleep(max(0.0, target - now))

    def purge_across_second(self, path, host=HOST, key=None):
        """PURGE and then wait the purge's second out, see next_second().

        The purge is sent at the end of a second, so the wait is short.
        """
        now = time.time()
        time.sleep(max(0.0, int(now) + 0.85 - now))
        r = self.purge_ok(path, host, key)
        self.next_second()
        return r

    # }}}


def clean_stale_runs():
    """Stop nginx instances left over by an interrupted run."""
    for pid_path in glob.glob(os.path.join(RUN_DIR, '*', '*', 'logs',
                                           'nginx.pid')):
        sandbox = os.path.dirname(os.path.dirname(pid_path))
        try:
            with open(pid_path) as f:
                pid = int(f.read().strip())
            os.kill(pid, 0)
        except (IOError, ValueError, OSError):
            continue

        try:
            cmdline = subprocess.check_output(
                ['ps', '-o', 'command=', '-p', str(pid)]
            ).decode('utf-8', 'replace')
        except subprocess.CalledProcessError:
            continue

        if sandbox not in cmdline:
            continue

        sys.stderr.write('stopping nginx left over in %s (pid %d)\n' % (
            sandbox, pid))
        try:
            os.killpg(pid, signal.SIGQUIT)
        except OSError:
            pass
        for _ in range(100):
            try:
                os.kill(pid, 0)
            except OSError:
                break
            time.sleep(0.1)
        else:
            try:
                os.killpg(pid, signal.SIGKILL)
            except OSError:
                pass


def title(name):
    return re.sub(r'^test_', '', name).replace('_', ' ')


def _interrupt(signum, frame):
    raise KeyboardInterrupt


def main(namespace, conf, patterns=None):
    patterns = patterns if patterns is not None else sys.argv[1:]

    # "kill <pid>" and Ctrl-C stop nginx and the origin the same way
    signal.signal(signal.SIGTERM, _interrupt)

    binary = os.environ.get('NFP_NGINX_BIN', DEFAULT_NGINX_BIN)
    if not os.path.exists(binary):
        sys.stderr.write('nginx binary %s does not exist, build it first: '
                         'make build\n' % binary)
        sys.exit(2)

    version = nginx_version(binary)
    if 'proxy_folder_purge' not in version:
        sys.stderr.write('%s was not built with the proxy_folder_purge '
                         'module:\n%s\n' % (binary, version))
        sys.exit(2)

    suite = os.path.splitext(os.path.basename(sys.argv[0]))[0]
    sys.stdout.write('%s: %s (%s)\n' % (
        suite, version.split('\n', 1)[0].strip(), binary))

    tests = [(name, namespace[name]) for name in sorted(namespace)
             if name.startswith('test_') and callable(namespace[name])]

    # A fragment is looked up in the name as it is printed, so both
    # "cached_object" and "cached object" select the same tests
    if patterns:
        fragments = [p.lower().replace('_', ' ') for p in patterns]
        tests = [t for t in tests
                 if any(p in title(t[0]).lower() for p in fragments)]

    if not tests:
        sys.stderr.write('no tests selected\n')
        sys.exit(2)

    clean_stale_runs()

    passed = failed = errors = 0
    interrupted = False
    started = time.time()

    for name, func in tests:
        test_dir = name[len('test_'):]
        # a test may override config placeholders: test_x.vars = {'MAX_MASKS': 10}
        ctx = Context(suite, test_dir, conf, getattr(func, 'vars', None))
        status = 'PASS'
        message = ''
        tb = ''

        try:
            ctx.start()
            func(ctx)

        except AssertionError as e:
            status = 'FAIL'
            message = str(e)
            tb = traceback.format_exc()

        except KeyboardInterrupt:
            status = 'ERROR'
            message = 'interrupted'
            interrupted = True

        except Exception as e:
            status = 'ERROR'
            message = '%s: %s' % (type(e).__name__, e)
            tb = traceback.format_exc()

        finally:
            try:
                if ctx.nginx.proc is not None:
                    ctx.stop()
                ctx.origin.shutdown()
                ctx.origin.server_close()
            except Exception as e:
                if status == 'PASS':
                    status = 'ERROR'
                    message = 'teardown: %s: %s' % (type(e).__name__, e)
                    tb = traceback.format_exc()

        if status == 'PASS':
            passed += 1
        elif status == 'FAIL':
            failed += 1
        else:
            errors += 1

        if status == 'PASS' and not KEEP:
            shutil.rmtree(ctx.sandbox, ignore_errors=True)

        sys.stdout.write('[%s] %s\n' % (status, title(name)))
        sys.stdout.flush()

        if message:
            # A failed test keeps its sandbox, the log is the starting point
            text = message + '\n' + tb if TRACEBACK else message
            for line in text.strip().split('\n'):
                sys.stdout.write('       %s\n' % line)
            sys.stdout.write('       logs: %s\n' % ctx.nginx.log_path)
            sys.stdout.flush()

        if interrupted:
            break

    sys.stdout.write(
        'RESULT: %d passed, %d failed, %d errors out of %d (%s) in %.1fs\n' % (
            passed, failed, errors, passed + failed + errors, conf,
            time.time() - started))
    sys.stdout.flush()

    sys.exit(0 if passed == len(tests) else 1)
