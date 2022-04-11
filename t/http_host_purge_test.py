#!/usr/bin/env python2

#
# (c)
#

import os
import sys
import json
import time
sys.path.append('./t')
from http_utils import *

N = 100
DELAY = 20
URL = "http://127.0.0.1:8082"
MASKS_STORAGE = "./test-root/masks_storage/masks.in*"
CACHE = "./test-root/cache/*"

def cleanup():
    print ('[+] Flush & Cleanup')
    purge_success(URL + "/*", {"X-Purge-Options": "flush"})
    try:
        os.popen('rm -Rf {}'.format(MASKS_STORAGE))
    except:
        pass
    try:
        os.popen('rm -Rf {}'.format(CACHE))
    except:
        pass
    print ('[+] OK')

# Start
print (
    '[!] WARNING. The codes does not sync with the background purge.\n' +
    'That means we have to use some timeouts between data caching, a purge\n' +
    'call, and validation. Be careful, make sure that DELAY is +/- sync with\n' +
    'the background purge throtolling.\n' +
    'And also this test expectes nginx builded with an option NGX_DEBUG 1\n' +
    '[!] WARNING. This test may take to long time\n')

cleanup()

print ('[+] Http host purge')

print ('[+] Foreground purge with host')
uri = URL + "/foreground_purge_with_host/2"
_, cached, _ = get_success(uri + '/test-1.txt', {'Host': 'vary10.foo.com'})
_, cached, _ = get_success(uri + '/test-2.txt', {'Host': 'vary11.foo.com'})
_, cached, _ = get_success(uri + '/test-3.txt', {'Host': 'vary12.foo.com'})
purge_success(uri + "/*", {'Host': 'purge_folder',
    'X-Purge-Options': 'delete', 'X-Cache-Host': 'x.bar.com'})
a, cached_2, b = get_success(uri + '/test-1.txt', {'Host': 'vary10.foo.com'})
assert b['x-cache-status'] == 'EXPIRED', 'wrong cache status'
a, cached_2, b = get_success(uri + '/test-2.txt', {'Host': 'vary11.foo.com'})
assert b['x-cache-status'] == 'EXPIRED', 'wrong cache status'
a, cached_2, b = get_success(uri + '/test-3.txt', {'Host': 'vary12.foo.com'})
assert b['x-cache-status'] == 'EXPIRED', 'wrong cache status'

uri = URL + "/foreground_purge_with_host/3"
_, cached, _ = get_success(uri + '/test-1.txt', {'Host': 'vary20.foo.com'})
_, cached, _ = get_success(uri + '/test-2.txt', {'Host': 'vary21.foo.com'})
_, cached, _ = get_success(uri + '/test-3.txt', {'Host': 'vary22.foo.com'})
purge_success(uri + "/*", {'Host': 'purge_folder',
    'X-Purge-Options': 'delete', 'X-Cache-Host': 'vary20.foo.com'})
a, cached_2, b = get_success(uri + '/test-1.txt', {'Host': 'vary20.foo.com'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
a, cached_2, b = get_success(uri + '/test-2.txt', {'Host': 'vary21.foo.com'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
a, cached_2, b = get_success(uri + '/test-3.txt', {'Host': 'vary22.foo.com'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
print ('[+] OK')


print ('[+] Background purge with host')
uri = URL + "/background_purge_with_host/4"
_, cached, _ = get_success(uri + '/test-1.txt', {'Host': 'vary30.foo.com'})
_, cached, _ = get_success(uri + '/test-2.txt', {'Host': 'vary31.foo.com'})
_, cached, _ = get_success(uri + '/test-3.txt', {'Host': 'vary32.foo.com'})
purge_success(uri + "/*", {'Host': 'purge_folder',
    'X-Purge-Options': 'delete', 'X-Cache-Host': 'x.bar.com'})
time.sleep(DELAY)
a, cached_2, b = get_success(uri + '/test-1.txt', {'Host': 'vary30.foo.com'})
assert b['x-cache-status'] == 'MISS', 'wrong cache status'
a, cached_2, b = get_success(uri + '/test-2.txt', {'Host': 'vary31.foo.com'})
assert b['x-cache-status'] == 'MISS', 'wrong cache status'
a, cached_2, b = get_success(uri + '/test-3.txt', {'Host': 'vary32.foo.com'})
assert b['x-cache-status'] == 'MISS', 'wrong cache status'

uri = URL + "/background_purge_with_host/5"
_, cached, _ = get_success(uri + '/test-1.txt', {'Host': 'vary40.foo.com'})
_, cached, _ = get_success(uri + '/test-2.txt', {'Host': 'vary41.foo.com'})
_, cached, _ = get_success(uri + '/test-3.txt', {'Host': 'vary42.foo.com'})
purge_success(uri + "/*", {'Host': 'purge_folder',
    'X-Purge-Options': 'delete', 'X-Cache-Host': 'vary40.foo.com'})
time.sleep(DELAY)
a, cached_2, b = get_success(uri + '/test-1.txt', {'Host': 'vary40.foo.com'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
a, cached_2, b = get_success(uri + '/test-2.txt', {'Host': 'vary41.foo.com'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
a, cached_2, b = get_success(uri + '/test-3.txt', {'Host': 'vary42.foo.com'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
print ('[+] OK')


print ('[!] WARNINGS.\n'
        '- Be sure, that background purge is off!\n' +
        '- This test expectes nginx builded with an option NGX_DEBUG 1\n')

print ('[+] Flush & Cleanup')
purge_success(URL + "/*", {"X-Purge-Options": "flush"})
try:
    os.popen('rm -Rf {}'.format(MASKS_STORAGE))
except:
    pass
print ('[+] OK')


print ('[+] Add http host test')

uri = URL + "/add_http_host"
purge_success(uri + "/10/*", {'Host': 'purge_folder',
    'X-Purge-Options': 'delete'})
purge_success(uri + "/11/*", {'Host': 'purge_folder',
    'X-Purge-Options': 'delete', 'X-Cache-Host': 'x.bar.com'})
purge_success(uri + "/12/*", {'Host': 'purge_folder',
    'X-Purge-Options': 'delete', 'X-Cache-Host': 'y.bar.com'})
_, res = purge_success(URL + "/*", {"X-Purge-Options": "dump"})
expected = iter([ {"flags":1045,"mask":"/add_http_host/10/*","domain":"purge_folder"},
                  {"flags":1045,"mask":"/add_http_host/11/*","domain":"x.bar.com"},
                  {"flags":1045,"mask":"/add_http_host/12/*","domain":"y.bar.com"}
                  ])
for r in json.loads(res):
    e = next(expected)
    assert r['flags'] == e['flags'], \
            "expecting {}, got {}".format(e['flags'], r['flags'])
    assert r['mask'] == e['mask'],\
            "expecting {}, got {}".format(e['mask'], r['mask'])
    assert r['domain'] == e['domain'],\
            "expecting {}, got {}".format(e['domain'], r['domain'])
l = int(os.popen('cat {} | wc -l'.format(MASKS_STORAGE)).read().split()[0])
assert l == 3, "expecting 3 lines, got {}".format(l)
print ('[+] OK')
