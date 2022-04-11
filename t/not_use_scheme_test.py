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

print ('[+] Not use scheme')

print ('[+] Absent X-Cache-Scheme header')
uri = URL + "/not_use_scheme/1"
_, cached, _ = get_success(uri + '/test-1.txt', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + '/test-2.txt', {'Host': 'purge_folder',
    'X-Forwarded-Scheme': 'http'})
_, cached, _ = get_success(uri + '/test-3.txt', {'Host': 'purge_folder',
    'X-Forwarded-Scheme': 'https'})
purge_success(uri + "/*", {'Host': 'purge_folder',
    'X-Purge-Options': 'delete'})
time.sleep(DELAY)
a, cached_2, b = get_success(uri + '/test-1.txt', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'MISS', 'wrong cache status'
a, cached_2, b = get_success(uri + '/test-2.txt', {'Host': 'purge_folder',
    'X-Forwarded-Scheme': 'http'})
assert b['x-cache-status'] == 'MISS', 'wrong cache status'
a, cached_2, b = get_success(uri + '/test-3.txt', {'Host': 'purge_folder',
    'X-Forwarded-Scheme': 'https'})
assert b['x-cache-status'] == 'MISS', 'wrong cache status'
print ('[+] OK')

print ('[+] X-Cache-Scheme: http')
uri = URL + "/not_use_scheme/2"
_, cached, _ = get_success(uri + '/test-1.txt', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + '/test-2.txt', {'Host': 'purge_folder',
    'X-Forwarded-Scheme': 'http'})
_, cached, _ = get_success(uri + '/test-3.txt', {'Host': 'purge_folder',
    'X-Forwarded-Scheme': 'https'})
purge_success(uri + "/*", {'Host': 'purge_folder',
    'X-Purge-Options': 'delete', 'X-Cache-Scheme': 'http'})
time.sleep(DELAY)
a, cached_2, b = get_success(uri + '/test-1.txt', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'MISS', 'wrong cache status'
a, cached_2, b = get_success(uri + '/test-2.txt', {'Host': 'purge_folder',
    'X-Forwarded-Scheme': 'http'})
assert b['x-cache-status'] == 'MISS', 'wrong cache status'
a, cached_2, b = get_success(uri + '/test-3.txt', {'Host': 'purge_folder',
    'X-Forwarded-Scheme': 'https'})
assert b['x-cache-status'] == 'MISS', 'wrong cache status'
print ('[+] OK')

print ('[+] X-Cache-Scheme: https')
uri = URL + "/not_use_scheme/3"
_, cached, _ = get_success(uri + '/test-1.txt', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + '/test-2.txt', {'Host': 'purge_folder',
    'X-Forwarded-Scheme': 'http'})
_, cached, _ = get_success(uri + '/test-3.txt', {'Host': 'purge_folder',
    'X-Forwarded-Scheme': 'https'})
purge_success(uri + "/*", {'Host': 'purge_folder',
    'X-Purge-Options': 'delete', 'X-Cache-Scheme': 'https'})
time.sleep(DELAY)
a, cached_2, b = get_success(uri + '/test-1.txt', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'MISS', 'wrong cache status'
a, cached_2, b = get_success(uri + '/test-2.txt', {'Host': 'purge_folder',
    'X-Forwarded-Scheme': 'http'})
assert b['x-cache-status'] == 'MISS', 'wrong cache status'
a, cached_2, b = get_success(uri + '/test-3.txt', {'Host': 'purge_folder',
    'X-Forwarded-Scheme': 'https'})
assert b['x-cache-status'] == 'MISS', 'wrong cache status'
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

print ('[+] Add not use scheme test')
uri = URL + "/not_use_scheme"
purge_success(uri + "/10/*", {'Host': 'purge_folder',
    'X-Purge-Options': 'delete'})
purge_success(uri + "/11/*", {'Host': 'purge_folder',
    'X-Purge-Options': 'delete', 'X-Cache-Scheme': 'http'})
purge_success(uri + "/12/*", {'Host': 'purge_folder',
    'X-Purge-Options': 'delete', 'X-Cache-Scheme': 'https'})
_, res = purge_success(URL + "/*", {"X-Purge-Options": "dump"})
expected = iter([ {"flags":21,"mask":"/not_use_scheme/12/*"},
                  {"flags":21,"mask":"/not_use_scheme/11/*"},
                  {"flags":21,"mask":"/not_use_scheme/10/*"}
                  ])

for r in json.loads(res):
    e = next(expected)
    assert r['flags'] == e['flags'], \
            "expecting {}, got {}".format(e['flags'], r['flags'])
    assert r['mask'] == e['mask'],\
            "expecting {}, got {}".format(e['mask'], r['mask'])
l = int(os.popen('cat {} | wc -l'.format(MASKS_STORAGE)).read().split()[0])
assert l == 3, "expecting 3 lines, got {}".format(l)
print ('[+] OK')
