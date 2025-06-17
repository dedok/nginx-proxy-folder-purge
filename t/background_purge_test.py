#!/usr/bin/env python3

#
# (C)
#

import os
import sys
import json
import time
sys.path.append('./t')
from http_utils import *


N = 100
DELAY = 15
URL = "http://127.0.0.1:8082"
MASKS_STORAGE = sys.argv[1] + "/masks_storage/masks.in*"
CACHE = sys.argv[1] + "/purge_folder/*"


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
cleanup()

result_cached = {}

print ('[+] Caching some content ...')
for i in range(1, N):
    uri = URL + "/file_" + str(i)
    a, b, c = get_success(uri, {'Host': 'purge_folder'})
    result_cached[uri] = b
print ('[+] OK')


print ('[+] Purge folder root')
purge_success(URL + "/*", {"Host": "purge_folder",
    "X-Purge-Options": "delete"})
print ('[+] OK')

time.sleep(DELAY)

print ('[+] Checking result ...')
result_updated = {}
for i in range(1, N):
    uri = URL + "/file_" + str(i)
    a, b, c = get_success(uri, {'Host': 'purge_folder'})
    result_updated[uri] = b

for k in result_cached:
    if result_cached[k] != result_updated[k]:
        assert True, 'cached != updated, key = {}, c = {}, u = {}'.\
            format(k, result_cached[k], result_updated[k])
print ('[+] OK')

print ('[+] Check that shared memory should be empty')
time.sleep(60)
_, out = purge_success(URL, {'Host': 'purge_folder',
    "X-Purge-Options": "dump"})
res = json.loads(out)
print (res)
assert res == [], 'shared memory isn\'t empty'
print ('[+] OK')


ext_cached = {}
ext2_cached = {}
b_cached = {}
print ('[+] Caching some content (part 2)...')
for i in range(1, N):
    url = URL + "/a/file_" + str(i) + ".ext"
    a, b, c = get_success(url, {'Host': 'purge_folder'})
    ext_cached[url] = b
    url = URL + "/a/file_" + str(i) + ".ext2"
    a, b, c = get_success(url, {'Host': 'purge_folder'})
    ext2_cached[url] = b
    url = URL + "/b/file_" + str(i)
    a, b, c = get_success(url, {'Host': 'purge_folder'})
    b_cached[url] = b
print ('[+] OK')


print ('[+] Purge folder /a/*')
purge_success(URL + "/a/*.ext", {"Host": "purge_folder",
    "X-Purge-Options": "delete"})
print ('[+] OK')

time.sleep(DELAY)

print ('[+] Checking result ...')
ext_updated = {}
ext2_updated = {}
b_updated = {}
for i in range(1, N):
    url = URL + "/a/file_" + str(i) + ".ext"
    a, b, c = get_success(url, {'Host': 'purge_folder'})
    ext_updated[url] = b
    url = URL + "/a/file_" + str(i) + ".ext2"
    a, b, c = get_success(url, {'Host': 'purge_folder'})
    ext2_updated[url] = b
    url = URL + "/b/file_" + str(i)
    a, b, c = get_success(url, {'Host': 'purge_folder'})
    b_updated[url] = b

for k in ext_updated:
    if ext_cached[k] != ext_updated[k]:
        assert True, '[ext] cached != updated, key = {}, c = {}, u = {}'.\
            format(k, ext_cached[k], ext_updated[k])

for k in ext2_updated:
    if ext2_cached[k] != ext2_updated[k]:
        assert True, '[ext2] cached != updated, key = {}, c = {}, u = {}'.\
            format(k, ext2_cached[k], ext2_updated[k])

for k in b_updated:
    if b_cached[k] != b_updated[k]:
        assert True, '[b] cached != updated, key = {}, c = {}, u = {}'.\
            format(k, b_cached[k], b_updated[k])
print ('[+] OK')

print ('[+] Delete')
uri = URL + "/background_purge_on/root/"
_, cached, _ = get_success(uri + 'root_file.txt', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + 'folder/file.txt', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + 'folder/subfolder/file.txt',
        {'Host': 'purge_folder'})
purge_success(uri + "folder/*", {'Host': 'purge_folder',
    "X-Purge-Options": "delete"})
time.sleep(60)
a, cached_2, b = get_success(uri + 'root_file.txt', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
a, cached_2, b = get_success(uri + 'folder/file.txt', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'MISS', 'wrong cache status'
a, cached_2, b = get_success(uri + 'folder/subfolder/file.txt',
        {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'MISS', 'wrong cache status'
print ('[+] OK')


print ('[+] The folder purge can work with ext')
uri = URL + "/background_purge_on/9/"
_, cached, _ = get_success(uri + '4/3/2/1/', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + '4/3/2/1/t1.html', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + '4/3/2/1/t2.html', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + '4/3/2/1/t2.htm', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + '4/3/2/1/t2.tml', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + '4/3/2/1/t2htm', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + '4/3/2/1/t2html', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + '4/3/2/1/html', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + '4/3/2/1/t2.txt', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + '4/3/2/1/t2', {'Host': 'purge_folder'})
purge_success(uri + "/4/3/2/1/*.html", {'Host': 'purge_folder',
    "X-Purge-Options": "delete"})
time.sleep(60)
_, cached, b = get_success(uri + '4/3/2/1/', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
_, cached, b = get_success(uri + '4/3/2/1/t1.html', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'MISS', 'wrong cache status'
_, cached, b = get_success(uri + '4/3/2/1/t2.html', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'MISS', 'wrong cache status'
_, cached, b = get_success(uri + '4/3/2/1/t2.htm', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
_, cached, b = get_success(uri + '4/3/2/1/t2.tml', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
print ('[+] OK')
# }}}


print ('[+] Chech that shared memory should be empty')
time.sleep(DELAY)
_, out = purge_success(uri, {'Host': 'purge_folder',
    "X-Purge-Options": "dump"})
res = json.loads(out)
print (res)
assert res == [], 'shared memory isn\'t empty'
print ('[+] OK')

