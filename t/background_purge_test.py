#!/usr/bin/env python2

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
DELAY = 20
URL = "http://127.0.0.1:8082"
MASKS_STORAGE = "./test-root/masks_storage/masks.in*"
CACHE = ".test-root/cache/*"

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
#print ("updated", result_updated)
#print ("cached", result_cached)

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
#print ("updated", ext_updated)
#print ("cached", ext_cached)

for k in ext2_updated:
    if ext2_cached[k] != ext2_updated[k]:
        assert True, '[ext2] cached != updated, key = {}, c = {}, u = {}'.\
            format(k, ext2_cached[k], ext2_updated[k])
#print ("updated", ext2_updated)
#print ("cached", ext2_cached)

for k in b_updated:
    if b_cached[k] != b_updated[k]:
        assert True, '[b] cached != updated, key = {}, c = {}, u = {}'.\
            format(k, b_cached[k], b_updated[k])
#print ("updated", b_updated)
#print ("cached", b_cached)
print ('[+] OK')

# Issue: NCCS-644 {{{
print ('[+] Delete recursive')
uri = URL + "/background_purge_on/root/"
_, cached, _ = get_success(uri + 'root_file.txt', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + 'folder/file.txt', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + 'folder/subfolder/file.txt',
        {'Host': 'purge_folder'})
time.sleep(1)
purge_success(uri + "folder/*", {'Host': 'purge_folder',
    "X-Purge-Options": "delete-recursive"})
time.sleep(DELAY)
a, cached_2, b = get_success(uri + 'root_file.txt', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
a, cached_2, b = get_success(uri + 'folder/file.txt', {'Host': 'purge_folder'})
print(b['x-cache-status'])
assert b['x-cache-status'] == 'MISS', 'wrong cache status'
a, cached_2, b = get_success(uri + 'folder/subfolder/file.txt',
        {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'MISS', 'wrong cache status'
print ('[+] OK')


print ('[+] Invalidate recursive')
uri = URL + "/background_purge_on/root1/"
_, cached, _ = get_success(uri + 'root_file.txt', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + 'folder/file.txt', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + 'folder/subfolder/file.txt',
        {'Host': 'purge_folder'})
time.sleep(1)
purge_success(uri + "folder/*", {'Host': 'purge_folder',
    "X-Purge-Options": "invalidate-recursive"})
time.sleep(DELAY)
a, cached_2, b = get_success(uri + 'root_file.txt', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
a, cached_2, b = get_success(uri + 'folder/file.txt', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'EXPIRED', 'wrong cache status'
a, cached_2, b = get_success(uri + 'folder/subfolder/file.txt',
        {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'EXPIRED', 'wrong cache status'
print ('[+] OK')

print ('[+] Delete non recursive')
uri = URL + "/background_purge_on/root3/"
_, cached, _ = get_success(uri + 'root_file.txt', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + 'folder/file.txt', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + 'folder/subfolder/file.txt',
        {'Host': 'purge_folder'})
time.sleep(1)
purge_success(uri + "*", {'Host': 'purge_folder',
    "X-Purge-Options": "delete"})
time.sleep(DELAY)
a, cached_2, b = get_success(uri + 'root_file.txt', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'MISS', 'wrong cache status'
a, cached_2, b = get_success(uri + 'folder/file.txt', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
a, cached_2, b = get_success(uri + 'folder/subfolder/file.txt',
        {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
print ('[+] OK')


print ('[+] Invalidate non recursive')
uri = URL + "/background_purge_on/root4/"
_, cached, _ = get_success(uri + 'root_file.txt', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + 'folder/file.txt', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + 'folder/subfolder/file.txt',
        {'Host': 'purge_folder'})
time.sleep(1)
purge_success(uri + "*", {'Host': 'purge_folder',
    "X-Purge-Options": "invalidate"})
time.sleep(2)
a, cached_2, b = get_success(uri + 'root_file.txt', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'EXPIRED', 'wrong cache status'
a, cached_2, b = get_success(uri + 'folder/file.txt', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
a, cached_2, b = get_success(uri + 'folder/subfolder/file.txt',
        {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
print ('[+] OK')
# }}}

## An issue: NCCS-667 {{{
print ('[+] Background purge should not work recursively by default')

uri = URL + "/1/"

print ('[+] Options delete')
_, cached, _ = get_success(uri + 'a_file.txt', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + 'a_file_1.txt', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + 'subfolder/a_file.txt',
        {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + 'subfolder/a_file_1.txt',
        {'Host': 'purge_folder'})
purge_success(uri + "*", {'Host': 'purge_folder',
    "X-Purge-Options": "delete"})
time.sleep(DELAY)
a, cached_2, b = get_success(uri + 'a_file.txt', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'MISS', 'wrong cache status'
a, cached_2, b = get_success(uri + 'a_file_1.txt', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'MISS', 'wrong cache status'
a, cached_2, b = get_success(uri + 'subfolder/a_file.txt',
        {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
a, cached_2, b = get_success(uri + 'subfolder/a_file_1.txt',
        {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
print ('[+] OK')

print ('[+] Options invalidate')
uri = URL + "/2/"
_, cached, _ = get_success(uri + 'a_file.txt', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + 'a_file_1.txt', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + 'subfolder/a_file.txt',
        {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + 'subfolder/a_file_1.txt',
        {'Host': 'purge_folder'})
purge_success(uri + "*", {'Host': 'purge_folder',
    'X-Purge-Options': 'invalidate'})
time.sleep(DELAY)
a, cached_2, b = get_success(uri + 'a_file.txt', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'EXPIRED', 'wrong cache status'
a, cached_2, b = get_success(uri + 'a_file_1.txt', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'EXPIRED', 'wrong cache status'
a, cached_2, b = get_success(uri + 'subfolder/a_file.txt',
        {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
a, cached_2, b = get_success(uri + 'subfolder/a_file_1.txt',
        {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'

print ('[+] OK')
# }}}


# Issue: NCCS-680 {{{
print ('[+] The folder purge method "domain/folder/*.ext" doesn\'t ...')
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
time.sleep(DELAY)
_, cached, b = get_success(uri + '4/3/2/1/', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
_, cached, b = get_success(uri + '4/3/2/1/t1.html', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'MISS', 'wrong cache status'
_, cached, b = get_success(uri + '4/3/2/1/t2.html', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'MISS', 'wrong cache status'
_, cached, b = get_success(uri + '4/3/2/1/t2.htm', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
_, cached, b = get_success(uri + '4/3/2/1/t2.htm', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
_, cached, b = get_success(uri + '4/3/2/1/t2.tml', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
_, cached, b = get_success(uri + '4/3/2/1/t2htm', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
_, cached, b = get_success(uri + '4/3/2/1/t2html', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
_, cached, b = get_success(uri + '4/3/2/1/html', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
_, cached, b = get_success(uri + '4/3/2/1/t2.txt', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
_, cached, b = get_success(uri + '4/3/2/1/t2', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
print ('[+] OK')
# }}}


# Issue: NCCS-654 {{{
print ('[+] Update purge start time')

print ('[+] delete')
uri = URL + "/background_purge/upst/delete/"
# XXX call get twise, because we have to ensure that file has been cached.
get_success(uri + 'file.txt', {'Host': 'purge_folder'})
_, _, h = get_success(uri + 'file.txt', {'Host': 'purge_folder'})
assert h['x-cache-status'] == 'HIT', 'wrong cache status'
purge_success(uri + "*", {'Host': 'purge_folder', "X-Purge-Options": "delete"})
time.sleep(DELAY)
_, _, h = get_success(uri + 'file.txt', {'Host': 'purge_folder'})
assert h['x-cache-status'] == 'MISS', 'wrong cache status'
purge_success(uri + "*", {'Host': 'purge_folder', "X-Purge-Options": "delete"})
time.sleep(DELAY)
_, _, h = get_success(uri + 'file.txt', {'Host': 'purge_folder'})
assert h['x-cache-status'] == 'MISS', 'wrong cache status'
print ('[+] OK')

print ('[+] invalidate')
uri = URL + "/background_purge/upst/invalidate/"
# XXX call get twise, because we have to ensure that file has been cached.
get_success(uri + 'file.txt', {'Host': 'purge_folder'})
_, _, h = get_success(uri + 'file.txt', {'Host': 'purge_folder'})
assert h['x-cache-status'] == 'HIT', 'wrong cache status'
purge_success(uri + "*", {'Host': 'purge_folder',
    "X-Purge-Options": "invalidate"})
time.sleep(DELAY)
_, _, h = get_success(uri + 'file.txt', {'Host': 'purge_folder'})
assert h['x-cache-status'] == 'EXPIRED', 'wrong cache status'
purge_success(uri + "*", {'Host': 'purge_folder',
    "X-Purge-Options": "invalidate"})
time.sleep(DELAY)
_, _, h = get_success(uri + 'file.txt', {'Host': 'purge_folder'})
assert h['x-cache-status'] == 'EXPIRED', 'wrong cache status'
print ('[+] OK')

print ('[+] delete-recursive')
uri = URL + "/background_purge/upst/delete-recursive/"

get_success(uri + 'file.txt', {'Host': 'purge_folder'})
_, _, h = get_success(uri + 'file.txt', {'Host': 'purge_folder'})
assert h['x-cache-status'] == 'HIT', 'wrong cache status'
get_success(uri + 'folder/file.txt', {'Host': 'purge_folder'})
_, _, h = get_success(uri + 'folder/file.txt', {'Host': 'purge_folder'})
assert h['x-cache-status'] == 'HIT', 'wrong cache status'
purge_success(uri + "/folder/*", {'Host': 'purge_folder',
    "X-Purge-Options": "delete-recursive"})
time.sleep(DELAY)
_, _, h = get_success(uri + 'file.txt', {'Host': 'purge_folder'})
assert h['x-cache-status'] == 'HIT', 'wrong cache status'
_, _, h = get_success(uri + '/folder/file.txt', {'Host': 'purge_folder'})
assert h['x-cache-status'] == 'MISS', 'wrong cache status'

purge_success(uri + "/folder/*", {'Host': 'purge_folder',
    "X-Purge-Options": "delete-recursive"})
time.sleep(DELAY)
_, _, h = get_success(uri + 'file.txt', {'Host': 'purge_folder'})
assert h['x-cache-status'] == 'HIT', 'wrong cache status'
_, _, h = get_success(uri + '/folder/file.txt', {'Host': 'purge_folder'})
assert h['x-cache-status'] == 'MISS', 'wrong cache status'
print ('[+] OK')


print ('[+] invalidate-recursive')
uri = URL + "/background_purge/upst/invalidate-recursive/"

get_success(uri + 'file.txt', {'Host': 'purge_folder'})
_, _, h = get_success(uri + 'file.txt', {'Host': 'purge_folder'})
assert h['x-cache-status'] == 'HIT', 'wrong cache status'
get_success(uri + 'folder/file.txt', {'Host': 'purge_folder'})
_, _, h = get_success(uri + 'folder/file.txt', {'Host': 'purge_folder'})
assert h['x-cache-status'] == 'HIT', 'wrong cache status'
purge_success(uri + "/folder/*", {'Host': 'purge_folder',
    "X-Purge-Options": "invalidate-recursive"})
time.sleep(DELAY)
_, _, h = get_success(uri + 'file.txt', {'Host': 'purge_folder'})
assert h['x-cache-status'] == 'HIT', 'wrong cache status'
_, _, h = get_success(uri + '/folder/file.txt', {'Host': 'purge_folder'})
assert h['x-cache-status'] == 'EXPIRED', 'wrong cache status'

purge_success(uri + "/folder/*", {'Host': 'purge_folder',
    "X-Purge-Options": "invalidate-recursive"})
time.sleep(DELAY)
_, _, h = get_success(uri + 'file.txt', {'Host': 'purge_folder'})
assert h['x-cache-status'] == 'HIT', 'wrong cache status'
_, _, h = get_success(uri + '/folder/file.txt', {'Host': 'purge_folder'})
assert h['x-cache-status'] == 'EXPIRED', 'wrong cache status'
print ('[+] OK')

print ('[+] Mask deletion, shared memory should be empty')
time.sleep(DELAY)
_, out = purge_success(uri + "/folder/*", {'Host': 'purge_folder',
    "X-Purge-Options": "dump"})
res = json.loads(out)
assert res == [], 'shared memory isn\'t empty'
print ('[+] OK')
# }}}

