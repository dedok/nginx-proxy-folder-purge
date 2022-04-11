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

#
# Description:
# Allows adding masks for the foreground purge: adding some content to the
# nginx cache and checking the foreground purge execution.
#
# The test requires that nginx will be started with
# `conf/foreground_purge.conf`.
#
# The goal of this test is checking that the foreground purge work.
#

print ('[!] WARNINGS.\n'
        '- Be sure, that background purge is off!\n' +
        '- This test expectes nginx builded with an option NGX_DEBUG 1\n')

URL = "http://127.0.0.1:8082"
MASKS_STORAGE = "../../../test/masks_storage/masks.in*"
CACHE = "../../../test/cache/*"

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


print ('[+] foreground_purge off test')
uri = URL + "/foreground_purge_off/"
_, cached, _ = get_success(uri + 'file.txt', {'Host': 'purge_folder'})
time.sleep(1)
purge_success(uri + "*", {'Host': 'purge_folder',
    "X-Purge-Options": "delete"})
_, cached_2, b = get_success(uri + 'file.txt', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
assert cached == cached_2, "cached != cached_2"
_, cached_2, b = get_success(uri + 'file.txt', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
assert cached == cached_2, "cached != cached_2"
_, cached_2, b = get_success(uri + 'file.txt', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
assert cached == cached_2, "cached != cached_2"
print ('[+] OK')


print ('[+] foreground_purge on test')
uri = URL + "/foreground_purge_on/"
_, cached, _ = get_success(uri + 'file.txt', {'Host': 'purge_folder'})
time.sleep(1)
purge_success(uri + "*", {'Host': 'purge_folder',
    "X-Purge-Options": "delete"})
a, cached_2, b = get_success(uri + 'file.txt', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'EXPIRED', 'wrong cache status'
assert cached != cached_2, 'content equals'
print ('[+] OK')


print ('[+] foreground_purge on default test')
uri = URL + "/foreground_purge_on_default/"
_, cached, _ = get_success(uri + 'file.txt', {'Host': 'purge_folder'})
time.sleep(1)
purge_success(uri + "*", {'Host': 'purge_folder',
    "X-Purge-Options": "delete"})
a, cached_2, b = get_success(uri + 'file.txt', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'EXPIRED', 'wrong cache status'
assert cached != cached_2, 'content equals'
print ('[+] OK')


# Issue: NCCS-644 {{{
print ('[+] Delete recursive')
uri = URL + "/foreground_purge_on/root/"
_, cached, _ = get_success(uri + 'root_file.txt', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + 'folder/file.txt', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + 'folder/subfolder/file.txt',
        {'Host': 'purge_folder'})
time.sleep(1)
purge_success(uri + "folder/*", {'Host': 'purge_folder',
    "X-Purge-Options": "delete-recursive"})
a, cached_2, b = get_success(uri + 'root_file.txt', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
a, cached_2, b = get_success(uri + 'folder/file.txt', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'EXPIRED', 'wrong cache status'
a, cached_2, b = get_success(uri + 'folder/subfolder/file.txt',
        {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'EXPIRED', 'wrong cache status'
print ('[+] OK')


print ('[+] Invalidate recursive')
uri = URL + "/foreground_purge_on/root1/"
_, cached, _ = get_success(uri + 'root_file.txt', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + 'folder/file.txt', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + 'folder/subfolder/file.txt',
        {'Host': 'purge_folder'})
time.sleep(1)
purge_success(uri + "folder/*", {'Host': 'purge_folder',
    "X-Purge-Options": "invalidate-recursive"})
a, cached_2, b = get_success(uri + 'root_file.txt', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
a, cached_2, b = get_success(uri + 'folder/file.txt', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'EXPIRED', 'wrong cache status'
a, cached_2, b = get_success(uri + 'folder/subfolder/file.txt',
        {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'EXPIRED', 'wrong cache status'
print ('[+] OK')

print ('[+] Delete non recursive')
uri = URL + "/foreground_purge_on/root3/"
_, cached, _ = get_success(uri + 'root_file.txt', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + 'folder/file.txt', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + 'folder/subfolder/file.txt',
        {'Host': 'purge_folder'})
time.sleep(1)
purge_success(uri + "*", {'Host': 'purge_folder',
    "X-Purge-Options": "delete"})
a, cached_2, b = get_success(uri + 'root_file.txt', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'EXPIRED', 'wrong cache status'
a, cached_2, b = get_success(uri + 'folder/file.txt', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
a, cached_2, b = get_success(uri + 'folder/subfolder/file.txt',
        {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
print ('[+] OK')


print ('[+] Invalidate non recursive')
uri = URL + "/foreground_purge_on/root4/"
_, cached, _ = get_success(uri + 'root_file.txt', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + 'folder/file.txt', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + 'folder/subfolder/file.txt',
        {'Host': 'purge_folder'})
time.sleep(1)
purge_success(uri + "*", {'Host': 'purge_folder',
    "X-Purge-Options": "invalidate"})
a, cached_2, b = get_success(uri + 'root_file.txt', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'EXPIRED', 'wrong cache status'
a, cached_2, b = get_success(uri + 'folder/file.txt', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
a, cached_2, b = get_success(uri + 'folder/subfolder/file.txt',
        {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
print ('[+] OK')
# }}}

print ('[+] invalidate-recursive + ext')
uri = URL + "/foreground_purge_on/root5/"
_, cached, _ = get_success(uri + 'root_file.txt', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + 'folder/file.txt', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + 'folder/subfolder/file.x_txt',
        {'Host': 'purge_folder'})
time.sleep(1)
purge_success(uri + "/*.txt", {'Host': 'purge_folder',
    "X-Purge-Options": "invalidate-recursive"})
a, cached_2, b = get_success(uri + 'root_file.txt', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'EXPIRED', 'wrong cache status'
a, cached_2, b = get_success(uri + 'folder/file.txt', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'EXPIRED', 'wrong cache status'
a, cached_2, b = get_success(uri + 'folder/subfolder/file.x_txt',
        {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
print ('[+] OK')


print ('[+] delete-recursive + ext')
uri = URL + "/foreground_purge_on/root6/"
_, cached, _ = get_success(uri + 'root_file.txt', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + 'folder/file.txt', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + 'folder/subfolder/file.x_txt',
        {'Host': 'purge_folder'})
time.sleep(1)
purge_success(uri + "/*.txt", {'Host': 'purge_folder',
    "X-Purge-Options": "delete-recursive"})
a, cached_2, b = get_success(uri + 'root_file.txt', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'EXPIRED', 'wrong cache status'
a, cached_2, b = get_success(uri + 'folder/file.txt', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'EXPIRED', 'wrong cache status'
a, cached_2, b = get_success(uri + 'folder/subfolder/file.x_txt',
        {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
print ('[+] OK')


# Issue: NCCS-673 {{{
print ('[+] Trailing slashes delete recursive')
uri = URL + "/foreground_purge_on/"
_, cached, _ = get_success(uri + '/5/4/3/2/1/', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + '/5/4/3/2/1', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + '/5/4/3/2/', {'Host': 'purge_folder'})
time.sleep(1)
purge_success(uri + "/5/4/3/2/1/*", {'Host': 'purge_folder',
    "X-Purge-Options": "delete-recursive"})
a, cached_2, b = get_success(uri + '/5/4/3/2/1/', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'EXPIRED', 'wrong cache status'
a, cached_2, b = get_success(uri + '/5/4/3/2/1', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
a, cached_2, b = get_success(uri + '/5/4/3/2/', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
print ('[+] OK')


print ('[+] Trailing slashes invalidate recursive')
uri = URL + "/foreground_purge_on/"
_, cached, _ = get_success(uri + '/6/4/3/2/1/', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + '/6/4/3/2/1', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + '/6/4/3/2/', {'Host': 'purge_folder'})
time.sleep(1)
purge_success(uri + "/6/4/3/2/1/*", {'Host': 'purge_folder',
    "X-Purge-Options": "invalidate-recursive"})
a, cached_2, b = get_success(uri + '/6/4/3/2/1/', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'EXPIRED', 'wrong cache status'
a, cached_2, b = get_success(uri + '/6/4/3/2/1', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
a, cached_2, b = get_success(uri + '/6/4/3/2/', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
print ('[+] OK')


print ('[+] Trailing slashes delete')
uri = URL + "/foreground_purge_on/"
_, cached, _ = get_success(uri + '/7/4/3/2/1/', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + '/7/4/3/2/1/a/', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + '/7/4/3/2/', {'Host': 'purge_folder'})
time.sleep(1)
purge_success(uri + "/7/4/3/2/1/*", {'Host': 'purge_folder',
    "X-Purge-Options": "delete"})
a, cached_2, b = get_success(uri + '/7/4/3/2/1/', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'EXPIRED', 'wrong cache status'
a, cached_2, b = get_success(uri + '/7/4/3/2/1/a/', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
a, cached_2, b = get_success(uri + '/7/4/3/2/', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
print ('[+] OK')


print ('[+] Trailing slashes invalidate')
uri = URL + "/foreground_purge_on/"
_, cached, _ = get_success(uri + '/8/4/3/2/1/', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + '/8/4/3/2/1/a/', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + '/8/4/3/2/', {'Host': 'purge_folder'})
time.sleep(1)
purge_success(uri + "/8/4/3/2/1/*", {'Host': 'purge_folder',
    "X-Purge-Options": "invalidate"})
a, cached_2, b = get_success(uri + '/8/4/3/2/1/', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'EXPIRED', 'wrong cache status'
a, cached_2, b = get_success(uri + '/8/4/3/2/1/a/', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
a, cached_2, b = get_success(uri + '/8/4/3/2/', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
print ('[+] OK')
# }}}


# Issue: NCCS-680 {{{
print ('[+] The folder purge method "domain/folder/*.ext" doesn\'t ...')
uri = URL + "/foreground_purge_on/9/"
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
time.sleep(1)
purge_success(uri + "/4/3/2/1/*.html", {'Host': 'purge_folder',
    "X-Purge-Options": "delete"})
_, cached, b = get_success(uri + '4/3/2/1/', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
_, cached, b = get_success(uri + '4/3/2/1/t1.html', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'EXPIRED', 'wrong cache status'
_, cached, b = get_success(uri + '4/3/2/1/t2.html', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'EXPIRED', 'wrong cache status'
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
uri = URL + "/foreground_purge_on/upst/delete/"
# XXX call get twise, because we have to ensure that file has been cached.
get_success(uri + 'file.txt', {'Host': 'purge_folder'})
_, _, h = get_success(uri + 'file.txt', {'Host': 'purge_folder'})
assert h['x-cache-status'] == 'HIT', 'wrong cache status'
purge_success(uri + "*", {'Host': 'purge_folder', "X-Purge-Options": "delete"})
_, _, h = get_success(uri + 'file.txt', {'Host': 'purge_folder'})
assert h['x-cache-status'] == 'EXPIRED', 'wrong cache status'
purge_success(uri + "*", {'Host': 'purge_folder', "X-Purge-Options": "delete"})
_, _, h = get_success(uri + 'file.txt', {'Host': 'purge_folder'})
assert h['x-cache-status'] == 'EXPIRED', 'wrong cache status'
print ('[+] OK')

print ('[+] invalidate')
uri = URL + "/foreground_purge_on/upst/invalidate/"
# XXX call get twise, because we have to ensure that file has been cached.
get_success(uri + 'file.txt', {'Host': 'purge_folder'})
_, _, h = get_success(uri + 'file.txt', {'Host': 'purge_folder'})
assert h['x-cache-status'] == 'HIT', 'wrong cache status'
purge_success(uri + "*", {'Host': 'purge_folder',
    "X-Purge-Options": "invalidate"})
_, _, h = get_success(uri + 'file.txt', {'Host': 'purge_folder'})
assert h['x-cache-status'] == 'EXPIRED', 'wrong cache status'
purge_success(uri + "*", {'Host': 'purge_folder',
    "X-Purge-Options": "invalidate"})
_, _, h = get_success(uri + 'file.txt', {'Host': 'purge_folder'})
assert h['x-cache-status'] == 'EXPIRED', 'wrong cache status'
print ('[+] OK')

print ('[+] delete-recursive')
uri = URL + "/foreground_purge_on/upst/delete-recursive/"

get_success(uri + 'file.txt', {'Host': 'purge_folder'})
_, _, h = get_success(uri + 'file.txt', {'Host': 'purge_folder'})
assert h['x-cache-status'] == 'HIT', 'wrong cache status'
get_success(uri + 'folder/file.txt', {'Host': 'purge_folder'})
_, _, h = get_success(uri + 'folder/file.txt', {'Host': 'purge_folder'})
assert h['x-cache-status'] == 'HIT', 'wrong cache status'
purge_success(uri + "/folder/*", {'Host': 'purge_folder',
    "X-Purge-Options": "delete-recursive"})
_, _, h = get_success(uri + 'file.txt', {'Host': 'purge_folder'})
assert h['x-cache-status'] == 'HIT', 'wrong cache status'
_, _, h = get_success(uri + '/folder/file.txt', {'Host': 'purge_folder'})
assert h['x-cache-status'] == 'EXPIRED', 'wrong cache status'

purge_success(uri + "/folder/*", {'Host': 'purge_folder',
    "X-Purge-Options": "delete-recursive"})
_, _, h = get_success(uri + 'file.txt', {'Host': 'purge_folder'})
assert h['x-cache-status'] == 'HIT', 'wrong cache status'
_, _, h = get_success(uri + '/folder/file.txt', {'Host': 'purge_folder'})
assert h['x-cache-status'] == 'EXPIRED', 'wrong cache status'
print ('[+] OK')


print ('[+] invalidate-recursive')
uri = URL + "/foreground_purge_on/upst/invalidate-recursive/"

get_success(uri + 'file.txt', {'Host': 'purge_folder'})
_, _, h = get_success(uri + 'file.txt', {'Host': 'purge_folder'})
assert h['x-cache-status'] == 'HIT', 'wrong cache status'
get_success(uri + 'folder/file.txt', {'Host': 'purge_folder'})
_, _, h = get_success(uri + 'folder/file.txt', {'Host': 'purge_folder'})
assert h['x-cache-status'] == 'HIT', 'wrong cache status'
purge_success(uri + "/folder/*", {'Host': 'purge_folder',
    "X-Purge-Options": "invalidate-recursive"})
_, _, h = get_success(uri + 'file.txt', {'Host': 'purge_folder'})
assert h['x-cache-status'] == 'HIT', 'wrong cache status'
_, _, h = get_success(uri + '/folder/file.txt', {'Host': 'purge_folder'})
assert h['x-cache-status'] == 'EXPIRED', 'wrong cache status'

purge_success(uri + "/folder/*", {'Host': 'purge_folder',
    "X-Purge-Options": "invalidate-recursive"})
_, _, h = get_success(uri + 'file.txt', {'Host': 'purge_folder'})
assert h['x-cache-status'] == 'HIT', 'wrong cache status'
_, _, h = get_success(uri + '/folder/file.txt', {'Host': 'purge_folder'})
assert h['x-cache-status'] == 'EXPIRED', 'wrong cache status'
print ('[+] OK')


print ('[+] OK')
# }}}

# TODO fixme
# NCCS-707 {{{
#print ('[+] NCCS-707')
#uri = URL + "/"
#_, _, h = get_success(uri + 't1.html', {
#    "Host": "slice_noshare.com",
#    "Pragma": "X-Cache-Status, X-Cache-Key, X-Check-Cacheable"})
#purge_success(uri + '*', {'Host': 'slice_noshare.com'})
#time.sleep(3)
#_, _, h = get_success(uri + 't1.html', {
#    "Host": "slice_noshare.com",
#    "Pragma": "X-Cache-Status, X-Cache-Key, X-Check-Cacheable"})
#assert h['x-cache-status'] == 'EXPIRED', 'wrong cache status'
#time.sleep(3)
#purge_success(uri + '*.html', {'Host': 'slice_noshare.com'})
#_, _, h = get_success(uri + 't1.html', {
#    "Host": "slice_noshare.com",
#    "Pragma": "X-Cache-Status, X-Cache-Key, X-Check-Cacheable"})
#assert h['x-cache-status'] == 'EXPIRED', 'wrong cache status'
#print ('[+] OK')
# }}}
