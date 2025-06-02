#!/usr/bin/env python3

#
# (C) BSD v2
#

import os
import sys
import json
import time
sys.path.append('./t')
from http_utils import *

#
# Description:
# Testing that purge is working for each requires.
# The test requires that nginx will be started with
# `conf/foreground_purge.conf`.
#

print ('[!] WARNINGS:\n'
        '- Be sure, that background purge is off!\n')

URL = "http://127.0.0.1:8082"
MASKS_STORAGE = sys.argv[1] + "/masks_storage/masks.in*"
CACHE = sys.argv[1] + "/cache/*"

print ('[+] Test "foreground_purge off"')
uri = URL + "/foreground_purge_off/"
_, cached, _ = get_success(uri + 'file.txt', {'Host': 'purge_folder'})
time.sleep(1)
purge_success(uri + "*", {'Host': 'purge_folder'})
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


print ('[+] Test "foreground_purge on"')
uri = URL + "/foreground_purge_on/"
_, _, b = get_success(uri + 'file.txt', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'MISS', 'wrong cache status'
# cached & cached_2 are content of the file, which is time::now()
time.sleep(1)
_, cached, b = get_success(uri + 'file.txt', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
purge_success(uri + "*", {'Host': 'purge_folder'})
a, cached_2, b = get_success(uri + 'file.txt', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'EXPIRED', 'wrong cache status'
assert cached != cached_2, 'content equals'
print ('[+] OK')


print ('[+] Purge a single url test')
uri = URL + "/foreground_purge_on/"
_, cached, _ = get_success(uri + 'qwerasdf', {'Host': 'purge_folder'})
time.sleep(1)
purge_success(uri + "qwer*", {'Host': 'purge_folder'})
a, cached_2, b = get_success(uri + 'qwerasdf', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'EXPIRED', 'wrong cache status'
assert cached != cached_2, 'content equals'
print ('[+] OK')

print ('[+] Test trailing slashes')
uri = URL + "/foreground_purge_on/"
_, cached, _ = get_success(uri + '/7/4/3/2/1/', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + '/7/4/3/2/1/a/', {'Host': 'purge_folder'})
_, cached, _ = get_success(uri + '/7/4/3/2/', {'Host': 'purge_folder'})
time.sleep(1)
purge_success(uri + "/7/4/3/2/1/*", {'Host': 'purge_folder'})
a, cached_2, b = get_success(uri + '/7/4/3/2/1/', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'EXPIRED', 'wrong cache status'
a, cached_2, b = get_success(uri + '/7/4/3/2/1/a/', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'EXPIRED', 'wrong cache status'
a, cached_2, b = get_success(uri + '/7/4/3/2/', {'Host': 'purge_folder'})
assert b['x-cache-status'] == 'HIT', 'wrong cache status'
print ('[+] OK')

print ('[+] Test pattern matching')
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
purge_success(uri + "/4/3/2/1/*.html", {'Host': 'purge_folder'})
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

uri = URL + "/foreground_purge_on/upst/delete/"
# XXX call get twise, because we have to ensure that file has been cached.
get_success(uri + 'file.txt', {'Host': 'purge_folder'})
_, _, h = get_success(uri + 'file.txt', {'Host': 'purge_folder'})
assert h['x-cache-status'] == 'HIT', 'wrong cache status'
purge_success(uri + "*", {'Host': 'purge_folder'})
_, _, h = get_success(uri + 'file.txt', {'Host': 'purge_folder'})
assert h['x-cache-status'] == 'EXPIRED', 'wrong cache status'
purge_success(uri + "*", {'Host': 'purge_folder'})
_, _, h = get_success(uri + 'file.txt', {'Host': 'purge_folder'})
assert h['x-cache-status'] == 'EXPIRED', 'wrong cache status'
print ('[+] OK')

