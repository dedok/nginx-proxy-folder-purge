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
MASKS_STORAGE = "./test-root/masks_storage/masks.in*"
CACHE = "./test-root/cache/*"

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


# An issue: NCCS-738 {{{
print ('[+] NCCS-738')
uri = URL + "/"
_, _, h = get_success(uri + 't1.html', {
    "Host": "slice_noshare.com",
    "Pragma": "X-Cache-Status, X-Cache-Key, X-Check-Cacheable"})
purge_success(uri + '*', {'Host': 'slice_noshare.com'})
time.sleep(3)
_, _, h = get_success(uri + 't1.html', {
    "Host": "slice_noshare.com",
    "Pragma": "X-Cache-Status, X-Cache-Key, X-Check-Cacheable"})
assert h['x-cache-status'] == 'EXPIRED', 'wrong cache status'
time.sleep(3)
purge_success(uri + '*.html', {'Host': 'slice_noshare.com'})
_, _, h = get_success(uri + 't1.html', {
    "Host": "slice_noshare.com",
    "Pragma": "X-Cache-Status, X-Cache-Key, X-Check-Cacheable"})
assert h['x-cache-status'] == 'EXPIRED', 'wrong cache status'
print ('[+] OK')
# }}}
