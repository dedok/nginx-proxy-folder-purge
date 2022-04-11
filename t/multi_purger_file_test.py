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
# The test requires that nginx will be started with
# `conf/foreground_purge.conf`.
#
# The goal of this test is checking that masks storage works well.
#

print ('[!] WARNINGS.\n'
        '- Be sure, that background purge is off!\n' +
        '- This test expectes nginx builded with an option NGX_DEBUG 1\n' +
        '- This test expectes worker count is over 1\n')

URL = "http://127.0.0.1:8082"
MASKS_STORAGE = "./test-root/masks_storage/masks.purger*"
CACHE = "./test-root/cache/*"
DELAY = 3

print ('[+] get worker count')
cnt = int(os.popen('ps -ef | grep -e "nginx: worker process" | grep -v "grep" | wc -l').read().split()[0])
print ('[+] worker count={}'.format(cnt))
print ('[+] OK')


print ('[+] send folder purge request {} times'.format(cnt * 3))
for i in range(cnt):
    url = URL + "/" + str(i) + "/test.html"
    get_success(url, {'Host': 'purge_folder'})
for i in range(cnt * 3):
    url = URL + "/" + str(i) + "/*"
    purge_success(url, {"Host": "purge_folder"})
print ('[+] OK')

time.sleep(DELAY)

print ('[+] expects over 1')
l = int(os.popen('ls -al {} | wc -l'.format(MASKS_STORAGE)).read().split()[0])
assert l > 1, "expecting over 1, got {}".format(l)
print ('[+] OK')

time.sleep(DELAY * cnt * 2)

print ('[+] check cache status')
for i in range(cnt):
    url = URL + "/" + str(i) + "/test.html"
    a, cached_2, b = get_success(url, {'Host': 'purge_folder'})
    assert b['x-cache-status'] == 'MISS', 'wrong cache status'
print ('[+] OK')
