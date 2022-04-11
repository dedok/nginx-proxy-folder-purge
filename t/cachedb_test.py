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

#
# Description:
# This tests is about testing some foreground masks storage cases
#
# The test requires that nginx will be started with
# `conf/foreground_process_prune.conf`.
#
#

print ('[!] WARNINGS.\n'
        '- Be sure, that background purge is off!\n' +
        '- This test expectes nginx builded with an option NGX_DEBUG 1\n')

URL = "http://127.0.0.1:8082"
MASKS_STORAGE = "./test-root/cachedb/cache.*"
CACHE = "./test-root/cache/*"

print ('[+] Flush & Cleanup')
purge_success(URL + "/*", {"X-Cache-Prune": "invalidate-reset"})
try:
    os.popen('rm -Rf {}'.format(MASKS_STORAGE))
except:
    pass
try:
    os.popen('rm -Rf {}'.format(CACHE))
except:
    pass
print ('[+] OK')

def read_cachedb():
    res = []
    for raw_mask in os.popen('cat {}'.format(MASKS_STORAGE)).read().split():
        magic, domain, mask, flags, timestamp = raw_mask.split(',')
        res.append({'magic': magic, 'domain': domain, 'mask': mask,
            'flags': int(flags), 'timestamp': int(timestamp)})
    return res

print ('[+] NCCS-728')
uri = URL + "/foreground_process_prune_on/"
purge_success(uri + "*", {'Host': 'purge_folder',
    "X-Cache-Prune": "delete"})
time.sleep(1)
purge_success(uri + "*", {'Host': 'purge_folder',
    "X-Cache-Prune": "delete"})
r = read_cachedb()
assert len(r) == 2, 'expected 2 rows'
assert r[0]['timestamp'] != r[1]['timestamp'], 'regression, timestamps are '\
        'eqal'
print ('[+] OK')

