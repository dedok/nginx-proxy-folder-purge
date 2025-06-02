#!/usr/bin/env python3

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
# This tests for testing _root_ cases
#
# The test requires that nginx will be started with
# `conf/foreground_purge.conf`.
#

print ('[!] WARNINGS.\n'
        '- Be sure, that background purge is off!\n' +
        '- This test expectes nginx builded with an option NGX_DEBUG 1\n')

URL = "http://127.0.0.1:8082"
MASKS_STORAGE = sys.argv[1] + "/masks_storage/masks.in*"
CACHE = sys.argv[1] + "/cache/*"

def read_masks_storage():
    res = []
    for raw_mask in os.popen('cat {}'.format(MASKS_STORAGE)).read().split():
        magic, domain, mask, timestamp = raw_mask.split(',')
        res.append({'magic': magic, 'domain': domain, 'mask': mask,
            'timestamp': int(timestamp)})
    return res

print ('[+] Test root cause with two delete operations')
uri = URL + "/foreground_purge_on/"
purge_success(uri + "/abc/*", {'Host': 'purge_folder'})
time.sleep(1)
purge_success(uri + "/dca/*", {'Host': 'purge_folder'})
r = read_masks_storage()
assert len(r) == 2, 'expected 2 rows'
assert r[0]['timestamp'] != r[1]['timestamp'], 'regression, timestamps are '\
        'eqal'
print ('[+] OK')

