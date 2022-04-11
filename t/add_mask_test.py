#!/usr/bin/env python2

#
# (C)
#

import os
import sys
import json
import string
import random
sys.path.append('./t')
from http_utils import *

#
# Description:
# Allows adding random masks to the masks storage, and also the test checks
# the result of this action. The test requires that nginx will be started
# with `conf/foreground_purge.conf`.
# The goal of this test is checking that parallel requests will not affect
# `masks_storage` work.
#

def random_url(size=6, chars=string.ascii_uppercase + string.digits):
    return '/{}/*'.format(''.join(random.choice(chars) for _ in range(size)))


URL = "http://127.0.0.1:8082"


print ('[+] Add random mask')
ok, url, mask = False, random_url(), (1 << 4) | (1 << 2) | (1 << 0)
purge_success(URL + url, {"X-Purge-Options": "delete"})
_, res = purge_success(URL + "/*", {"X-Purge-Options": "dump"})
for r in json.loads(res):
    if url == r['mask'] and r['flags'] == mask:
        ok = True
        break
assert ok == True, 'did not found an added mask'
print ('[+] OK')

