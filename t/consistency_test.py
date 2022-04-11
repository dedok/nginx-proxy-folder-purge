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
# The test requires that nginx will be started with
# `conf/foreground_purge.conf`.
#
# The goal of this test is checking that masks storage works well.
#

print ('[!] WARNINGS.\n'
        '- Be sure, that background purge is off!\n' +
        '- This test expectes nginx builded with an option NGX_DEBUG 1\n')

URL = "http://127.0.0.1:8082"
MASKS_STORAGE = "./test-root/masks_storage/masks.in*"
CACHE = "./test-root/cache/*"

print ('[+] ./t/run.sh expects 16 lines')
l = int(os.popen('cat {} | wc -l'.format(MASKS_STORAGE)).read().split()[0])
assert l == 16, "expecting 16 lines, got {}".format(l)
print ('[+] OK')


print ('[+] ./t/run.sh expects 8 purges')
_, out = purge_success(URL + '/*', {'Host': 'purge_folder',
    "X-Purge-Options": "dump"})
res = json.loads(out)
assert len(res) == 8, 'shared memory does not have 8 elements'
print ('[+] OK')

