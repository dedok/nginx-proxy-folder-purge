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

#
# Description:
# Checking that mask storage works well, shared memory also works well
# The test requires that nginx will be started with
# `conf/foreground_purge.conf`.
#

print ('[!] WARNINGS.\n'
        '- Be sure, that background purge is off!\n')

URL = "http://127.0.0.1:8082"
MASKS_STORAGE = sys.argv[1] + "/masks_storage/masks.in*"


print ('[+] run 8+8 purges')
for i in range(0, 8):
    _, out = purge_success(URL + '/foreground_purge/f_' + str(i),
                           {'Host': 'purge_folder'})
for i in range(0, 8):
    _, out = purge_success(URL + '/foreground_purge/f_' + str(i),
                           {'Host': 'purge_folder'})


print ('[+] expected 16 lines in mask.in.*')
l = int(os.popen('cat {} | wc -l'.format(MASKS_STORAGE)).read().split()[0])
assert l == 16, "expecting 16 lines, got {}".format(l)
print ('[+] OK')


print ('[+] expected 8 purges in shared_memory')
_, out = purge_success(URL + '/*', {'Host': 'purge_folder',
    "X-Purge-Options": "dump"})
res = json.loads(out)
assert len(res) == 8, 'shared memory does not have 8 elements'
print ('[+] OK')

