#!/usr/bin/env python3

#
# (C) BSD v2
#

import os
import sys
import json
sys.path.append('./t')
from http_utils import *

#
# Description:
# The test is checking PURGE api.
# Conf:
# conf/foreground_purge.conf.
#

print ('[!] WARNINGS.\n'
        '- Be sure, that background purge is off!\n')

URL = "http://127.0.0.1:8082"
MASKS_STORAGE = sys.argv[1] + "/masks_storage/masks.in*"
CACHE = sys.argv[1] + "/cache/*"


print ('[+] Add masks')
purge_success(URL + "/b/*", {})
purge_success(URL + "/a/*", {})
_, res = purge_success(URL + "/*", {"X-Purge-Options": "dump"})
expected = iter([ {"mask":"/a/*"},
                  {"mask":"/b/*"}
                  ])
for r in json.loads(res):
    e = next(expected)
    assert r['mask'] == e['mask'],\
            "expecting {}, got {}".format(e['mask'], r['mask'])
l = int(os.popen('cat {} | wc -l'.format(MASKS_STORAGE)).read().split()[0])
assert l == 2, "expecting 2 lines, got {}".format(l)
print ('[+] OK')


print ('[+] Flush & Cleanup')
# TODO: test shared memory after
purge_success(URL + "/*", {"X-Purge-Options": "flush"})
try:
    os.popen('rm -Rf {}'.format(MASKS_STORAGE))
except:
    pass
print ('[+] OK')

