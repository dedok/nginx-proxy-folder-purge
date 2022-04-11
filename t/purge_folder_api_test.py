#!/usr/bin/env python2

#
# (C) Diceplex LLC
#

import os
import sys
import json
sys.path.append('./t')
from http_utils import *

#
# Description:
# The test is checking PURGE api. That includes: checking some good cases,
# checking some bad cases.
# The test requires that nginx will be started with `conf/foreground_purge.conf`.
#

print ('[!] WARNINGS.\n'
        '- Be sure, that background purge is off!\n' +
        '- This test expectes nginx builded with an option NGX_DEBUG 1\n')

URL = "http://127.0.0.1:8082"
MASKS_STORAGE = "./test-root/masks_storage/masks.in*"

print ('[+] Flush & Cleanup')
purge_success(URL + "/*", {"X-Purge-Options": "flush"})
try:
    os.popen('rm -Rf {}'.format(MASKS_STORAGE))
except:
    pass
print ('[+] OK')


print ('[+] Add masks test')
# TODO: fix me
# NCCS-703 {{{
# NCCS-620 {{{
#purge_success(URL + "/e/", {}, 400)
#purge_fail_with(URL + "/e/", {}, 404)
# }}}
#purge_success(URL + "/a/", {"X-Purge-Options": "delete"})
#purge_fail_with(URL + "/a/", {"X-Purge-Options": "delete"}, 404)
# }}}
purge_success(URL + "/b/*", {"X-Purge-Options": "invalidate"})
purge_success(URL + "/a/*", {"X-Purge-Options": "invalidate"})
purge_success(URL + "/a/*.txt", {"X-Purge-Options": "invalidate"})
_, res = purge_success(URL + "/*", {"X-Purge-Options": "dump"})
expected = iter([ {"flags":36 | (1 << 0),"mask":"/a/*"},
                  {"flags":40 | (1 << 0),"mask":"/a/*.txt"},
                  {"flags":36 | (1 << 0),"mask":"/b/*"}
                  ])
for r in json.loads(res):
    e = next(expected)
    assert r['flags'] == e['flags'], \
            "expecting {}, got {}".format(e['flags'], r['flags'])
    assert r['mask'] == e['mask'],\
            "expecting {}, got {}".format(e['mask'], r['mask'])
l = int(os.popen('cat {} | wc -l'.format(MASKS_STORAGE)).read().split()[0])
assert l == 3, "expecting 3 lines, got {}".format(l)
print ('[+] OK')

print ('[+] W/O or wrong X-Purge-Option')
# NCCS-737 {{{
# Off, see: NCCS-620 {{{
#_, res = purge_fail_with(URL, {}, 400)
#assert res == expected, 'not expected result, got {}'.format(res)
# }}}
_, res = purge_fail_with(URL + "/*", {'X-Purge-Options': "something wrong"}, 400)
_, res = purge_fail_with(URL + "/*", {'X-Purge-Options': "invalid"}, 400)
_, res = purge_fail_with(URL + "/*", {'X-Purge-Options': "dele"}, 400)
print ('[+] OK')
# }}}

print ('[+] Declined')
print ('[+][+] W/O asterisk')
purge_fail_with(URL + "/a/*/c.txt", {"X-Purge-Options": "invalidate"}, 400)
purge_fail_with(URL + "/a/c.txt", {"X-Purge-Options": "invalidate"}, 400)
print ('[+][+] W/O file extension')
purge_fail_with(URL + "/a/*.", {"X-Purge-Options": "invalidate"}, 400)
purge_fail_with(URL + "/a/.*", {"X-Purge-Options": "invalidate"}, 400)
purge_fail_with(URL + "/.*", {"X-Purge-Options": "invalidate"}, 400)

# TODO fixme
#purge_fail_with(URL + "/.", {"X-Purge-Options": "invalidate"}, 400)
print ('[+] OK')

print ('[+][+] W/O asterisk')
purge_fail_with(URL + "/a/*/c.txt", {"X-Purge-Options": "invalidate"}, 400)
purge_fail_with(URL + "/a/c.txt", {"X-Purge-Options": "invalidate"}, 400)
print ('[+][+] W/O file extension')
purge_fail_with(URL + "/a/*.", {"X-Purge-Options": "invalidate"}, 400)
purge_fail_with(URL + "/a/.*", {"X-Purge-Options": "invalidate"}, 400)
purge_fail_with(URL + "/.*", {"X-Purge-Options": "invalidate"}, 400)

# TODO fixme
#purge_fail_with(URL + "/.", {"X-Purge-Options": "invalidate"}, 400)
print ('[+] OK')

print ('[+] X-Purge-Options should be case insensitive')

#TODO fixme
#purge_fail_with(URL + "/aa/", {"x-purge-options": "delete"}, 200)

purge_success(URL + "/bb/*", {"X-PURGE-OPTIONS": "invalidate"})
_, res = purge_success(URL + "/*", {"X-Purge-Options": "dump"})
expected = iter([ {"flags":36 | (1 << 0),"mask":"/a/*"},
                  {"flags":40 | (1 << 0),"mask":"/a/*.txt"},
                  {"flags":36 | (1 << 0),"mask":"/b/*"},
                  {"flags":36 | (1 << 0),"mask":"/bb/*"}
                  ])

for r in json.loads(res):
    e = next(expected)
    assert r['flags'] == e['flags'], \
            "expecting {}, got {}".format(e['flags'], r['flags'])
    assert r['mask'] == e['mask'],\
            "expecting {}, got {}".format(e['mask'], r['mask'])
l = int(os.popen('cat {} | wc -l'.format(MASKS_STORAGE)).read().split()[0])
assert l == 4, "expecting 4 lines, got {}".format(l)
print ('[+] OK')

print ('[+] {} deleted'.format(MASKS_STORAGE))
os.popen('rm -Rf {}'.format(MASKS_STORAGE))
#TODO: fixme
#purge_fail_with(URL + "/c/", {"X-Purge-Options": "delete"}, 404)
purge_success(URL + "/c/*", {"X-Purge-Options": "invalidate"})
l = int(os.popen('cat {} | wc -l'.format(MASKS_STORAGE)).read().split()[0])
assert l == 1, "expecting 1 lines, got {}".format(l)
print ('[+] OK')


print ('[+] Flush & Cleanup')
purge_success(URL + "/*", {"X-Purge-Options": "flush"})
try:
    os.popen('rm -Rf {}'.format(MASKS_STORAGE))
except:
    pass
print ('[+] OK')
