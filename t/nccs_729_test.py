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

print ('[!] WARNINGS.\n'
        '- Be sure, that background purge is off!\n' +
        '- This test expectes nginx builded with an option NGX_DEBUG 1\n')
URL = "http://127.0.0.1:8082"
MASKS_STORAGE = "./test-root/masks_storage/masks.in*"
CACHE = "./test-root/cache/*"
DELAY = 20

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

# An issue: NCCS-729 {{{
print ('[+] NCCS-729')
uri = URL + "/"
_, _, h = get_success(uri + 't1.html', {"Host": "noslice_noshare.com"})
purge_success(uri + '*', {'Host': 'noslice_noshare.com',
    'X-Purge-Options': 'invalidate'})
purge_success(uri + '*', {'Host': 'noslice_noshare.com',
    'X-Purge-Options': 'delete'})
time.sleep(DELAY)
_, _, h = get_success(uri + 't1.html', { "Host": "noslice_noshare.com"})
assert h['x-cache-status'] == 'MISS', 'wrong cache status'
print ('[+] OK')
# }}}
