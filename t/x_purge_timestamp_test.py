#!/usr/bin/env python2

#
# (C)
#

import os
import sys
import time
import json
sys.path.append('./t')
from http_utils import *

#
# Description:
# The test is checking the x_purge_timestamp, an http header.
# And also it is checking some bad cases.
#
# The test requires that nginx will be started with `conf/foreground_purge.conf`.
#

# TODO fixme
#print ('[!] WARNINGS.\n'
#        '- Be sure, that background purge is off!\n' +
#        '- This test expectes nginx builded with an option NGX_DEBUG 1\n')
#
#URL = "http://127.0.0.1:8082"
#MASKS_STORAGE = "./test-root/masks_storage/masks.in*"
#
#print ('[+] Flush & Cleanup')
#purge_success(URL + "/*", {"X-Purge-Options": "flush"})
#try:
#    os.popen('rm -Rf {}'.format(MASKS_STORAGE))
#except:
#    pass
#print ('[+] OK')
#
#
#print ('[+] X-Purge-timestamp OK')
#now = int(time.time())
#now = now - 10 # Just for sure
#purge_success(URL + '/x_purge_timestamp/test-1/*', {
#    'Host': 'purge_folder', 'X-Purge-TimeStamp': now })
#purge_success(URL + '/x_purge_timestamp/test-1/x/*', {
#    'Host': 'purge_folder'})
#_, res = purge_success(URL + '/*', {'X-Purge-Options': 'dump'})
#res = json.loads(res)
#assert res[0]['pst'] >= now, 'x-purge-timestamp wasn\'t set'
#assert res[0]['mask'] == '/x_purge_timestamp/test-1/x/*', 'mast is wrong'
#assert res[0]['domain'] == 'purge_folder',  'domain is wrong'
#assert res[0]['flags'] == 1045, 'flags are wrong'
#assert res[1]['pst'] == now, 'x-purge-timestamp wasn\'t set'
#assert res[1]['mask'] == '/x_purge_timestamp/test-1/*', 'mast is wrong'
#assert res[1]['domain'] == 'purge_folder',  'domain is wrong'
#assert res[1]['flags'] == 1045, 'flags are wrong'
#print ('[+] OK')
#
#
#print ('[+] X-Purge-timestamp WRONG')
#now = int(time.time())
#rc, out = purge_fail_with(URL + '/x_purge_timestamp/test-1/a/*', {
#    'Host': 'purge_folder', 'X-Purge-TimeStamp': now - 4000 }, 400)
#rc, out = purge_fail_with(URL + '/x_purge_timestamp/test-1/b/*', {
#    'Host': 'purge_folder', 'X-Purge-TimeStamp': now + 1000 }, 400)
#rc, out = purge_fail_with(URL + '/x_purge_timestamp/test-1/c/*', {
#    'Host': 'purge_folder', 'X-Purge-TimeStamp': 'text' }, 400)
#print ('[+] OK')


