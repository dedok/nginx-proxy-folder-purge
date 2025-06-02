#
# Common HTTP function for make tests easy
#

import json
import urllib
import urllib.request
import traceback


#VERBOSE = True
VERBOSE = False

def request(method, url, headers, data):
    out = ''
    try:
        if VERBOSE:
            if headers:
                print(headers)
                hdr_s = ' '.join('-H "%s: %s"' % (k, v) for k, v in headers.iteritems())
            else:
                hdr_s = ''
            print('curl -X%s -D - -o/dev/null -s %s "%s"' % (method, hdr_s, url))
        req = urllib.request.Request(url)
        if headers:
            for header in headers:
                req.add_header(header, headers[header])

        req.get_method = lambda: method
        if data:
            res = urllib.request.urlopen(req, data)
        else:
            res = urllib.request.urlopen(req)

        out = res.read()
        out = out + res.read()
        rc = res.getcode()

        if VERBOSE:
            print("code: ", rc, " recv: '", out, "'")

        if rc != 500:
            return (rc, out, res.info())

        return (rc, False, False)
    except urllib.error.HTTPError as e:
        if e.code == 400:
            out = e.read();

        if VERBOSE:
            print("code: ", e.code, " recv: '", out, "'")

        return (e.code, out, False)
    except Exception as e:
        print(traceback.format_exc())
        return (False, e, False)


def purge(url, headers, data = None):
    return request('PURGE', url, headers, data)


def get(url, headers, data = None):
    return request('GET', url, headers, data)


def purge_success(url, headers, data = None):
    (rc, out, headers) = purge(url, headers, data)
    assert rc == 200, '"{}" expected code = 200, got = {}, out = {}'.\
            format(url, rc, out)
    return rc, out


def purge_fail_with(url, headers, expected_code, data = None):
    (rc, out, headers) = purge(url, headers, data)
    assert rc == expected_code, '"{}" expected_code code = {}, got = {}'.\
            format(url, expected_code, rc)
    return rc, out


def get_success(url, headers = None, data = None):
    (rc, out, headers) = get(url, headers, data)
    assert rc == 200, '"{}" expected code = 200, got = {}, out = {}'.\
            format(url, rc, out)
    return rc, out, headers


def assert_header(result, headers_in):
    for header in headers_in:
        header_from_server = result['headers'][header]
        assert(header_from_server == headers_in[header]), 'expected headers_in'

