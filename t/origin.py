#!/usr/bin/env python3

#
# (C) BSD v2
#

#
# Description:
# An origin server emulation. The goal of the script is working within tests.
#
# Every response has a body that is unique per origin request
# ("served=<n> <path>"), so a test can always tell a cached copy from a
# freshly fetched one. GET /__stats returns the request counters.
#
# Standalone usage (the tests start it in-process instead):
#
#     $> python3 t/origin.py [port]
#

import json
import socketserver
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

STATS_PATH = '/__stats'


class OriginHandler(BaseHTTPRequestHandler):

    protocol_version = 'HTTP/1.1'
    server_version = 'purge-test-origin/1.0'

    def do_GET(self):
        self.serve()

    def do_HEAD(self):
        self.serve(head=True)

    def serve(self, head=False):
        if self.path == STATS_PATH:
            body = json.dumps(self.server.stats()).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')

        else:
            n = self.server.count_request(self.path)
            body = "served={} {}\n".format(n, self.path).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('X-Origin-Hit', str(n))

        self.send_header('Content-Length', str(len(body)))
        self.end_headers()

        if not head:
            self.wfile.write(body)

    def log_message(self, format, *args):
        pass


# ThreadingHTTPServer appeared in Python 3.7, the ThreadingMixIn + HTTPServer
# combo works on older releases too and gives the same behaviour.
class ThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address):
        HTTPServer.__init__(self, address, OriginHandler)
        self.lock = threading.Lock()
        self.requests = 0
        self.paths = {}

    def count_request(self, path):
        with self.lock:
            self.requests += 1
            self.paths[path] = self.paths.get(path, 0) + 1
            return self.paths[path]

    def stats(self):
        with self.lock:
            return {'requests': self.requests, 'paths': dict(self.paths)}


def start_origin(port=0):
    """Start an origin on 127.0.0.1 and return (server, port)."""
    server = ThreadingHTTPServer(('127.0.0.1', port))
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    return server, server.server_address[1]


if __name__ == '__main__':
    _, origin_port = start_origin(int(sys.argv[1]) if len(sys.argv) > 1 else 9999)
    print('origin is listening on 127.0.0.1:{}, stats on GET {}'.format(
        origin_port, STATS_PATH))
    try:
        while True:
            threading.Event().wait(3600)
    except KeyboardInterrupt:
        pass
