#!/usr/bin/env python3
import hashlib
import json
import os
import re
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlsplit


def compute_etag(path):
    """Compute a content-based ETag for a file. Returns hex digest or None."""
    try:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except FileNotFoundError:
        return None


class PUTHandler(SimpleHTTPRequestHandler):
    def _check_preconditions(self, path):
        """Evaluate If-Match and If-None-Match against the current file's ETag.
        Returns (ok, etag) where ok is True if all conditions hold (or none
        were given). Only `If-None-Match: *` is supported; specific etag
        values aren't needed by laut.
        """
        current_etag = compute_etag(path)
        if_match = self.headers.get('If-Match')
        if if_match:
            expected = if_match.strip().strip('"')
            if current_etag is None or expected != current_etag:
                return False, current_etag
        if_none_match = self.headers.get('If-None-Match')
        if if_none_match and if_none_match.strip() == '*':
            if current_etag is not None:
                return False, current_etag
        return True, current_etag

    def _send_etag(self, etag):
        if etag:
            self.send_header('ETag', f'"{etag}"')

    def do_GET(self):
        # Only list the trace namespace root and scheme leaves. This is
        # debug-only; production caches typically refuse directory listings.
        route = urlsplit(self.path).path
        listing = re.fullmatch(
            r'/traces(?:/([A-Za-z0-9][A-Za-z0-9._-]*))?/?', route
        )
        if listing:
            self._serve_listing(
                self.translate_path(route), namespaces=listing[1] is None
            )
            return

        path = self.translate_path(self.path)
        if os.path.isdir(path):
            self.send_error(404)
            return
        etag = compute_etag(path)
        if etag is None:
            self.send_error(404)
            return
        with open(path, 'rb') as f:
            content = f.read()
        self.send_response(200)
        self.send_header('Content-Length', str(len(content)))
        self.send_header('Content-Type', self.guess_type(path))
        self._send_etag(etag)
        self.end_headers()
        self.wfile.write(content)

    def _serve_listing(self, dir_path, namespaces=False):
        # nginx ngx_http_autoindex_module / Caddy file_server format=json
        # shape: an array of objects, each with at least a `name` field.
        # That leaves room for future `type`/`size`/`mtime` fields without
        # changing the schema.
        try:
            entry_type = os.path.isdir if namespaces else os.path.isfile
            names = sorted(
                n for n in os.listdir(dir_path)
                if entry_type(os.path.join(dir_path, n))
            )
        except FileNotFoundError:
            names = []
        except NotADirectoryError:
            self.send_error(404)
            return
        body = json.dumps([{"name": n} for n in names]).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_PUT(self):
        path = self.translate_path(self.path)
        ok, current_etag = self._check_preconditions(path)
        if not ok:
            self.send_response(412)
            self.end_headers()
            return

        os.makedirs(os.path.dirname(path), exist_ok=True)
        length = int(self.headers.get('Content-Length', 0))
        data = self.rfile.read(length)

        with open(path, 'wb') as f:
            f.write(data)

        new_etag = compute_etag(path)
        self.send_response(201)
        self._send_etag(new_etag)
        self.end_headers()


if __name__ == '__main__':
    os.makedirs('/var/lib/cache', exist_ok=True)
    os.chdir('/var/lib/cache')
    server = HTTPServer(('0.0.0.0', 9000), PUTHandler)
    server.serve_forever()
