#!/usr/bin/env python3
import hashlib
import json
import os
from http.server import HTTPServer, SimpleHTTPRequestHandler


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
        # GET on a /traces/ "directory" returns a JSON list of stored
        # filenames. Production caches typically refuse this; the test
        # fixture enables it so `laut verify --debug-preimage-corpus`
        # can build an in-memory index. Listing is debug-only.
        if self.path.rstrip('/') == '/traces':
            self._serve_listing('/var/lib/cache/traces')
            return

        path = self.translate_path(self.path)
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

    def _serve_listing(self, dir_path):
        # nginx ngx_http_autoindex_module / Caddy file_server format=json
        # shape: an array of objects, each with at least a `name` field.
        # That leaves room for future `type`/`size`/`mtime` fields without
        # changing the schema.
        try:
            names = sorted(os.listdir(dir_path))
        except FileNotFoundError:
            names = []
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
