#!/usr/bin/env python3
import os
import sys
from pathlib import Path
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import base64
import argparse
import socket


class Handler(SimpleHTTPRequestHandler):
    index_pages: list[str] = []  # clear index_pages to ignore index.html
    user_pass = ""

    def log_message(self, format, *args):
        pass

    def _authorized(self) -> bool:
        if not self.user_pass:
            return True

        # Basic Authorization
        auth_header = self.headers.get("Authorization", "").encode("ascii")
        valid_header = b"Basic " + base64.b64encode(self.user_pass.encode("ascii"))
        if auth_header is None or not auth_header:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="Test"')
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"no auth header received")
            return False
        elif auth_header != valid_header:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="Test"')
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(auth_header)
            self.wfile.write(b"not authenticated")
            return False

        return True

    def do_HEAD(self):
        if not self._authorized():
            return
        super(Handler, self).do_HEAD()

    def do_GET(self):
        if not self._authorized():
            return
        super(Handler, self).do_GET()


def daemonize(logfile: Path = "/dev/null"):
    pid = os.fork()
    if pid > 0:
        sys.exit(0)  # parent

    os.setsid()  # new session

    # double fork
    pid = os.fork()
    if pid > 0:
        sys.exit(0)  # parent

    sys.stdout.flush()
    sys.stderr.flush()

    fin = open("/dev/null", "r")
    fout = open(logfile, "w")
    os.dup2(fin.fileno(), sys.stdin.fileno())
    os.dup2(fout.fileno(), sys.stdout.fileno())
    os.dup2(fout.fileno(), sys.stderr.fileno())


def port_is_open(port: int, timeout: float = 1.0) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect(("127.0.0.1", port))
            return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-b", "--bind", type=str, default="127.0.0.1")
    parser.add_argument("-p", "--port", type=int, default=8000)
    parser.add_argument("--dir", "--directory", type=Path, default=None)
    parser.add_argument("--daemon", action="store_true")
    parser.add_argument("--auth", type=str, default="")
    parser.add_argument("--log", type=Path, default="/dev/null")
    args = parser.parse_args()

    if port_is_open(args.port):
        print(f"port {args.port} is already used", file=sys.stderr)
        sys.exit(1)

    if args.daemon:
        daemonize(args.log)

    if args.dir:
        os.chdir(args.dir)

    if args.auth:
        Handler.user_pass = args.auth

    with ThreadingHTTPServer((args.bind, args.port), Handler) as s:
        print(f"listening at {s.server_address[0]}:{s.server_address[1]}")
        s.serve_forever()
