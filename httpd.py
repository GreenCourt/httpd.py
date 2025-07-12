#!/usr/bin/env python3
import os
import sys
from pathlib import Path
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import base64
import argparse
import socket
from mimetypes import guess_type
import urllib.parse
import html
import io


class Handler(SimpleHTTPRequestHandler):
    index_pages: list[str] = []  # clear index_pages to ignore index.html
    user_pass = ""
    url_prefix = ""

    # def log_message(self, format, *args):
    #    pass

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

    def translate_path(self, path: str):
        if self.url_prefix and path.startswith(self.url_prefix):
            # remove url_prefix from path
            path = path[len(self.url_prefix) :] or "/"
        return super().translate_path(path)

    def do_HEAD(self):
        if not self._authorized():
            return
        super(Handler, self).do_HEAD()

    def do_GET(self):
        if not self._authorized():
            return
        super(Handler, self).do_GET()

    def list_directory(self, path):
        try:
            contents = os.listdir(path)
        except OSError:
            self.send_error(403)
            return None

        contents = list(filter(lambda x: x and x[0] != ".", contents))
        contents.sort(key=lambda a: a.lower())

        def is_image(name: str):
            return guess_type(name)[0].startswith("image/")

        dirs = list(filter(lambda x: os.path.isdir(os.path.join(path, x)), contents))
        files = list(filter(lambda x: x not in dirs, contents))
        images = list(filter(is_image, files))

        r = []
        try:
            displaypath = urllib.parse.unquote(self.path, errors="surrogatepass")
        except UnicodeDecodeError:
            displaypath = urllib.parse.unquote(self.path)
        displaypath = html.escape(displaypath, quote=False)
        enc = sys.getfilesystemencoding()
        title = displaypath
        r.append("<!DOCTYPE HTML>")
        r.append('<html lang="en">')
        r.append("<head>")
        r.append(f'<meta charset="{enc}">')
        r.append("<style>")
        r.append("a { text-decoration: none; }")  # disable underline for links
        r.append("img { max-width: 250px; max-height:250px }")
        r.append("</style>")

        r.append(f"<title>{title}</title>\n</head>")
        r.append("<body>\n")

        def make_list(contents: list[str]):
            if not contents:
                return

            r.append("<ul>")
            for name in contents:
                fullname = os.path.join(path, name)
                displayname = linkname = name
                # Append / for directories or @ for symbolic links
                if os.path.isdir(fullname):
                    displayname = name + "/"
                    linkname = name + "/"
                if os.path.islink(fullname):
                    displayname = name + "@"
                    # Note: a link to a directory displays with @ and links with /
                r.append(
                    '<li><a href="%s">%s</a></li>'
                    % (
                        urllib.parse.quote(linkname, errors="surrogatepass"),
                        html.escape(displayname, quote=False),
                    )
                )
            r.append("</ul><hr>\n")

        make_list(dirs)
        make_list(files)

        image_limit = 100
        for i in images[:image_limit]:
            r.append(
                '<a href="%s"><img src="%s" alt="%s"></a>\n'
                % (
                    urllib.parse.quote(i, errors="surrogatepass"),
                    urllib.parse.quote(i, errors="surrogatepass"),
                    html.escape(i, quote=False),
                )
            )
        if len(images) > image_limit:
            r.append(f"<br> only {image_limit} of {len(images)} images are shown .")

        r.append("</body>\n</html>\n")
        encoded = "\n".join(r).encode(enc, "surrogateescape")
        f = io.BytesIO()
        f.write(encoded)
        f.seek(0)
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=%s" % enc)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        return f


def daemonize(logfile: str | Path = "/dev/null"):
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
    parser.add_argument("--url-prefix", type=str, default="")
    parser.add_argument("--daemon", action="store_true")
    parser.add_argument("--auth", type=str, default="", help="user:pass")
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

    if args.url_prefix:
        Handler.url_prefix = (
            args.url_prefix
            if args.url_prefix and args.url_prefix[0] == "/"
            else ("/" + args.url_prefix)
        )

    with ThreadingHTTPServer((args.bind, args.port), Handler) as s:
        print(f"listening at {s.server_address[0]}:{s.server_address[1]}")
        s.serve_forever()
