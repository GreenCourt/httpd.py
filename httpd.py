#!/usr/bin/env python3
import os
import sys
from pathlib import Path
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import base64
import argparse
import socket
from mimetypes import guess_type
from subprocess import run
from shutil import which
import html
import urllib.parse
import io


pandoc = Path(__file__).parent.joinpath("pandoc")
if not pandoc.is_file():
    pandoc = which("pandoc")

katex_dir = Path(__file__).parent.joinpath("katex")
katex_dummy_path = "fc258238-32f5-4e94-bc6c-cfd643538f81"

pandoc_include = """
<style>
body { margin: 1em 2em; background-color: floralwhite; }
h1 { border-bottom: 1px solid silver; }
h2 { border-bottom: 1px solid silver; }
pre:has(code) { background-color:#eeeeee; padding:1em; }
table { border-collapse: collapse; }
thead { border-bottom: 1px solid gray; }
th, td { padding: 0.2em 1em; }
</style>
<script>
let lastModified = "";
setInterval(function() {
  fetch(window.location.href, {"method":"HEAD", cache:"no-cache" })
    .then(response => {
      return response.headers.get('last-modified');
    })
    .then(time => {
      if (!lastModified) lastModified = time;
      else if (lastModified != time) window.location.reload();
    });
}, 1000);
</script>
"""


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

    def _send_file(self, path: Path, content_type: str | None = None):
        if not path.is_file():
            self.send_error(404)
            return

        if content_type is None:
            content_type = guess_type(path)[0]

        self.send_response(200)
        if content_type is not None:
            self.send_header("Content-type", content_type)
        self.end_headers()
        with open(path, "rb") as f:
            while t := f.read(4096):
                self.wfile.write(t)

    def _send_pandoc(self, path: Path):
        if not path.is_file():
            self.send_error(404)
            return

        katex_opt: str = (
            "--katex" if katex_dir is None else ("--katex=" + katex_dummy_path + "/")
        )

        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=UTF-8")
        self.end_headers()
        run(
            [
                pandoc,
                "-s",
                "-f",
                "gfm",
                "-t",
                "html",
                katex_opt,
                "-M",
                "document-css=false",
                "-V",
                "header-includes=" + pandoc_include,
                path,
            ],
            stdout=self.wfile,
        )

    def do_GET(self):
        if not self._authorized():
            return
        local_path: Path = Path(self.translate_path(self.path))

        if katex_dir is not None and katex_dummy_path in local_path.parts:
            self._send_file(
                katex_dir.joinpath(
                    *(local_path.parts[local_path.parts.index(katex_dummy_path) + 1 :])
                )
            )
            return

        t = guess_type(local_path)[0]
        if pandoc is not None and t is not None and t == "text/markdown":
            self._send_pandoc(local_path)
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

        def is_markdown_or_html(name: str):
            t = guess_type(name)[0]
            return t is not None and t in ["text/markdown", "text/html"]

        dirs = list(filter(lambda x: os.path.isdir(os.path.join(path, x)), contents))
        files1 = list(
            filter(
                lambda x: os.path.isfile(os.path.join(path, x))
                and is_markdown_or_html(x),
                contents,
            )
        )
        files2 = list(
            filter(
                lambda x: os.path.isfile(os.path.join(path, x))
                and not is_markdown_or_html(x),
                contents,
            )
        )

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
        r.append(
            "<style> a { text-decoration: none; } </style>"
        )  # disable underline for links
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
        make_list(files1)
        make_list(files2)

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


def daemonize(logfile: Path = Path("/dev/null")):
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
    parser.add_argument("--katex", type=Path, default=None)
    args = parser.parse_args()

    if port_is_open(args.port):
        print(f"port {args.port} is already used", file=sys.stderr)
        sys.exit(1)

    if args.katex is not None:
        if not args.katex.is_dir():
            print(f"{args.katex} is not a directory", file=sys.stderr)
            sys.exit(1)
        katex_dir = args.katex
    elif not katex_dir.is_dir():
        katex_dir = None

    if args.daemon:
        daemonize(args.log)

    if args.dir:
        os.chdir(args.dir)

    if args.auth:
        Handler.user_pass = args.auth

    with ThreadingHTTPServer((args.bind, args.port), Handler) as s:
        print(f"listening at {s.server_address[0]}:{s.server_address[1]}")
        s.serve_forever()
