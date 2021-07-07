import os
import sys
import time
import select
##################################
import http.client
import socket
import ssl
from urllib import parse
import threading
import gzip
import zlib
##################################
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from subprocess import Popen, PIPE
from io import StringIO

BUFF = 4096
delay = 0.1

def join_with_script_dir(path):
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), path)

def make_openssl():
    make_cakey = "openssl genrsa -out ca.key 2048".split()
    make_cacert = 'openssl req -new -x509 -days 3650 -key ca.key -out ca.crt -subj "/CN=pandaCA"'
    make_certkey = "openssl genrsa -out cert.key 2048".split()
    make_dir = "mkdir certs".split()
    if not os.path.isfile(join_with_script_dir('ca.key')):
        Popen(make_cakey, shell=PIPE, stderr=PIPE)
        time.sleep(0.3)
    if not os.path.isfile(join_with_script_dir('ca.crt')):
        os.system(make_cacert)
    if not os.path.isfile(join_with_script_dir('cert.key')):
        Popen(make_certkey, shell=PIPE, stderr=PIPE)
    if not os.path.isdir(join_with_script_dir('certs')):
        Popen(make_dir, shell=PIPE, stderr=PIPE)


class ProxyServer(ThreadingMixIn, HTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True

    def handle_error(self, request, client_address):
        cls, e = sys.exc_info()[:2]
        if cls is socket.error or cls is ssl.SSLError:
            pass
        else:
            return HTTPServer.handle_error(self, request, client_address)


class ProxyHandler(BaseHTTPRequestHandler):
    cakey = join_with_script_dir('ca.key')
    cacert = join_with_script_dir('ca.crt')
    certkey = join_with_script_dir('cert.key')
    certdir = join_with_script_dir('certs/')
    timeout = 5
    lock = threading.Lock()
    data = ''

    def __init__(self, *args, **kwargs):
        self.tls = threading.local()
        self.tls.conns = {}
        BaseHTTPRequestHandler.__init__(self, *args, *kwargs)

    def interrupt(self):
        print(self.data)
        cmd = input('Forward or Drop? (F or D): ')
        if cmd.lower() == "f":
            return True
        else :
            return False

    def do_CONNECT(self):
        self.wfile.write(("%s %d %s\r\n" % (self.protocol_version, 200, 'Connection Established')).encode())
        self.wfile.flush()
        # self.send_response(200, 'Connection Established')
        # self.end_headers()

        self.connection = self.request
        hostname = self.path.split(":")[0]
        certpath = f"{self.certdir.rstrip('/')}\{hostname}.crt"

        with self.lock:
            if not os.path.isfile(certpath):
                print('make cert')
                epoch = "%d" % (time.time() * 1000)
                p1 = Popen(["openssl", "req", "-new", "-key", self.certkey, "-subj", "/CN=%s" % hostname], stdout=PIPE)
                p2 = Popen(["openssl", "x509", "-req", "-days", "3650", "-CA", self.cacert, "-CAkey", self.cakey,
                            "-set_serial", epoch, "-out", certpath], stdin=p1.stdout, stderr=PIPE)
                p2.communicate()

        with ssl.wrap_socket(self.connection,
                             keyfile=self.certkey,
                             certfile=certpath,
                             server_side=True,
                             do_handshake_on_connect=False) as conn:
            self.connection = conn
            self.rfile = conn.makefile('rb', self.rbufsize)
            self.wfile = conn.makefile('wb', self.wbufsize)

        while True:
            try:
                self.connection.do_handshake()
                break
            except Exception as e:
                print(f'CONNECT except : {e}')
                return
        print('debug')

        conntype = self.headers.get('Proxy-Connection', '')
        if self.protocol_version == 'HTTP/1.1' and conntype.lower() != 'close':
            self.close_connection = False
        else:
            self.close_connection = True

    def do_GET(self):
        if self.path == "http://sleepanda.test/":
            self.send_cacert()
            return
        self.proxy_request()

    def proxy_request(self):
        req = self
        content_length = int(req.headers.get('Content-Length', 0))
        req_body = self.rfile.read(content_length) if content_length else None

        if req.path[0] == '/':
            path = f'{req.headers["Host"]}{req.path}'
            if isinstance(self.connection, ssl.SSLSocket):
                req.path = f'https://{path}'
            else :
                req.path = f'http://{path}'

        req_body_modified = self.request_handler(req, req_body)
        if req_body_modified is False:
            self.send_error(403)
            return
        elif req_body_modified is not None:
            req_body = req_body_modified
            del req.headers['Content-length']
            req.headers['Content-length'] = str(len(req_body))

        url = parse.urlparse(req.path)
        scheme, netloc, path = url.scheme, url.netloc, (url.path + '?' +
                                                        url.query if url.query else url.path)
        assert scheme in ('http', 'https')
        if netloc:
            req.headers['Host'] = netloc

        origin = (scheme, netloc)
        try:
            if not origin in self.tls.conns:
                if scheme == 'https':
                    self.tls.conns[origin] = http.client.HTTPSConnection(netloc, timeout=self.timeout)
                else:
                    self.tls.conns[origin] = http.client.HTTPConnection(netloc, timeout=self.timeout)
            conn = self.tls.conns[origin]
            conn.request(self.command, path, req_body, dict(req.headers))
            res = conn.getresponse()

            version_table = {10: 'HTTP/1.0', 11: 'HTTP/1.1'}
            setattr(res, 'headers', res.msg)
            setattr(res, 'response_version', version_table[res.version])

            res_body = res.read()
        except Exception as e:
            print(f'Get Error : {e}')
            self.close_connection = True
            return

        res_body_modified = self.response_handler(req, req_body, res, res_body)
        if res_body_modified is False:
            self.send_error(403)
            return
        elif res_body_modified is not None:
            res_body = res_body_modified
            del res.headers['Content-length']
            res.headers['Content-Length'] = str(len(res_body))

        self.send_response(res.status, res.reason)
        for header, val in res.headers.items():
            self.send_header(header, val)
        self.end_headers()

        if res_body:
            self.wfile.write(res_body)
        self.wfile.flush()

    do_HEAD = do_GET
    do_POST = do_GET
    do_PUT = do_GET
    do_DELETE = do_GET
    do_OPTIONS = do_GET

    def send_cacert(self):
        with open(self.cacert, 'rb') as f:
            data = f.read()

        print('send')
        self.send_response(200, 'OK')
        #self.wfile.write("%s %d %s\r\n" % (self.protocol_version, 200, 'OK'))
        self.send_header('Content-Type', 'application/x-x509-ca-cert')
        self.send_header('Content-Disposition','attachment; filename=Pandaca.crt')
        self.send_header('Content-Length', len(data))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(data)

    def request_handler(self, req, req_body):
        pass
    def save_handler(self, req, req_body, res, res_body):
        pass



def start(HandlerClass=ProxyHandler, ServerClass=ProxyServer):
    make_openssl()
    try :
        port = 7070
        server_address = ('::1', port)
        proxy = ServerClass(server_address, HandlerClass)
        s = proxy.socket.getsockname()
        print(f"HTTP Proxy On {s[0]}:{s[1]}")
        proxy.serve_forever()
    except KeyboardInterrupt:
        print('Server down..')
        proxy.server_close()

if __name__ == '__main__':
    start()
