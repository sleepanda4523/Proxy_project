import os
import sys
import time
import select
##################################
import http.client
import socket
import ssl
from OpenSSL import SSL
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
        print(cls, e)
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

        self.connection = self.request

    def interrupt(self):
        print(self.data)
        cmd = input('Forward or Drop? (F or D): ')
        if cmd.lower() == "f":
            return True
        else :
            return False

    def do_CONNECT(self):
        if os.path.isfile(self.cakey) and os.path.isfile(self.cacert) and os.path.isfile(self.certkey) and os.path.isdir(self.certdir):
            self.connect_intercept()
        else:
            self.connect_relay()

    def connect_intercept(self):
        hostname = self.path.split(":")[0]
        certpath = f'{self.certdir.rstrip("/")}/{hostname}.crt'

        self.wfile.write(("%s %d %s\r\n" % (self.protocol_version, 200, 'Connection Established')).encode())
        self.wfile.flush()
        #self.send_response(200, 'Connection Established')
        #self.end_headers()

        with self.lock:
            if not os.path.isfile(certpath):  # 만약 연결할 서버의 인증서가 없다면
                new_cert_req = ['openssl','req', '-new', '-key', self.certkey, '-subj', f'/CN={hostname}']
                epoch = "%d" % (time.time() * 1000)
                p1 = Popen(new_cert_req, stdout=PIPE, stderr=PIPE)
                p2 = Popen(["openssl", "x509", "-req", "-days", "3650", "-CA", self.cacert, "-CAkey", self.cakey,
                            "-sha256", "-set_serial", epoch, "-out", certpath], stdin=p1.stdout, stderr=PIPE)
                p2.communicate()

        ctx = ssl.SSLContext()
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cafile=self.cacert)
        ctx.load_cert_chain(certfile=certpath, keyfile=self.certkey)
        try:
            with ctx.wrap_socket(self.connection, server_side=True) as conn:
                print(f'{self.command} {hostname}')
                self.connection = conn
                self.rfile = conn.makefile('rb', self.rbufsize)
                self.wfile = conn.makefile('wb', self.wbufsize)
        except Exception as e:
            print(f'ssl Except : {e}')

        conntype = self.headers.get('Proxy-Connection', '')
        if self.protocol_version == 'HTTP/1.1' and conntype.lower() != 'close':
            self.close_connection = False
        else:
            self.close_connection = True


    def connect_relay(self):
        address = self.path.split(':', 1)
        address[1] = int(address[1]) or 443
        try:
            s = socket.create_connection(address, timeout=self.timeout)
        except Exception as e:
            self.send_error(502)
            return
        self.send_response(200, 'Connection Established')
        self.end_headers()

        conns = [self.connection, s]
        self.close_connection = False
        while not self.close_connection:
            rlist, wlist, xlist = select.select(conns, [], conns, self.timeout)
            if xlist or not rlist:
                break
            for r in rlist:
                other = conns[1] if r is conns[0] else conns[0]
                data = r.recv(8192)
                if not data:
                    self.close_connection = True
                    break
                other.sendall(data)

    def do_GET(self):
        if self.path == "http://sleepanda.test/":
            self.send_cacert()
            return
        self.get_handle()

    def get_handle(self):
        print('get')
        # request 읽어오기.
        req = self
        content_len = int(req.headers.get("Content-Length", 0))
        req_body = self.rfile.read(content_len) if content_len else None
        # http/https 주소 탐색.
        if req.path[0] == "/":
            if isinstance(self.connection, ssl.SSLSocket):
                req.path = f"https://{req.headers['Host']}{req.path}"
            else:
                req.path = f"http://{req.headers['Host']}{req.path}"

        # request_handler함수로 request의 body 수정.
        req_body_modified = self.request_handler(req, req_body)
        if req_body_modified is False:
            self.send_error(403)
            return
        elif req_body_modified is not None:
            req_body = req_body_modified
            req.headers['Content-length'] = str(len(req_body))

        # urllib.parse.urlsplit으로 (scheme, netloc, path, query, fragment) 분석
        url = parse.urlparse(req.path)
        """
        만약 http://www.test.test/hello/world?name=panda라는 URL이 있을 때
        scheme = 'http", netloc = "www.test.test" path = "/hello/world qurey = "?name=panda"
        """
        scheme, netloc, path = url.scheme, url.netloc, (url.path + '?' + url.query if url.query else url.path)
        # 프로토콜이 http or https인지 가정설정문으로 체크.
        assert scheme in ('http', 'https')
        if netloc:
            req.headers['Host'] = netloc
        try:
            origin = (scheme, netloc)
            if not origin in self.tls.conns:
                if scheme == 'https':
                    self.tls.conns[origin] = http.client.HTTPSConnection(netloc, timeout=self.timeout)
                else:
                    self.tls.conns[origin] = http.client.HTTPConnection(netloc, timeout=self.timeout)
            conn = self.tls.conns[origin]
            with self.lock:
                self.data = req_body
                print(f'{self.command} {path} {req_body}')
                conn.request(self.command, path, self.data, dict(req.headers))
                res = conn.getresponse()

            version_table = {10: 'HTTP/1.0', 11: 'HTTP/1.1'}
            setattr(res, 'headers', res.msg)
            setattr(res, 'response_version', version_table[res.version])

            res_body = res.read()
        except Exception as e:
            print(f'exception request: {e}')
            if origin in self.tls.conns:
                del self.tls.conns[origin]
            self.send_error(502)
            return

        # content_encoding = res.headers.get('Content-Encoding', 'identity')
        # res_body_plain = self.decode_content_body(res_body, content_encoding)

        # print(self.command,path, netloc)

        r = f"{self.protocol_version} {res.status} {res.reason}\r\n"
        self.wfile.write(r.encode())
        for tuple in res.getheaders():
            self.send_header(tuple[0], tuple[1])
        self.end_headers()
        self.wfile.write(res_body)
        self.wfile.flush()

        with self.lock:
            self.save_handler(req, req_body, res, res_body)

        # with self.lock:
        #     self.save_handler(req, req_body, res, res_body)

    do_HEAD = do_GET
    do_POST = do_GET
    do_PUT = do_GET
    do_DELETE = do_GET
    do_OPTIONS = do_GET

    def relay_streaming(self, res):
        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, res.status, res.reason))
        for line in res.headers.headers:
            self.wfile.write(line)
        self.end_headers()
        try:
            while True:
                chunk = res.read(8192)
                if not chunk:
                    break
                self.wfile.write(chunk)
            self.wfile.flush()
        except socket.error:
            pass

    def filter_headers(self, headers):
        # http://tools.ietf.org/html/rfc2616#section-13.5.1
        hop_by_hop = ('connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade')
        for k in hop_by_hop:
            del headers[k]

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
