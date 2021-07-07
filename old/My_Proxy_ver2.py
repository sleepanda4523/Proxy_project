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

BUFF = 2048
delay = 0.03


def join_with_script_dir(path):
    """
    __file__ : 이 파이썬 파일의 상대경로. 즉 이름.
    os.path.abspath(path) : 절대경로를 찾아줌.
    os.path.dirname(path) : 경로의 디렉터리.
    os.path.join(path, *path) : 경로 병합.
    ->  즉 이 파이썬 파일이 들어있는 디렉토리를 기준으로 인증서 파일 탐색.
    """
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), path)


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    # print('check')
    address_family = socket.AF_INET6
    daemon_threads = True

    def handle_error(self, request, client_address):
        # surpress socket/ssl related errors
        cls, e = sys.exc_info()[:2]
        if cls is socket.error or cls is ssl.SSLError:
            pass
        else:
            return HTTPServer.handle_error(self, request, client_address)


class ProxyRequestHandler(BaseHTTPRequestHandler):
    cakey = join_with_script_dir('../ca.key')
    cacert = join_with_script_dir('../ca.crt')
    certkey = join_with_script_dir('../cert.key')
    certdir = join_with_script_dir('../certs/')
    timeout = 10
    lock = threading.Lock()

    def __init__(self, *args, **kwargs):
        self.tls = threading.local()
        self.tls.conns = {}

        BaseHTTPRequestHandler.__init__(self, *args, *kwargs)

    def do_CONNECT(self):
        """
        if os.path.isfile(self.cakey) and os.path.isfile(self.cacert) and os.path.isfile(
                self.certkey) and os.path.isdir(self.certdir):
            self.if_have_cert()
        else:
            self.connect_relay()
        """
        self.connect_relay()

    def connect_relay(self):
        address = self.path.split(':', 1)
        address[1] = int(address[1]) or 443
        #print(f'relay :{address}')
        try:
            s = socket.create_connection(address, timeout=self.timeout)
        except Exception as e:
            self.send_error(502)
            return
        self.send_response(200, 'Connection Established')
        self.end_headers()

        conns = [self.connection, s]
        self.close_connection = 0
        while not self.close_connection:
            rlist, wlist, xlist = select.select(conns, [], conns, self.timeout)
            if xlist or not rlist:
                break
            for r in rlist:
                other = conns[1] if r == conns[0] else conns[0]
                data = r.recv(8192)
                if not data:
                    self.close_connection = 1
                    break
                other.sendall(data)

    def do_GET(self):
        # GET 요청 핸들러
        # 인증서 사이트 다운로드.
        print(f'GET : {self.path}')
        if self.path == "http://sleepanda.test/":
            self.send_cacert()
            return
        # request 읽어오기.
        req = self
        content_len = int(req.headers.get("Content-Length", 0))
        req_body = self.rfile.read(content_len) if content_len else None
        # http / https
        if req.path[0] == "/":
            if isinstance(self.connection, ssl.SSLSocket):
                req.path = f"https://{req.headers['Host']}{req.path}"
            else:
                req.path = f"http://{req.headers['Host']}{req.path}"

        url = parse.urlparse(req.path)
        protocol, netloc, path = url.scheme, url.netloc, (url.path + '?' + url.query if url.query else url.path)
        assert protocol in ('http', 'https')
        if netloc:
            req.headers['Host'] = netloc

        try:
            origin = (protocol, netloc)
            if not origin in self.tls.conns:
                if protocol == 'https':
                    self.tls.conns[origin] = http.client.HTTPSConnection(netloc, timeout=self.timeout)
                else :
                    self.tls.conns[origin] = http.client.HTTPConnection(netloc, timeout=self.timeout)
            conn = self.tls.conns[origin]


            conn.request(self.command, path, req_body, dict(req.headers))
            res = conn.getresponse()
            #print(res.read())
            res_body = res.read()

        except Exception as e:
            if origin in self.tls.conns:
                del self.tls.conns[origin]
            self.send_error(502)
            return

        try:
            self.wfile.write((f'{self.protocol_version} {res.status} {res.reason}\r\b').encode())
            for tulpe_line in res.getheaders():
                self.wfile.write(str(tulpe_line[0]+tulpe_line[1]).encode())
            #self.end_headers()
            self.wfile.write(res_body)
            self.wfile.flush()
        except Exception as e:
            print(f"exception2 : {origin} {e}")

    do_HEAD = do_GET
    do_POST = do_GET
    do_PUT = do_GET
    do_DELETE = do_GET
    do_OPTIONS = do_GET

    def filter_headers(self, headers):
        pass

    def encode_content_body(self, text, encoding):
        if encoding == 'identity':
            data = text
        elif encoding in ('gzip', 'x-gzip'):
            Io = StringIO()
            with gzip.GzipFile(fileobj=Io, mode='wb') as f:
                f.write(text)
        elif encoding == 'deflate':
            data = zlib.compress(text)
        else:
            raise Exception(f"Unknown Content-Encoding: {encoding}")
        return data

    def decode_content_body(self, data, encoding):
        if encoding == 'identity':
            text = data
        elif encoding in ('gzip', 'x-gzip'):
            Io = StringIO(data)
            with gzip.GzipFile(fileobj=Io) as f:
                text = f.read()
        elif encoding == 'deflate':
            try:
                text = zlib.decompress(data)
            except zlib.error:
                text = zlib.decompress(data, -zlib.MAX_WBITS)
        else:
            raise Exception(f"Unknown Content-Encoding: {encoding}")
        return text

    def send_cacert(self):
        with open(self.cacert, 'rb') as f:
            data = f.read()

        print('send')
        self.send_response(200, 'OK')
        # self.wfile.write("%s %d %s\r\n" % (self.protocol_version, 200, 'OK'))
        self.send_header('Content-Type', 'application/x-x509-ca-cert')
        self.send_header('Content-Disposition', 'attachment; filename=ca.crt')
        self.send_header('Content-Length', len(data))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(data)

    def print_info(self, req, req_body, res, res_body):
        print("----------Request-----------")
        print(f'{req.headers}')
        print("---------Response-----------")
        print(f'{res.headers}')
        print("-----------------------------")

    def request_handler(self, req, req_body):
        pass

    def response_handler(self, req, req_body, res, res_body):
        pass

    def save_handler(self, req, req_body, res, res_body):
        self.print_info(req, req_body, res, res_body)



def lets_go(HandlerClass=ProxyRequestHandler, ServerClass=ThreadingHTTPServer, protocol="HTTP/1.1"):
    if sys.argv[1:]:
        port = int(sys.argv[1])
    else:
        port = 7070

    HandlerClass.protocol_version = protocol
    server_address = ('localhost', port)
    httpd = ServerClass(server_address, HandlerClass)
    s = httpd.socket.getsockname()
    print(f"HTTP Proxy On {s[0]}:{s[1]}")
    httpd.serve_forever()


if __name__ == '__main__':
    lets_go()
