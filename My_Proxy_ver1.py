import os
import sys
import time
##################################
import socket
import ssl
from urllib import parse
import threading
##################################
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from subprocess import Popen, PIPE

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

    cakey = join_with_script_dir('ca.key')
    cacert = join_with_script_dir('ca.crt')
    certkey = join_with_script_dir('cert.key')
    certdir = join_with_script_dir('certs/')
    timeout = 5
    lock = threading.Lock()

    def do_CONNECT(self):
        self.if_have_cert()

    def if_have_cert(self):
        hostname = self.path.split(":")[0] # BaseHTTPRequestHandler안 path : 요청 경로.
        cert_path = f"{self.certdir.rstrip('/')}/{hostname}.crt"

        with self.lock:                 # = lock.acquire() ~ lock.release()
            if not os.path.isfile(cert_path):        # 만약 연결할 서버의 인증서가 없다면
                etime = f"{time.time()*1000}"
                p1 = Popen(["openssl", "req", "-new", "-key", self.certkey, "-subj", "/CN=%s" % hostname], stdout=PIPE)
                p2 = Popen(["openssl", "x509", "-req", "-days", "3650", "-CA", self.cacert, "-CAkey", self.cakey, "-set_serial", etime, "-out", certpath], stdin=p1.stdout, stderr=PIPE)
                p2.communicate()

        self.wfile.write(f"{self.protocol_version} 200 Connect OK\r\n")
        self.end_headers()

        self.connection = ssl.wrap_socket(self.request, keyfile=self.certkey, certfile=cert_path, server_side=True)
        self.rfile = self.connection.makefile("rb",self.rbufsize)
        self.wfile = self.connection.makefile("wb",self.wbufsize)

        conntype = self.headers.get('Proxy-Connection', '')
        if self.protocol_version == "HTTP/1.1" and conntype.lower() != 'close' :
            self.close_connection = 0
        else:
            self.close_connection = 1

    def do_GET(self):
        # GET 요청 핸들러
        # 인증서 사이트 다운로드.
        if self.path == "http://sleepproxy.panda":
            self.send_cacert()
            return
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
        if netloc :
            req.headers['Host'] = netloc



    def send_cacert(self):
        with open(self.cacert, 'rb') as f:
            data = f.read()

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, 200, 'OK'))
        self.send_header('Content-Type', 'application/x-x509-ca-cert')
        self.send_header('Content-Length', len(data))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(data)


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



