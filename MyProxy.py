
import select
import socket
import sys

BUFF = 2048
proxy_ip = '127.0.0.1'
proxy_port = 7070

def med_host_port(data):
    header = data.decode().split("\r\n")
    med = header[0].split(" ")[0]
    for get_host in header:
        if "Host" in get_host:
            get_host = get_host[5:]
            if ":" in get_host:
                host = get_host.split(":")[0].lstrip()
                port = int(get_host.split(":")[1])
            else :
                port = 80
    print(f'med:{med}, host:{host}, port:{port}')
    return med, host, port



class Forward:
    def __init__(self):
        self.forward = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    def med_conn(self, host, port):
        self.forward.connect((host, port))
        return self.forward

    def send_for(self,data):
        self.forward.send(data)
        return self.forward.recv(BUFF)

class Server:
    input_list = []
    def __init__(self, host, port):
        self.proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.proxy.bind((host, port))
        self.proxy.listen()
        # ----------기본 세팅-------------

    def main_loop(self):
        self.input_list.append(self.proxy)
        while True:
            inputready, writeready, exceptready = select.select(self.input_list,[],[])
            for ir in inputready:
                # 클라이언트 접속시 (accept)
                if ir == self.proxy:
                    conn, addr = self.proxy.accept()
                    print(f'{addr} is connected')
                    self.input_list.append(conn)
                # 그 밖( Client에서 패킷 전송시)
                else :
                    data = ir.recv(BUFF)
                    if data:
                        print(f'{ir.getpeername()} send: \n{data.decode()}')
                        med, host, port = med_host_port(data)
                        # test
                        # 원래 서버와 통신 준비
                        res = self.go_forward(host, port, data)
                        print(res.decode())
                    else :
                        print(f'{ir.getpeername()} close')
                        ir.close()
                        self.input_list.remove(ir)
    def go_forward(self, host, port, data):
        forward = Forward()
        bl_for = forward.med_conn(host,port)
        if bl_for:
            return forward.send_for(data)
        else :
            print("No Connected")
            return False

if __name__ == "__main__":
    server = Server(proxy_ip, proxy_port)
    try:
        print("Let's Go!")
        server.main_loop()
    except KeyboardInterrupt as e:
        print("Ctrl C - Stopping server")
        sys.exit(1)


