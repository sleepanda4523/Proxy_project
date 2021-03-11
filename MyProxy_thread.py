import select
import socket
import threading
import sys
import time

BUFF = 2048
proxy_ip = '127.0.0.1'
proxy_port = 7070
delay = 0.03

def med_host_port(data):
    header = data.decode().split("\r\n")
    med = header[0].split(" ")[0]
    for get_host in header:
        if "Host" in get_host:
            get_host = get_host[5:]
            print(get_host)
            if ":" in get_host:
                host = get_host.split(":")[0].lstrip()
                port = int(get_host.split(":")[1])
            else:
                host = get_host.lstrip()
                port = 80
    print(f'med:{med}, host:{host}, port:{port}')
    return med, host, port

class Forward:
    def __init__(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    def conn(self, host, port):
        print(host, port)
        self.server.connect((host, port))
        return self.server
    def on_send(self, data):
        self.server.send(data)
        time.sleep(delay)
        return self.server.recv(BUFF)

class Server:
    def __init__(self, host, port):
        self.proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.proxy.bind((host, port))
        self.proxy.listen()
        # ----------기본 세팅-------------
    def main_loop(self):
        while True:
            print("wait")
            client_socket, addr = self.proxy.accept()
            threading._start_new_thread(self.threaded,(client_socket, addr))
        self.proxy.close()

    def threaded(self, client_socket, addr):
        print("-----------------------------------")
        print(f'Connected : {addr[0]}:{addr[1]}')
        while True:
            self.data = client_socket.recv(BUFF)
            if not self.data:
                break
            med, host, port = med_host_port(self.data)
            res = self.on_connect(host, port, self.data)
            print(f'Server: \n{res}\n')
            client_socket.send(res)
        print(f"Bye Client: {addr[0]}:{addr[1]}")
        print("-----------------------------------")
        self.on_close(client_socket)


    def on_connect(self, host, port, data):
        forward = Forward()
        lb_for = forward.conn(host, port)
        if not lb_for:
            print("Not Connent to Server...")
            return False
        return forward.on_send(data)

    def on_close(self, socket):
        socket.close()



if __name__ == "__main__":
    server = Server(proxy_ip, proxy_port)
    try:
        print("Let's Go!")
        server.main_loop()
    except KeyboardInterrupt as e:
        print("Ctrl C - Stopping server")
        sys.exit(1)


