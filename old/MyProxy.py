# -*- coding: utf-8 -*-
"""
Created on Tue Mar  2 13:43:33 2021
@author: msi
"""

import select
import socket
import sys
import time
import ssl
import re


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
            domain = get_host.lstrip()
            if ":" in get_host:
                host = get_host.split(":")[0].lstrip()
                port = int(get_host.split(":")[1])
            else:
                host = get_host.lstrip()
                port = 80
    print(f'med:{med}, host:{host}, port:{port}, domain:{domain}')
    return med, host, port,domain



class Forward:
    def __init__(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    def conn(self, host, port):
        #print(host, port)
        self.server.connect((host, port))
        return self.server
    def on_send(self, data):
        print(data)
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
                print("waiting...")
                client_socket,addr = self.proxy.accept()
                self.start_socket(client_socket, addr)

    def start_socket(self, client, addr):
        print("-----------------------------")
        print(f"Connected: {addr[0]}:{addr[1]}")
        while True:
            self.data = client.recv(BUFF)
            if len(self.data) < 1:
                print("Bye Client")
                print("----------------------------")
                client.close()
                return

            med, host, port, domain = med_host_port(self.data)
            self.data = self.check_connection()
            if med != "CONNECT":
                self.data = self.remove_site(domain)
            print(f'Client: \n{self.data.decode()}\n')
            res = self.on_connect(host, port, self.data)
            print(f"Server: \n{res}\n")
            client.send(res)

    def on_connect(self, host, port, data):
        forward = Forward()
        lb_for = forward.conn(host, port)
        if not lb_for:
            print("Not Connent to Server...")
            return False
        return forward.on_send(data)

    def check_connection(self):
        data = self.data.decode()
        if "Connection:" in data:
            print("change")
            data = data.replace("keep-alive", "close")
        return data.encode()

    def remove_site(self, domain):
        data = self.data.decode()
        data = data.replace(domain, "/", 1)
        return data.encode()



if __name__ == "__main__":
    server = Server(proxy_ip, proxy_port)
    try:
        print("Let's Go!")
        server.main_loop()
    except KeyboardInterrupt as e:
        print("Ctrl C - Stopping server")
        sys.exit(1)