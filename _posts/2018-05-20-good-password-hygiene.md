---
layout: post
title: 'Good password hygiene'
date: 2018-05-20
author: Casey Mullineaux
cover: '/images/posts/good-password-hygiene/good-password-hygiene.jpg'
tags: security
---

So what makes a good password? Historically, we've always been told that a good password, is a *complex* password. This is simply not true.

<div class="alert alert-info">Size matters!</div>

# The problem

How many times have you been told by a website or an application, that your 'password does not meet complexity requirements'? It needs to be at least 8 characters, contain an uppercase letter, a number, and a symbol. The problem here is that the most important attribute of a password - the *length* - is usually not enforced to a degree that makes any meaningful impact. Instead, there is an emphasis on how complex, or *difficult* the password needs to be. To meet that requirement, all we do is simple character substitution. 

<div class="alert alert-danger">
    <strong>A password of 'B4tm4n' isn't much stronger than 'batman'.</strong><br/>
    <br/>
    'batman' - time to crack: instantly.<br/>
    'B4tm4n' - time to crack: 1 second.<br/>
</div>

Complexity alone doesn't make the password any stronger in any meaningful way. It only makes it more difficult to guess *by another human*. It also has the unwanted side effect of making it much more difficult to remember. This opens the doors to bad practices such as writing down passwords on post-it notes. This can lead to things like a [French network exposing it's passwords on live tv](https://arstechnica.com/information-technology/2015/04/hacked-french-network-exposed-its-own-passwords-during-tv-interview/), or [Hawaii's population being informed of an incoming balistic missile](https://motherboard.vice.com/en_us/article/7xeqe9/hawaii-emergency-password-post-it). Don't laugh - this stuff actually happens.

![hawaii-missile-crisis](https://amp.businessinsider.com/images/5a5e41e728eecc420c8b4fcb-750-375.jpg)

The truth is, when a computer is doing the guessing, the *complexity* of a password by itself has little impact on its strength. If a password is complex, but only four characters long, a computer will be able to attempt every possible combination of letters, numbers, and special characters within a matter of seconds.

As the [xkcd comic](https://xkcd.com/936) below explains, the end result is that we've successfully trained everyone to use passwords that are hard for humans to remember, but easy for computers to guess.
![xkcd](https://imgs.xkcd.com/comics/password_strength.png)

# The solution

Forget about passwords as you know them today. Use *passphrases* instead.
>A passphrase is a sequence of words or other text used to control access to a computer system, program or data. A passphrase is similar to a password in usage but is generally longer for added security.

A passphrase combines both attributes that make up a secure password. Complexity **and** length. The gif below demonstrates why this is important.

![complexity](/images/posts/good-password-hygiene/zFyBtyA.gif)


Here are five simple steps to create a secure passphrase.

## Step 1 - Find your phrase
A good technique is to use a couple of random dictionary words that make up a silly story (such as the comic above) or use your favourite quote from a movie, book, or tv show.

As an example:
<div class="alert alert-info">whereweregoingwedontneedroads</div>

## Step 2 - Capitalize
At this step, your password is probably already stronger than any of your other passwords. But we can do better. Add some complexity by capitalizing the first letter of each word. 
<div class="alert alert-info">WhereWereGoingWeDontNeedRoads</div>

## Step 3 - Add punctuation
If you're going to use a passphrase, you may as well keep your English teacher happy ...
<div class="alert alert-info">WhereWe'reGoingWeDon'tNeedRo</div>

## Step 4 - Add spaces
Fun Fact: the space character is often not included in the standard character set used for brute force attacks. Adding just as single space greatly increases the strength of a password.
<div class="alert alert-info">Where We're Going We Don't Need Roads!</div>

## Step 5 - Add emphasis
You can go one step further by using block capitals for one or more words.
<div class="alert alert-success">Where We're Going We Don't NEED Roads!</div>

And there you have it. An easy to remember, 38 character, complex passphrase, that according to [howsecureismypassword.net](https://howsecureismypassword.net) will take **26 septendecillion** years (is that even a word?) to crack.

![good-password-hygiene](/images/posts/good-password-hygiene/good-password-hygiene.png)


*Note: Please don't use this password!*