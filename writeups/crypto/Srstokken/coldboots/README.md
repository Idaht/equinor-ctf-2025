# Sørstokken: Offline bruteforce attack before SRP proof

```
Team: coldboots (https://ctftime.org/team/144114/)
Author: @ciphr
Date: 10.11.2025
```

# TL;DR -- summary
- the server leaks the AES-encrypted welcome message **before** it checks the SRP proof.
- this allows us to bruteforce `admin_password` as it's search-space is a number `0 .. 499999`
- it takes ~minutes even with the custom key stretching that uses 2025 iteration of sha256.

A nice PoW is enabled to prevent brute-force against the remote, but that's not a problem. Lucky us, the author included the `client.py` that does all the hard work!

# Attack
- For local testing i set `POW_difficulty = 1` in my **server.py**
- I patch inn a modified `Client.authenticate` to inline the bruteforce attack, and then login to get the flag.

> **NOTE** Remember that the admin's `password = <salt><bruteforced part>`


# Flag
```
$ python3 solve.py
[+] Opening connection to coldboots-3b926378-soerstokken.ept.gg on port 1337: Done
[┤] 🏴 PoW
POW_enabled='1' POW_prefix='3a07e58885d4ef4e3265f82d706d05d3' POW_difficulty=22
[q] 🏴 Bruteforcing: ! found password=114007
password 22489c234ff90fb413973725bb002e37114007
User message: EPT{but_I_thought_SRP_was_ZK_where_did_I_go_wrong}
[*] Closed connection to coldboots-3b926378-soerstokken.ept.gg port 1337
```

# solve.py

```python
from pwn import remote, process
from hashlib import sha256
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES
from common import *
import secrets


a = secrets.randbits(1024)
salt = None
ciphertext = None
B, u = None, None

from multiprocessing import Pool
from pwn import log

def try_decrypt_with_K(ciphertext, K):
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    try:
        plain = unpad(AES.new(K, AES.MODE_CBC, iv).decrypt(ct), AES.block_size)
        return plain.decode(errors="ignore")
    except Exception:
        return None

def test_decrypt(i):
    global salt, ciphertext, B, U, a
    password = str(i).encode()
    x =  custom_password_hash(salt, salt+password)
    S = pow(B - k*pow(g, x, P), a + u*x, P)
    K = sha256(long_to_bytes(S, SRP_LEN)).digest()
    plaintext = try_decrypt_with_K(ciphertext, K)
    if plaintext != None and b"Welcome" in plaintext.encode():
        return str(i)
    return False

def attack():
    p = Pool(50)
    MAX = 500_000    
    logger = log.progress("🏴 Bruteforcing")
    for i in range(0, MAX, 1000):        
        logger.status(f"trying {i}..")
        match = p.map(test_decrypt, range(i,i+1000))
        hits = list(filter(None, match))
        if len(hits)>0:
            logger.status(f"! found password={hits[0]}")
            return hits[0]        
    raise Exception("buggy! not found")



def evil_authenticate(self, username, password):
    global salt, ciphertext, B, u

    # Stage 1 - send username, get params
    self.socket.sendline(username.encode())
    salt = bytes.fromhex(self.recv())

    # Stage 2 - exchange public params        
    A = pow(g, a, P)
    self.socket.sendline(str(A).encode())

    B, u = map(int, self.recv().split(","))

    # ATTACK
    line = self.socket.recvlineS()
    ciphertext = bytes.fromhex(line[1:])
    password = salt.decode() + str(attack())
    print("password", password)
    # ATTACK
    
    x = custom_password_hash(salt, password.encode())
    S = pow(B - k*pow(g, x, P), a + u*x, P)
    K = sha256(long_to_bytes(S, SRP_LEN)).digest()
    self.key = K

    # Build and send M1
    verify = sha256()
    verify.update(long_to_bytes(A, SRP_LEN))
    verify.update(long_to_bytes(B, SRP_LEN))
    verify.update(long_to_bytes(S, SRP_LEN))
    local_M = verify.digest()
    self.socket.sendline(local_M.hex().encode())

    # ATTACK
    #print(f"User message: {self.recv()}")
    # ATTACK

    # Get M2 from server and verify it
    remote_M2 = self.recv()    

    M2 = sha256()
    M2.update(long_to_bytes(A, SRP_LEN))
    M2.update(local_M)
    M2.update(long_to_bytes(S, SRP_LEN))
    M2 = M2.hexdigest()

    if remote_M2 != M2:
        print("Password mismatch")
        raise AuthError

    # If all went well, retrieve and display the user message!
    print(f"User message: {self.recv()}")
    self.socket.close()


from client import Client
cli = Client()
cli.authenticate = evil_authenticate
logger = log.progress("🏴 PoW")
cli.handle_pow()
cli.authenticate(cli, "admin", "kek")
```



# my poor laptop
This is why multiprocessing.Pool is awesome. Use those cpu cores!

> remember to set your `Power Mode` to `performance`

`htop -n 1 > file` didn't work too great, but hey! you get the point!
```
0[||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||98.2%]
4[||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||98.2%]
8[||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||98.2%]
12[||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||96.5%]  

1[||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||98.2%]
5[||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||96.6%]
9[|||||||||||||||||||||||||||||||||||||||||||||||||||||||||||100.0%]

13[|||||||||||||||||||||||||||||||||||||||||||||||||||||||||||100.0%]  
2[|||||||||||||||||||||||||||||||||||||||||||||||||||||||||||100.0%]
6[|||||||||||||||||||||||||||||||||||||||||||||||||||||||||||100.0%]
10[|||||||||||||||||||||||||||||||||||||||||||||||||||||||||||100.0%] 
14[|||||||||||||||||||||||||||||||||||||||||||||||||||||||||||100.0%]  
3[||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||98.2%]
7[|||||||||||||||||||||||||||||||||||||||||||||||||||||||||||100.0%]
11[|||||||||||||||||||||||||||||||||||||||||||||||||||||||||||100.0%]
15[||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||98.2%]  
```