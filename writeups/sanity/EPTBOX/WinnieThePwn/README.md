From the challenge description we get that there is a flag hidden on our EPTBOX, and that the following command was executed to encrypt the flag:

```bash
$ openssl enc -des-ede3-cbc -salt -pbkdf2 -iter 250000 \
-in flag.txt -out .ept.txt.enc \
-pass pass:epteptepteptepteptepteptepteptepteptepteptept 
```

I therefore looked for the `.ept.txt.enc` file by using find:

```
find / -iname ".ept.txt.enc" -type f 2>/dev/null
```

Find found the file located in `/usr/share/.ept.txt.enc` .
I then decrypted it with openssl using the `-d` option:

```
openssl enc -d -des-ede3-cbc -salt -pbkdf2 -iter 250000 \
-in /usr/share/.ept.txt.enc -out decrypted_flag.txt \
-pass pass:epteptepteptepteptepteptepteptepteptepteptept
```

And read the flag with cat

```
cat decrypted_flag.txt 

EPT{EPTb0x_b3st_b0x!} 
```

#### Flag: EPT{EPTb0x_b3st_b0x!} 