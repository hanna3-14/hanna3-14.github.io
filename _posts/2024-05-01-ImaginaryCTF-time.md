---
layout: post
title: ImaginaryCTF - Time
tags: CTF Writeup Crypto AES Seed Random
category: writeup
---

**CTF:** [ImaginaryCTF](https://imaginaryctf.org/ArchivedChallenges) - Challenge from April 11, 2024

**Challenge-Name:** Time

**Category:** Crypto

**Difficulty:** 75pts

**Challenge-Author:** NoobMaster

**Writeup by:** Hanna3-14

## Description
Just decrypt the flag! `nc 34.72.43.223 48000`

## Attachments
`chall.py`:
```python
#!/usr/local/bin/python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import random
import time

def encrypt(message, key):
	cipher = AES.new(key, AES.MODE_ECB)
	ciphertext = cipher.encrypt(pad(message, AES.block_size))
	return ciphertext

flag = open('flag.txt','rb').read().strip()
random.seed(int(time.time()))
key = random.randbytes(16)

encrypted_flag = encrypt(flag, key)
print("Encrypted flag (in hex):", encrypted_flag.hex())
```

## Writeup

### Understanding the Challenge
For this challenge, the flag is encrypted with AES in Electronic Code Book Mode (ECB).
The key for the encryption consists of 16 random bytes that are generated with the python `random()` function.
As stated within the [documentation](https://docs.python.org/3/library/random.html) of this `random()` function, it is unsuitable for cryptographic purposes as it is completely deterministic.
Before generating the key, the seed of the random method is set to be the current unix timestamp.
Once I figured out the exact time of the key generation, I can reproduce the key and therefore decrypt the flag.

### Solving the Challenge
I wrote a solve script for solving this challenge.
Once I open the connection to the remote challenge (or run the challenge locally), I read the value of the encrypted flag into the solve script.
Afterwards I try decrypting the flag by using the current unix timestamp as seed for the `random()` function and then generating the key for the AES algorithm.
Based on the flag format I can verify whether the flag has been found.
As long as the decrypted bytes do not contain the flag format, I decrease the seed for the `random()` function by one second and run the decryption process again.
With this, I can go back in time step by step and eventually find the correct key that has been used for the encryption.

#### Solve Script
```python
from Crypto.Cipher import AES
import random
import time
import pwn

def decrypt(ciphertext, key):
	cipher = AES.new(key, AES.MODE_ECB)
	message = cipher.decrypt(ciphertext)
	return message

proc = pwn.remote('34.72.43.223', 48000)
# proc = pwn.process("python3 chall.py", shell=True)

encrypted_flag = proc.recvline_startswith(b'Encrypted flag (in hex): ').split(b': ')[1]

encrypted_flag = bytes.fromhex(encrypted_flag.decode())

timeseed = int(time.time())
random.seed(timeseed)
key = random.randbytes(16)
flag_found = False
while flag_found == False:
	decrypted_flag = decrypt(encrypted_flag, key)
	if b'ictf' in decrypted_flag:
		flag_found = True
		print("Flag:", decrypted_flag)
	else:
		timeseed -= 1
		random.seed(timeseed)
		key = random.randbytes(16)
```

### flag
`ictf{1_c4n_bru73f0rc3_t1m3_1ts3lf!}`
