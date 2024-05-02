---
layout: post
title: ImaginaryCTF - Time 2
tags: [CTF, Writeup, Crypto, AES, Key Generation]
category: writeup
---

**CTF:** [ImaginaryCTF](https://imaginaryctf.org/ArchivedChallenges) - Challenge from April 15, 2024

**Challenge-Name:** Time 2

**Category:** Crypto

**Difficulty:** 85pts

**Challenge-Author:** NoobMaster

**Writeup by:** Hanna3-14

## Description
I guess one seed was not enough... `nc 34.72.43.223 48123`

## Attachments
`chall.py`:
```python
#!/usr/local/bin/python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import random
import time
import os

def encrypt(message, key):
	cipher = AES.new(key, AES.MODE_ECB)
	ciphertext = cipher.encrypt(pad(message, AES.block_size))
	return ciphertext

flag = open('flag.txt','rb').read().strip()
random.seed(int(os.urandom(64).hex(),16)) # super secure!
key = b''
x=random.randbytes(1)
for i in range(16):
	key += x
	random.seed(int(x.hex(),16))
	x = random.randbytes(1)
encrypted_flag = encrypt(flag, key)
print("Encrypted flag (in hex):", encrypted_flag.hex())
```

## Writeup

### Understanding the Challenge
This challenge is a direct successor of the challenge called `Time`.
Read my according writeup [here](https://hanna3-14.github.io/writeup/2024/05/01/ImaginaryCTF-time.html) in case you haven't read it so far.

This time, the seed used for the `random()` function is super secure (let's trust the comment).
The vulnerability here is that the `random()` function is used to only generate a single byte.
This byte can easily be brute-forced as there are only 256 possiblities for the value of it.
The key generation is completely deterministic and can easily be reproduced as is based on this single byte that has been generated from the `random()` function.

### Solving the Challenge
My solve script brute-forces all 256 possiblities for the start byte and afterwards reproduces the possible encryption key.
Each encryption key is used to decrypt the flag and check whether the decrypted bytes contain the flag format.

#### Solve Script
```python
from Crypto.Cipher import AES
import random
import pwn

def decrypt(ciphertext, key):
	cipher = AES.new(key, AES.MODE_ECB)
	message = cipher.decrypt(ciphertext)
	return message

proc = pwn.remote('34.72.43.223', 48123)
# proc = pwn.process("python3 chall.py", shell=True)

encrypted_flag = proc.recvline_startswith(b'Encrypted flag (in hex): ').split(b': ')[1]

encrypted_flag = bytes.fromhex(encrypted_flag.decode())

flag_found = False
key = b''
x = b'\x00'

for i in range(0, 255):
	key = b''
	for j in range(16):
		key += x
		random.seed(int(x.hex(),16))
		x = random.randbytes(1)
	flag = decrypt(encrypted_flag, key)
	if b'ictf' in flag:
		flag_found = True
		print("Flag:", flag.decode('ascii'))
	else:
		x = i.to_bytes(1)
```

### flag
`ictf{1_n33d_t0_1mpr0v3_s3cur17y}`
