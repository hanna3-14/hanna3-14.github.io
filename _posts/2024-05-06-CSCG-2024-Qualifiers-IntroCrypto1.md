---
layout: post
title: CSCG 2024 Qualifiers - Intro Crypto 1
tags: CTF Writeup Crypto AES-CTR Nonce
category: writeup
---

**CTF:** [Cyber Security Challenge Germany](https://cscg.de/) - Qualifier (from March 01, 2024 to May 01, 2024)

**Challenge-Name:** Intro Crypto 1

**Category:** Crypto

**Difficulty:** Easy

**Challenge-Author:** 0X4D5A

**Writeup by:** Hanna3-14

## Description
What is this non(c/s)ence everyonce is taking about?

## Attachments
`main.py`:
```python
#!/usr/bin/env pypy3

import os
from pydoc import plain
from sys import byteorder
from Crypto.Cipher import AES
from Crypto.Util import Counter
import hashlib

# Create a secret.py file with a variable `FLAG` for local testing :)
from secret import FLAG

secret_key = os.urandom(16)

def encrypt(plaintext, counter):
	m = hashlib.sha256()
	m.update(counter.to_bytes(8, byteorder="big"))

	alg = AES.new(secret_key, AES.MODE_CTR, nonce=m.digest()[0:8])
	ciphertext = alg.encrypt(plaintext)

	return ciphertext.hex()


def main():
	print("DES is broken, long live the secure AES encryption!")
	print("Give me a plaintext and I'll encrypt it a few times for you. For more security of course!")

	try:
		plaintext = bytes.fromhex(input("Enter some plaintext (hex): "))
	except ValueError:
		print("Please enter a hex string next time.")
		exit(0)
	
	for i in range(0, 255):
		print(f"Ciphertext {i:03d}: {encrypt(plaintext, i)}")
	
	print("Flag:", encrypt(FLAG.encode("ascii"), int.from_bytes(os.urandom(1), byteorder="big")))

if __name__ == "__main__":
	main()
```

## Writeup

### Understanding the Challenge

This challenge consists of a python script that accepts a hex value as user input.
Afterwards, 255 different ciphertexts are printed.
Finally, the encrypted flag is also printed.

Taking a look at the `main.py` file reveals that the encryption is done with AES.
To be more specific, Counter Mode (CTR) is used which as mode of operation for AES.
A quick research on [Wikipedia](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)) explains everything that I need to know about CTR to solve this challenge.

![AES-CTR]({{ url }}/images/AES-CTR/encryption.png)

With AES-CTR, a nonce is generated for each encryption.
As shown within the above figure, this nonce is concatenated with a counter that is incremented for each block.
The secret key is used to encrypt this concatenation via AES.
The most interesting thing to know (at least for this challenge) is, that AES is not directly used to encrypt the plaintext in Counter Mode.
Instead, AES is used to encrypt the concatenation of the nonce and the according counter to create an intermediate state.
This intermediate state is then used for an XOR operation with the plaintext block.

To decrypt the flag, I only need to figure out this intermediate state that is the result of each AES block.
With this information I can apply the XOR operation to this intermediate state and the ciphertext to get the plaintext as shown within the below figure.

![AES-CTR]({{ url }}/images/AES-CTR/decryption.png)

As I can send any plaintext to the oracle to receive all the 255 possible ciphertext, I can reproduce all possibilities for this intermediate state and use this information to decrypt the flag.

### Solving the Challenge

With a chosen plaintext attach I am able to reconstruct all 255 possibilities for the intermediate state and afterwards decrypt the flag.
The intermediate state can be calculated via an XOR opertion of a plaintext and the according ciphertext.
To simplify this step, I send a plaintext consisting of only zeros to the oracle.
With this, I can skip this XOR operation as the ciphertext equals the intermediate state.
The most important thing to note here is that the plaintext that I send to the oracle has to be at least the same length as the flag as I need to recreate the intermediate state of all blocks.

I read all the 255 possibilities of the intermediate state into my solve script and afterwards search for the flag by applying the XOR operation to the encrypted flag and any of the ciphertexts (which in this case are equal to the intermediate state).

#### Solve Script
```python
import pwn

# proc = pwn.process("python3 main.py", shell=True)
proc = pwn.remote('25b10651f8cf88c2696a1bdb-1024-intro-crypto-1.challenge.cscg.live', 1337, ssl=True)

# plaintext = b'00' * 15
plaintext = b'00' * 70

first_input_delim = b'Enter some plaintext (hex): '
proc.sendlineafter(first_input_delim, plaintext)

ciphertexts = []

for i in range(0, 255):
	ciphertext = proc.recvline().decode().split(": ")[1]
	ciphertexts.append(int(ciphertext.rstrip(), 16))

encryptet_flag = int(proc.recvline_startswith(b'Flag: ').decode().split(": ")[1].rstrip(), 16)

for i in range(0, 255):
	decrypted = encryptet_flag ^ ciphertexts[i]

	try:
		print(bytes.fromhex(hex(decrypted)[2:]).decode('utf-8'))
	except ValueError:
		pass
```

### flag
`CSCG{CTR_A3S_Br0ken!???N0pe,it's_C4ll3d_number_used_once_f0r_a_r3as0n}`

[^1]: `https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)`
