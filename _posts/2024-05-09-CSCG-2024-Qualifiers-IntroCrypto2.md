---
layout: post
title: CSCG 2024 Qualifiers - Intro Crypto 2
tags: [CTF, Writeup, Crypto, SHA-1, Length Extension Attack]
category: writeup
---

**CTF:** [Cyber Security Challenge Germany](https://cscg.de/) - Qualifier (from March 01, 2024 to May 01, 2024)

**Challenge-Name:** Intro Crypto 2

**Category:** Crypto

**Difficulty:** Easy

**Challenge-Author:** NEVSOR

**Writeup by:** Hanna3-14

## Description
If you give a user some data and read it from the user later (e.g. when using cookies), you have to ensure the user has not tampered with it.

This challenge implements a simple, but insecure MAC scheme.

## Attachments

`main.py`:
```python
#!/usr/bin/env python3

from hashlib import sha1
from base64 import b64encode, b64decode
from secrets import token_hex

from secret import FLAG


KEY = token_hex(16)


def get_mac(data: bytes) -> str:
	return sha1(KEY.encode("latin1") + data).hexdigest()


def parse_token(token: str) -> dict:
	# Decode token
	token = b64decode(token)

	# Check the MAC
	token, mac = token.split(b"|mac=")
	if get_mac(token) != mac.decode("latin1"):
		return None

	# Parse values
	values = dict()
	for part in token.decode("latin1").split("|"):
		key, value = part.split("=")
		values[key] = value
	return values


def generate_token(values: dict) -> str:
	token = "|".join(f"{key}={value}" for key, value in values.items())
	secure_token = f"{token}|mac={get_mac(token.encode('latin1'))}"

	return b64encode(secure_token.encode("latin1")).decode("latin1")


def handle_register():
	name = input("What is you name? ")
	animal = input("What is your favorite animal? ")

	token = generate_token(
		{
			"name": name,
			"animal": animal,
			"admin": "false",
		}
	)

	print("Here is your access token:", token)


def handle_show_animal_videos():
	user_data = parse_token(input("Enter access token: "))

	if user_data is None:
		print("Invalid token.")
		return

	print(
		f"\nHere are some {user_data['animal']} videos for you: https://www.youtube.com/results?search_query=funny+{user_data['animal']}+video+compilation"
	)


def handle_show_flag():
	user_data = parse_token(input("Enter access token: "))

	if user_data is None:
		print("Invalid token.")
		return

	if user_data["admin"] == "true":
		print("The flag is", FLAG)
	else:
		print("You are not an admin.")


def main():
	while True:
		# Show main menu

		print(
			"""
		1. Register
		2. Show animal videos
		3. Show flag
		4. Exit
		"""
		)

		try:
			choice = int(input("Enter your choice: "))
		except ValueError:
			print("Please enter a number next time.")
			continue
		except EOFError:
			break

		if choice == 1:
			handle_register()
		elif choice == 2:
			handle_show_animal_videos()
		elif choice == 3:
			handle_show_flag()
		elif choice == 4:
			break
		else:
			print("Please enter a valid choice.")


if __name__ == "__main__":
	main()
```

## Writeup

### Understanding the Challenge
One of the purposes of a Message Authentication Code (MAC) is to detect any changes to the content of a message.
As mentioned in the challenge description, the MAC used here appears to be insecure.

When I run the `main.py` script, I can register an account and will therefore get an access token.
Unfortunately, this token has the admin parameter set to false but I need an admin token to access the flag.
Apparently, I need to somehow set the admin parameter to true but the access token still needs to be valid.

### Solving the Challenge
First, I investigated how the access token is generated based on my input.
The token string `name=|animal=|admin=false` is generated based on my input for my name and my favorite animal.
To keep things simple, I left the input fields empty.

The MAC for the token string is created using the SHA-1 hash function and then concatenated to the existing string with `|mac={hashsum}`.
Before applying the hash function, a salt of 32 bytes is prepended to the token string.
Knowing the value of the salt would give me the ability to create any valid access token by myself.
This would make it easy to set the admin parameter to true, but unfortunately brute forcing this salt would be too much effort.

Since I cannot create a new token by myself, I need to modify the token that I received when I registered my account.
After doing some research on the SHA-1 hash function, I learned about the length extension attack which is well described in the answer of this [question on stackexchange](https://crypto.stackexchange.com/questions/3978/understanding-the-length-extension-attack).
Using this attack, I can extend the token string to be the following:
```
{32 bytes salt}name=|animal=|admin=false{some padding}|admin=true|mac={hashsum}
```
I took another look at the `main.py` file to verify that the last value of the admin parameter is be used for the authorization once I try to access the flag.

To understand the attack it is important to know at least some basics about SHA-1.
This hash function processes data in 512-bit blocks, where the output of hashing any block is used as the initialization vection (IV) for the next block.
The output of hashing the last block is the total hash sum.
In the context of this challenge, I want to extend the input string for the hash function by another 512-bit block but still get a valid SHA-1 hash according to the prepended salt.
Fortunately, I can use the hash sum contained in the current token as the IV for hashing the additional block.
This allows me to create a valid access token that includes admin rights.

I found a python implementation of SHA-1 on [stackexchange](https://codereview.stackexchange.com/questions/37648/python-implementation-of-sha1) that I modified for my use case.
The original implementation from stackexchange contained the IV based on the SHA-1 specification.
I modified this function to accept the hash sum of the previous block as the IV.
I also had to make some changes to the padding, which I will describe below.
With these modifications, I can form the valid hash sum of an additional block containing the string `|admin=true` without knowing the value of the salt that has been used.

To form the complete access token, I also need to reproduce the padding bits that are used to fit the initial input string into blocks of 512 bits before the hashing has been performed.
The value of the padding depends on the length of the input string that has been given to the hash function.
In the case of this challenge, the input string is made up of 256 bits (32 bytes) for the salt as well as 200 bits (25 bytes) for the token string `name=|animal=|admin=false`, for a total of 456 bits.
Now I can start to recreate the padding.
Based on the SHA-1 specification, the padding starts with a single 1-bit.
Then zero bits are appended until the total length equals 448 mod 512.
The hex value of the length of the input string (456 bits) is 1C8 and is added as 64 bit padding to fill the last block to 512 bits.

In my solve script, the padding is generated at the byte level.
Therefore, the byte `80` is added to represent the hex representation of the single 1-bit followed by 15 zero bits.
Then the padding of 62 zero bytes is added to generate a total length of 960 bits, which is equal to 448 bits mod 512.
With this information I already know, that 2 blocks of 512 bits each are used for the hashing.

After recreating the padding that was used to create the original hash value, I need to make one final adjustment to the hash function.
As you can see in the below code snippet, the original implementation that I found on stackexchange would automatically determine the length of the input string in bits and add that value into the padding.
```python
#append the original length
	pBits+='{0:064b}'.format(len(bits)-1)
```
If I were to use this code as it is, it would add only add the length of the additional block `name=|animal=|admin=false` into the padding because I am only providing that block for the hash function.
This would result in an invalid MAC because I need to pretend that this additional block is attached directly to the previous two blocks that contain the salt, the original token string and the original padding.
For this reason, I have modified this line of code to add the length of 1112 bits instead.
This length is calculated as the length of the two original blocks, each of which is 512 bits long, for a total of 1024 bits.
It also adds the length of the third block, which is 11 bytes, or 88 bits.
Now that the modified hash function produces a valid hash sum, I managed to generate a valid admin token that I can use to retrieve the flag.

#### Solve Script
```python
import pwn
from base64 import b64encode, b64decode

def sha1(data, h0, h1, h2, h3, h4):
	bytes = ""

	for n in range(len(data)):
		bytes+='{0:08b}'.format(ord(data[n]))
	bits = bytes+"1"
	pBits = bits
	# pad until length equals 448 mod 512
	while len(pBits)%512 != 448:
		pBits+="0"
	# append the original length
	pBits+='{0:064b}'.format(1112) # 1112 bits is the length of m||p||z

	def chunks(l, n):
		return [l[i:i+n] for i in range(0, len(l), n)]

	def rol(n, b):
		return ((n << b) | (n >> (32 - b))) & 0xffffffff

	for c in chunks(pBits, 512): 
		words = chunks(c, 32)
		w = [0]*80
		for n in range(0, 16):
			w[n] = int(words[n], 2)
		for i in range(16, 80):
			w[i] = rol((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]), 1)  

		a = h0
		b = h1
		c = h2
		d = h3
		e = h4

		# main loop
		for i in range(0, 80):
			if 0 <= i <= 19:
				f = (b & c) | ((~b) & d)
				k = 0x5A827999
			elif 20 <= i <= 39:
				f = b ^ c ^ d
				k = 0x6ED9EBA1
			elif 40 <= i <= 59:
				f = (b & c) | (b & d) | (c & d) 
				k = 0x8F1BBCDC
			elif 60 <= i <= 79:
				f = b ^ c ^ d
				k = 0xCA62C1D6

			temp = rol(a, 5) + f + e + k + w[i] & 0xffffffff
			e = d
			d = c
			c = rol(b, 30)
			b = a
			a = temp

		h0 = h0 + a & 0xffffffff
		h1 = h1 + b & 0xffffffff
		h2 = h2 + c & 0xffffffff
		h3 = h3 + d & 0xffffffff
		h4 = h4 + e & 0xffffffff

	return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)

proc = pwn.process("python3 main.py", shell=True)
# proc = pwn.remote("3a036f3c7331fe7542d395f6-1024-intro-crypto-2.challenge.cscg.live", 1337, ssl=True)

first_input_delim = b'Enter your choice: '
second_input_delim = b'What is you name? '
third_input_delim = b'What is your favorite animal? '

first_selection = b'1'
name = b''
animal = b''

proc.sendlineafter(first_input_delim, first_selection)
proc.sendlineafter(second_input_delim, name)
proc.sendlineafter(third_input_delim, animal)

token = proc.recvline().decode().split(": ")[1].rstrip()
token = b64decode(token)

mac = token.split(b"|mac=")[1]

mac1 = int(mac[0:8].decode("latin1"), 16)
mac2 = int(mac[8:16].decode("latin1"), 16)
mac3 = int(mac[16:24].decode("latin1"), 16)
mac4 = int(mac[24:32].decode("latin1"), 16)
mac5 = int(mac[32:40].decode("latin1"), 16)
hash = sha1("|admin=true", mac1, mac2, mac3, mac4, mac5)

padding = ""
padding += "80"
padding += "00" * 62
padding += "00000000000001C8" # 456 bytes = length of salt + "name=|animal=|admin=false"
token = b"name=|animal=|admin=false" + bytes.fromhex(padding) + b"|admin=true|mac=" + hash.encode("latin1")
token = b64encode(token)

first_selection = b'3'
second_input_delim = b'Enter access token: '

proc.sendlineafter(first_input_delim, first_selection)
proc.sendlineafter(second_input_delim, token)

flag = proc.recvline().decode().split(" ")[3].rstrip()
print(flag)
```

### flag
`CSCG{Should_have_used_HMAC_or_KMAC_instead-.-}`
