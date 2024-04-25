---
layout: post
title: ImaginaryCTF - R54
tags: CTF Writeup Crypto RSA
category: writeup
---

**CTF:** [ImaginaryCTF](https://imaginaryctf.org/ArchivedChallenges) - Challenge from March 18, 2024

**Challenge-Name:** R54

**Category:** Crypto

**Difficulty:** 50pts

**Challenge-Author:** NoobMaster

**Writeup by:** Hanna3-14

## Description
An easy RSA challenge for you! Remote: `nc 34.173.236.50 49100` Note: When inputting the secret message as hex, do not send "0x"

## Attachments
`R54.py`:
```python
#!/usr/local/bin/python
from Crypto.Util.number import *
import os
p = getPrime(512)
q = getPrime(512)
n = p * q
phi = (p-1)*(q-1)
e = 65537
m = bytes_to_long(os.urandom(16))
c = pow(m,e,n)
print(f'{c = }')
print(f'{n = }')
print(f'{phi = }')
print("Enter the values of p, q, and the secret message to get the flag!\n")
input1 = int(input("Enter p: ").strip())
input2 = int(input("Enter q: ").strip())
message = int(input("Enter the secret message as hex: ").strip(),16)
if ((input1 == p and input2 == q) or (input1 == q and input2 == p)) and (message == m):
    print(open("flag.txt").read())
else:
    print("Wrong!")
```

## Writeup

### Understanding the Challenge
For this challenge I am confronted with a programm that prints the values `c`, `n` and `phi(n)` from an RSA encryption.
I need to calculate `p`, `q` and the secret `message` and provide those values to the program.

### Solving the Challenge
I wrote a solve script that reads the values of `c`, `n` and `phi(n)` from the program.
As the value of `phi(n)` is known, it is simple to decode the message from the ciphertext as I can easily calculate the decryption key `d`.
Based on the equation `e * d = 1 (mod phi(n))` the decryption key can be calculated as the multiplicative inverse of the encryption key `e` within the finite field of `phi(n)`
The equation can be rearranged to be `d = e⁻¹ (mod phi(n))` for the calculation of `d`.

With a little maths and the help of `z3` I could also calculate the values for `p` and `q`.
As `phi(n) = (p - 1) * (q - 1)` I could multiply out the formula to get `phi(n) = pq - q - p + 1`.
With replacing `p * q` by `n` and a little more rearrangement I set up the following equation: `p + q = -1 * (phi(n) - n - 1)`.
I put this equation as well as the well-known `p * q = n` into the `z3`-solver which calculates the values of `p` and `q` based on these equations.

Finally I could send those values to the program.
The message needed to be a hex value.

### Alternative Solutions
After solving the challenge I figured out that there actually is a way to calculate the values of `p` and `q` without the help of `z3`.
It is documented on this [page](https://crypto.stackexchange.com/questions/5791/why-is-it-important-that-phin-is-kept-a-secret-in-rsa) how the knowledge of `phi(n)` can be used to break RSA.

By further rearranging the formula it is possible to calculate `p` and `q` with the abc-formula.
This approach is also used for the author's solve script.

#### Solve Script
```python
import pwn
import z3

proc = pwn.remote('34.173.236.50', 49100)
# proc = pwn.process("python3 R54.py", shell=True)

e = 65537

c = int(proc.recvline_startswith(b'c = ').split(b' = ')[1])

n = int(proc.recvline_startswith(b'n = ').split(b' = ')[1])

phi = int(proc.recvline_startswith(b'phi = ').split(b' = ')[1])

d = pow(int(e), -1, int(phi))

message = pow(c, d, n)

p_and_q = -1 * (phi - n - 1)

p_z3 = z3.Int('p')
q_z3 = z3.Int('q')

s = z3.Solver()
s.add(p_z3 * q_z3 == n)
s.add(p_z3 + q_z3 == p_and_q)
s.check()

first_input_delim = b'Enter p:'
p = s.model()[p_z3].as_long()
proc.sendlineafter(first_input_delim, str(p).encode())

second_input_delim = b'Enter q: '
q = s.model()[q_z3].as_long()
proc.sendlineafter(second_input_delim, str(q).encode())

third_input_delim = b'Enter the secret message as hex: '
message = hex(message)
message = str(message).replace('0x', '')
proc.sendlineafter(third_input_delim, message.encode())

proc.interactive()
```

#### Author's Solve Script
```python
from pwn import *
from gmpy2 import iroot
io = remote("34.173.236.50","49100")
io.readuntil(b'c =')
ct = int(io.readline().strip())
io.readuntil(b'n =')
n = int(io.readline().strip())
io.readuntil(b'phi =')
phi = int(io.readline().strip())
e = 65537
private = pow(e,-1,phi)
message = hex(pow(ct,private,n))[2:]
a = 1
b = -(n+1-phi)
c = n
d = pow(b,2) - 4*a*c
p = (-b - iroot(d,2)[0])//(2*a)
q = n//p
assert n == p*q
io.sendline(str(p).encode())
io.sendline(str(q).encode())
io.sendline(str(message).encode())
io.readuntil(b"Enter p: Enter q: Enter the secret message as hex: ")
flag = io.readline().strip()
print(flag)
```

### flag
`ictf{1_l0v3_r54_d0_y0u?_7f1a3d2e4b5c}`
