---
layout: post
title: ImaginaryCTF - caeRSA
tags: CTF Writeup Crypto RSA
---

**CTF:** [ImaginaryCTF](https://imaginaryctf.org/ArchivedChallenges) - Challenge from October 31, 2023

**Challenge-Name:** caeRSA

**Category:** Crypto

**Difficulty:** 75pts

**Challenge-Author:** Eth007

**Writeup by:** Hanna3-14

## Description
Is this a caesar cipher?

## Attachments
For this challenge, two files are provided:

`output.txt`:
```
n = 19355995213714664465702502197305959105349530032907725752203864507983484143883515103245262219845738556578566246257890295513849511693035895337799781462040021809333980041553610054523098268493332135409959470003449559236197049689580174601191674962605756998195741956214835847971758629035220436091190633919878395634554284822355022358100266404337050233556015328446673749251644703836645992049002768610956950167294796711793256875005940215938598600778329755667357450234437401681448573611133702927124285161778557710292542578221686802387399003174702448048280316265014781609804599757565913109056825709295961296668516906772294894267
e = 65537
c = 2589396961489841386774801094025522637294961737788302802011804836049290819986834354571223130301042061844015459587816779529877282493874010800897717704821234553047507738254449760614059950932071655883388132120048602642425805600328441165661157493286672680368626893279651764828675384508095593604357548448614439436138329783188336622845193076111617148333129545417269202789618345005565895688470183243741846853073168382549299550197124460516551663112475087629528164148557387616384457069308197464014549599762347165082824488724164677141229974801501119152691614064057344096940488716836722966158192052893160769301757434356622387301
leak = 19355995213714664465702502197305959105349530032907725752203864507983484143883515103245262219845738556578566246257890295513849511693035895337799781462040021809333980041553610054523098268493332135409959470003449559236197049689580174601191674962605756998195741956214835847971758629035220436091190633919878395650291300341110072778644856476367976824940253046709334578547483288535872216727552340415669616745382170725761906332792655288093828011648890862980153303055534564785621895847836134539600723704388044176380330885723549547817012230475742006686256038468745789455668494100021250138374979579486926903849987506606806460280
```

`main.py`:
```python
from Crypto.Util.number import getPrime, long_to_bytes, bytes_to_long

p = getPrime(1024)
q = getPrime(1024)
e = 65537

n = p*q
leak = (p+42)*(q+69)
m = bytes_to_long(open("flag.txt", "rb").read().strip())
c = pow(m, e, n)

print(f"{n = }")
print(f"{e = }")
print(f"{c = }")
print(f"{leak = }")
```

## Writeup

### Understanding the Challenge
For this challenge the flag is convertet into a long and afterwards encrypted with RSA.
The `output.txt` file contains the values of `n`, `e`, `c` and `leak`.
The value of leak is calculated as

`leak = (p + 42) * (q + 69)`

### Solving the Challenge
To solve this challenge I read the values of the `output.txt` file into the respective variables `n`, `e`, `c` and `leak`.
After trying some not so useful brute force attacks I strained my head and did some math.

First of all, I know that `p * q = n`.

In addition I have the value of leak as: `leak = (p + 42) * (q + 69)`

which can be rearranged as: `leak = (p * q) + 69p + 42q + (42 * 69)`.

After replacing `(p * q)` by `n` and rearranging the formula again I get the following equation:

`69p + 42q = leak - (42 * 69) - n`

I can rearrange `p * q = n` to get `q = n/p` which leads to the following equation:

`69p + 42 * n/p = leak - (42 * 69) - n`

multiplying this equation by `p` results in:

`69p² + 42n = (leak - (42 * 69) - n) * p`

which is a quadratic equation that can be formatted nicely as:

`69p² - (leak - (42 * 69) - n) * p + 42n = 0`

Solving this equation with the `abc-formula` possibly returns two solutions.
In this case, only one of those solutions is a valid solution.
I denote the only solution as `p` and calculate `q` by dividing `n` with `p`.

Now I have everything that I need to solve this challenge.
After calculating `φ(n)` the decryption key `d` can be calculated easily as `e` is known from the `output.txt` file.
As the last two steps I decrypt the cipher (`c`) and convert it to bytes.

#### Solve Script
```python
from Crypto.Util.number import long_to_bytes
from decimal import Decimal, getcontext
import math

# set the precision for Decimal calculations
getcontext().prec = 10000

def abc(a, b, c):
	decA = Decimal(a)
	decB = Decimal(b)
	decC = Decimal(c)
	bsquared = (decB * decB) - (4 * decA * decC)
	try:
		x1 = (-1 * decB + bsquared.sqrt()) / (2 * decA)
	except:
		x1 = None
	try:
		x2 = (-1 * decB - bsquared.sqrt()) / (2 * decA)
	except:
		x2 = None
	return x1, x2

with open('output.txt', 'r') as output:
	
	lines = []

	for line in output:
		line = line.split()
		lines.append(line[2])

	n = lines[0]
	e = lines[1]
	c = lines[2]
	leak = lines[3]

	# p * q = n
	# (p + 42) * (q + 69) = leak
	# n + 42q + 69p + 42 * 69 = leak
	b = int(leak) - (42 * 69) - int(n)
	
	p, q = abc(69, -b, 42*int(n))

	if p != None:
		decP = Decimal(p)
	else:
		decP = Decimal(q)	
	decQ = Decimal(int(n)) / decP
	
	phi = (decP - Decimal('1')) * (decQ - Decimal('1'))

	d = pow(int(e), -1, int(phi))

	d = pow(int(e), -1, int(phi))

	m = pow(int(c), d, int(n))
	print(long_to_bytes(m).decode('ascii'))
```

### flag
`ictf{did_caesar_really_know_crypto}`
