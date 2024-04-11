**CTF:** [ImaginaryCTF](https://imaginaryctf.org/ArchivedChallenges) - Challenge from November 02, 2023

**Challenge-Name:** caeRSA2

**Category:** Crypto

**Difficulty:** 50pts

**Challenge-Author:** quasar098

**Writeup by:** Hanna3-14

## Description
todo think of witty description

## Attachments
For this challenge, two files are provided:

`output.txt`:
```
79042006452860058297974339760070849541387880896278476411190080004015676005013 641071400881800725518430254332081121802 819556310889501693286593613495081034203
89075738936782078082773468624634410565236830709459835679338473908704097356169658 3037653281877117565882923921716670057058 2873355015056965690524690133873030165768
4247532611409661020009322332169937699599179370714823752330375508233335920169683048 12099463329932863016905061245318999247943 67642748976031060590224836973498959064563
500191030286923291989900554337564754446512722045236408438503375816227243854735664228 1012004450594520498891331338464888336000399 4392238896479798962739065684742223551352112
86630178010058699836895267117568132752060809075134352826099205446701360362163617118230 02396260088848037847549446559088530231277950 03754233969312275017584043950886996171912986
90387560263172753186251853747562967086621897623871761688999696473979925674816604665832912 209861748128862770451563666370069144942762996 866032272987562095930521486763700003372461627
3663855033365661974922008463173324070221492249258566098370103865842118923429467859745954424 0686607631616615108760243403330825610405794080 5349910384187724593561351203238640195580654177
5352795421417787499906983608906339812517482172279256237732605929109572394713402177089254576506 57420083612701406793822428971446301463914328058 84031180834866508612717625769625973530468844752
2185556756554608410231536775413741254444213336061172418631321880165988146933836785015938388301759 3470727929476705455157597649937342139407849956691 764084415787779623063286752073379332467496235325
811729331385660645282848122582331094655229405467416414939484763831917636692172886481343455847237648 27398485450811838621200493320064668428362315616000 67450765626654056121617844515017168584399944110961
07723630204542775060866653478190772757126764517044203428647580513151398644388436416844716290982555399 779747508871650421346674359120639937878860012833227 637012656979290715069309336159361582469190612360711
9554041567663663744167986748623762848614318046909157712308610955145631317438547106410910279561753667024 3295604763108105159046445567757628809697275914851818 5578179331948521603188967449947313917332804457329751
3490178830154173147262407583678162030531789356710821390345445740597845977320687884227246698474239445669433 65063006978300754698145147828429521232557914944057032 95456531642191752508205360406807805582337227341947509
```

`caeRSA2.py`:
```python
from Crypto.Util.number import *
from random import randint


flag = open("flag.txt", "rb").read()
caesar = lambda v, k: "".join([str((int(c)+k) % 10) for c in str(v)])
assert len(flag) == 52, len(flag)
for i in range(0, len(flag), 4):
	prime_size = i | 128
	p, q = getPrime(prime_size), getPrime(prime_size)
	assert p != q
	ct = pow(bytes_to_long(flag[i:i+4]), 65537, p*q)
	print(caesar(ct, randint(0, 9)), caesar(p, randint(0, 9)), caesar(q, randint(0, 9)))
```

## Writeup

### Understanding the Challenge
For this challenge the flag is split into chunks of 4 characters each.
Each chunk gets encrypted with a new RSA key.
After the encryption with RSA, the ciphertext, p and q are encrypted with caeser by a random value between 0 and 9.
These values are written to the `output.txt` file.

### Solving the Challenge
To solve this challenge I read the `output.txt` file line by line.
For each line I store the ciphertext (`ct`), `p` and `q` in a separate variable.

To revert the caesar encryption of p and q, I brute force all possibilities for a shift between 0 and 9.
If one of these shifts is a prime number I assume that this is the original value of `p` and `q`.

With the information about the original `p` and `q` I can easily calculate `n`.
More importantly, I am also able to calculate `φ(n)`.
As I know from the challenge file that `e = 65537` I can calculate `d` as

`d = e⁻¹ mod φ(n)`

The value of `d` will be different for each line of the `output.txt` file as `p` and `q` are different and therefore `φ(n)` is different.

Finally, I brute force the caesar shift between 0 and 9 again to decrypt the flag.
If the decrypted value can be converted to bytes I assume that this value is part of the flag.
By looping over each line of the `output.txt` file I concatenate the flag.

#### Solve Script
```python
from Crypto.Util.number import long_to_bytes
import sympy

caesar = lambda v, k: "".join([str((int(c)+k) % 10) for c in str(v)])

e = 65537

with open('output.txt', 'r') as output:
	for line in output:
		ct, p, q = line.split()
		
		real_p = 0

		for number in range(10):
			if (sympy.isprime(int(caesar(p, number)))):
				real_p = int(caesar(p, number))

		real_q = 0

		for number in range(10):
			if (sympy.isprime(int(caesar(q, number)))):
				real_q = int(caesar(q, number))

		n = real_p * real_q

		phi = (real_p - 1) * (real_q - 1)

		d = pow(e, -1, phi)

		real_ct = 0

		for number in range(10):
			middle = caesar(ct, number)

			message = pow(int(middle), d, n)
			try:
				data = long_to_bytes(message).decode("ascii")
				print(data, end="")
			except:
				print("", end="")
```

### flag
`ictf{rivest_shamir_adleman_is_evirfg_funzve_nqyrzna}`
