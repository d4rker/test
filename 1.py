from pycoin.ui.key_from_text import key_from_text
from pycoin.satoshi.der import sigdecode_der
from binascii import unhexlify

def d():
	hwif = 'xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j'
	to_sign = unhexlify('4554813e91f3d5be790c7c608f80b2b00f3ea77512d49039e9e3dc45f89e2f01')
	priv_key = key_from_text(hwif)
	sig = priv_key.sign(to_sign)
	r, s = sigdecode_der(sig)
	print(r)
	print(s)

d()
