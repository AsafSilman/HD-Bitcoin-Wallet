import os
import Address_Util

def Checkaddress(address):
	return Address_Util.checkaddress(address)

class Private_key:

	def __init__(self,key):
		if len(key)==64:
			self.private_key = key
			self.generated = False
		elif (len(key)==51 or len(key) == 52) and Address_Util.checkaddress(key):
			self.private_key =  Address_Util.b58decode(key)[1:33]
			self.generated = False
		else:
			raise Exception("Invalid Private Key")

	def show_private_key(self):
		return self.private_key

	def show_compressed_public_key(self):
		public_key = self.show_public_key()
		return Address_Util.public_key_to_compressed(public_key)

	def show_public_key(self):
		return Address_Util.private_key_to_public(self.private_key)

	def show_WIF(self):
		return Address_Util.base58CheckEncode(128,self.private_key)

	def show_compressed_WIf(self):
		modified_key = (self.private_key+'01')
		return Address_Util.base58CheckEncode(128,(modified_key))

	def show_bitcoin_address(self):
		key = self.show_public_key()
		return Address_Util.public_key_to_address(key)

	def show_compressed_bitcoin_address(self):
		key = self.show_compressed_public_key()
		return Address_Util.public_key_to_address(key)

	def dump(self):
		print "Private Key (HEX)            : %s" % self.show_private_key()
		print
		print "Uncompressed WIF             : %s" % self.show_WIF()
		print "Compressed WIF               : %s" % self.show_compressed_WIf()
		print
		print "Uncompressed Public Key      : %s" % self.show_public_key()
		print "Compressed Public Key        : %s" % self.show_compressed_public_key()
		print
		print "Uncompressed Bitcoin Address : %s" % self.show_bitcoin_address()
		print "Compressed Bitcoin Address   : %s" % self.show_compressed_bitcoin_address()
		print "Valid Addresses (both)       : %s" % ( Checkaddress(self.show_bitcoin_address()) and Checkaddress(self.show_compressed_bitcoin_address()) )

	def dump_string(self):
		string =  "Private Key (HEX)            : %s\n\n" % self.show_private_key()
		
		string += "Uncompressed WIF             : %s\n" % self.show_WIF()
		string += "Compressed WIF               : %s\n\n" % self.show_compressed_WIf()
		
		string += "Uncompressed Public Key      : %s\n" % self.show_public_key()
		string += "Compressed Public Key        : %s\n\n" % self.show_compressed_public_key()
		
		string += "Uncompressed Bitcoin Address : %s\n" % self.show_bitcoin_address()
		string += "Compressed Bitcoin Address   : %s\n" % self.show_compressed_bitcoin_address()
		string += "Valid Addresses (both)       : %s" % ( Checkaddress(self.show_bitcoin_address()) and Checkaddress(self.show_compressed_bitcoin_address()) )
		return string

class Public_key:
	#0405c8897fd0ff5644adba4545a84020cd6aa94d90e1e0a56bb4b8eb7522e3ef8c3ce6a1770325699f0672016985db4a592dcc8e2827928a480838514b8d50fc7a
	#0205c8897fd0ff5644adba4545a84020cd6aa94d90e1e0a56bb4b8eb7522e3ef8c
	def __init__(self,key):
		self.key = key
		if len(self.key) == 130:
			self.compressed = False
		elif len(self.key) == 66:
			self.compressed = True

	def show_compressed_public_key(self):
		if  not self.compressed:
			return Address_Util.public_key_to_compressed(self.key)
		else:
			return self.key

	def show_public_key(self):
		if self.compressed:
			return Address_Util.compressed_key_to_full(self.key)
		else:
			return self.key

	def show_compressed_bitcoin_address(self):
		key = self.show_compressed_public_key()
		return Address_Util.public_key_to_address(key)

	def show_bitcoin_address(self):
		key = self.show_public_key()
		return Address_Util.public_key_to_address(key)

	def dump(self):
		print "Uncompressed Public Key      : %s" % self.show_public_key()
		print "Compressed Public Key        : %s" % self.show_compressed_public_key()
		print
		print "Uncompressed Bitcoin Address : %s" % self.show_bitcoin_address()
		print "Compressed Bitcoin Address   : %s" % self.show_compressed_bitcoin_address()
		print "Valid Addresses (both)       : %s" % (Checkaddress(self.show_bitcoin_address()) and Checkaddress(self.show_compressed_bitcoin_address()) )
	def dump_string(self):
		string =  "Uncompressed Public Key      : %s\n" % self.show_public_key()
		string += "Compressed Public Key        : %s\n\n" % self.show_compressed_public_key()
		
		string += "Uncompressed Bitcoin Address : %s\n" % self.show_bitcoin_address()
		string += "Compressed Bitcoin Address   : %s\n" % self.show_compressed_bitcoin_address()
		string += "Valid Addresses (both)       : %s\n" % (Checkaddress(self.show_bitcoin_address()) and Checkaddress(self.show_compressed_bitcoin_address()) )
		return string


y = Public_key('0439a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c23cbe7ded0e7ce6a594896b8f62888fdbc5c8821305e2ea42bf01e37300116281')
x = Private_key('e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35')

assert y.show_compressed_public_key() == '0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2'
assert y.show_compressed_bitcoin_address() == '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma'

assert x.show_compressed_public_key() == '0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2'
assert y.show_compressed_bitcoin_address() == '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma'