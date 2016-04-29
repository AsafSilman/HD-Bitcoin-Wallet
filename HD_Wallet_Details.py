import Address_Util
import EC_Util
import hmac
import hashlib
import Addresses_Details
import os

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def HMAC_SHA512(key,data):
    return hmac.new(key,data,hashlib.sha512).hexdigest()

def hash160(s):
    s = s.decode('hex')
    first_hash = (hashlib.sha256(s).digest())
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(first_hash)
    return ripemd160.hexdigest()

def serialize_Wallet(key,chain,depth,fingerprint,Child_number,Private):
	chain = '%s%s' %('0'*(64-len(chain)),chain)

	if Private:
		key = '%s%s' %('0'*(64-len(key)),key)
		payload = depth + fingerprint + Child_number + chain + '00' + key
		return Address_Util.base58CheckEncode('0488ade4',payload)
	else:
		key = '%s%s' %('0'*(64-len(key)),key)
		payload = depth + fingerprint + Child_number + chain  + key
		return Address_Util.base58CheckEncode('0488b21e',payload)

def New_wallet():
	Data = os.urandom(256)
	Key = os.urandom(32)
	I =  HMAC_SHA512(Key,Data)
	Master_Secret = I[:64]
	Master_Chain_Code = I[64:]
	return serialize_Wallet(Master_Secret,Master_Chain_Code,'00','00000000','00000000',True)

def point_addition_for_public_key(Keyi,Key_par):
	(point_X,point_Y) = EC_Util.EccMultiply(int(Keyi,16))

	self_key_point = Address_Util.compressed_key_to_full(Key_par)
	(self_x, self_y) = (int(self_key_point[2:66],16),int(self_key_point[66:],16))

	(Final_x,Final_y) = EC_Util.ECadd(point_X,point_Y,self_x,self_y)
	Key_raw = '04%x%x' % (Final_x,Final_y)

	return Address_Util.public_key_to_compressed(Key_raw)

def addition_for_private_key(keyi,key_par):
	return "%x" % ((int(keyi,16) + int(key_par,16)) % N)


class HD_wallet_details:
	"""
	Accepts Public-extended keys or Private-extended keys
	"""
	
	account = 0

	def __init__(self,HD_address):
		converted_address = Address_Util.base58Decode(HD_address).decode('hex')
		
		self.address = HD_address
		self.version = converted_address[:4].encode('hex')
		
		if self.version == '0488ade4' or self.version == '0488ADE4':
			self.private = True
		else:
			self.private = False
		
		self.depth = converted_address[4].encode('hex')
		self.fingerprint = converted_address[5:9].encode('hex')
				
		self.child_number = converted_address[9:13].encode('hex')
		
		if self.fingerprint == '00000000' and self.depth == '00' and self.child_number == '00000000':
			self.master = True
		else:
			self.master = False

		if int(self.child_number,16) >=2**31:
			self.hardened = True
		else:
			self.hardened = False

		self.chain_code = converted_address[13:45].encode('hex')
		
		if self.private:
			self.key = converted_address[46:78].encode('hex')
		else:
			self.key = converted_address[45:78].encode('hex')
		
		self.check = converted_address[78:].encode('hex')

	def next_account(self):
		(key,chain,depth,fingerprint,Child_number,Private) =  self.CKDpriv(self.account)
		self.account += 1
		return serialize_Wallet(key,chain,depth,fingerprint,Child_number,Private)		

	def CKDpriv(self,number):
		hex_digit = "%x" % number
		serialized = "%s%s" % ('0'*(8-len(hex_digit)),hex_digit)

		Depth_raw = "%x" % (int(self.depth,16)+1)
		Depth = "%s%x" % ('0'*(2-len(Depth_raw)),(int(self.depth,16)+1))

		if self.private and number >= 2**31:
		
			data = ('00' + self.key + serialized).decode('hex')

			I = HMAC_SHA512(self.chain_code.decode('hex'),data)

			Key = addition_for_private_key(I[:64],self.key)
			Chain = I[64:]
			
			fingerprint = hash160(Address_Util.private_key_to_compressed(self.key))[:8]
			
			return (Key,Chain,Depth,fingerprint,serialized,self.private)
		
		elif self.private:
			
			data = (Address_Util.private_key_to_compressed(self.key) + serialized).decode('hex')
			
			I = HMAC_SHA512(self.chain_code.decode('hex'),data)

			Key = addition_for_private_key(I[:64],self.key)
			Chain = I[64:]
			
			fingerprint = hash160(Address_Util.private_key_to_compressed(self.key))[:8]
			
			return (Key,Chain,Depth,fingerprint,serialized,self.private)
		else:
			return self.CKDpub(number)

	def CKDpub(self,number):
		if self.private or number>=2**31:
			raise Exception("Can't be computed")
		else:
			hex_digit = "%x" % number
			serialized = "%s%s" % ('0'*(8-len(hex_digit)),hex_digit)
			data = (self.key + serialized).decode('hex')

			I = HMAC_SHA512(self.chain_code.decode('hex'),data)

			Key =  point_addition_for_public_key(I[:64],self.key)
			Chain = I[64:]
			
			Depth_raw = "%x" % (int(self.depth,16)+1)
			Depth = "%s%x" % ('0'*(2-len(Depth_raw)),(int(self.depth,16)+1))
			
			fingerprint = hash160(self.key)[:8]

			return (Key,Chain,Depth,fingerprint,serialized,self.private)

	def sserialize(self):
		#s for self serlialize
		payload = self.depth + self.fingerprint + self.child_number + self.chain_code
		if self.private:
			payload += '00' + self.key
			return Address_Util.base58CheckEncode('0488ade4',payload)
		else:
			payload += self.key
			return Address_Util.base58CheckEncode('0488b21e',payload)

	def private_to_public_extended_key(self):
		if self.private:
			Key = Address_Util.private_key_to_compressed(self.key)
			return serialize_Wallet(Key,self.chain_code,self.depth,self.fingerprint,self.child_number,False)
		else:
			return self.sserialize()

	def dump(self):
		print "Serialized Key        : %s" % self.sserialize()
		if self.private:
			print "Serialized Public Key : %s" % self.private_to_public_extended_key()
		print "Private Key           : %s" % self.private
		print
		print "Depth                 : %s" % self.depth
		print "Fingerprint           : %s" % self.fingerprint
		print "Child Number          : %s" % self.child_number
		print "Is Hardened           : %s" % self.hardened
		print "Is Master             : %s" % self.master
		print
		print "Chain Code            : %s" % self.chain_code
		print "Key                   : %s" % self.key
		print "Check                 : %s" % Address_Util.checkaddress(self.address)
	def dump_string(self):
		if self.private:
			string =  "Serialized Key : %s\n" % self.sserialize()
			string += "Public Key     : %s\n" % self.private_to_public_extended_key()
			string += "Private Key    : %s\n\n" % self.private
			
			string += "Depth          : %s\n" % self.depth
			string += "Fingerprint    : %s\n" % self.fingerprint
			string += "Child Number   : %s\n" % self.child_number
			string += "Is Hardened    : %s\n" % self.hardened
			string += "Is Master      : %s\n\n" % self.master
			
			string += "Chain Code     : %s\n" % self.chain_code
			string += "Key            : %s\n\n" % self.key
			
			public_key = Address_Util.private_key_to_compressed(self.key)
			
			string += "Compressed Address : %s\n" % Address_Util.public_key_to_address(public_key)
		else:
			string =  "Serialized Key     : %s\n" % self.sserialize()
			string += "Private Key        : %s\n\n" % self.private

			string += "Depth              : %s\n" % self.depth
			string += "Fingerprint        : %s\n" % self.fingerprint
			string += "Child Number       : %s\n" % self.child_number
			string += "Is Hardened        : %s\n" % self.hardened
			string += "Is Master          : %s\n\n" % self.master

			string += "Chain Code         : %s\n" % self.chain_code
			string += "Key                : %s\n\n" % self.key
			string += "Compressed Address : %s" % Address_Util.public_key_to_address(self.key)



		return string

#Beta Testing
#xprv9s21ZrQH143K2JF8RafpqtKiTbsbaxEeUaMnNHsm5o6wCW3z8ySyH4UxFVSfZ8n7ESu7fgir8imbZKLYVBxFPND1pniTZ81vKfd45EHKX73
"""
wallet = HD_wallet_details('xpub661MyMwAqRbcEnKbXcCqD2GT1di5zQxVqoHPAgHNe8dv5JP8gWmDproS6kFHJnLZd23tWevhdn4urGJ6b264DfTGKr8zjmYDjyDTi9U7iyT')

wallet.dump()

print wallet.CKDpriv(2)

"""

"""
#Individual Addresses
wallet = HD_wallet_details('xpub695dFcmaKwVoJyWdu181V6fLMbCQqcqJbbyW2y4W9UmeNJrRD4fZ2wS6nn1FJsxGYTj31QKq5TuzFr4ApTW6sBx536pohM15s5sFXKEWrHY')

for i in range(50):
	temp =  wallet.next_account()
	temp1 = HD_wallet_details(temp)
	address = Addresses_Details.Public_key(temp1.key)
	print address.show_compressed_bitcoin_address()

"""

"""
#Whole HD address details
#wallet = HD_wallet_details(New_wallet())
wallet = HD_wallet_details('xprv9s21ZrQH143K2JF8RafpqtKiTbsbaxEeUaMnNHsm5o6wCW3z8ySyH4UxFVSfZ8n7ESu7fgir8imbZKLYVBxFPND1pniTZ81vKfd45EHKX73')

print "This program will generate a random extended private key and display all relative information."
print "in addition you can derive a hardened/non-hardened child private-extended-key by typing a number below."
print "Needs Further Testing"
print
print "----------------------------------------------------------HD Wallet--------------------------------------------------------------------------"
wallet.dump()


print
print
hardened = False

Cnumber = int(raw_input("Enter Child Number: "))
if hardened:
	Cnumber +=2**31

(key,chain,depth,fingerprint,Child_number,Private) = wallet.CKDpriv(Cnumber)

derived = HD_wallet_details(serialize_Wallet(key,chain,depth,fingerprint,Child_number,Private))

if Private:
	address = Addresses_Details.Private_key(derived.key)
else:
	address = Addresses_Details.Public_key(derived.key)


if hardened:
	print "----------------------------------------------Derived Hardened HD Wallet Path (%s)----------------------------------------------------------" % (int(derived.child_number,16)-2**31)
	derived.dump()
else:
	print "---------------------------------------------------Derived HD Wallet Path (%s)--------------------------------------------------------------" % (int(derived.child_number,16))
	derived.dump()


print "--------------------------------------------------------Derived Address----------------------------------------------------------------------"
address.dump()


os.system('pause')
"""
