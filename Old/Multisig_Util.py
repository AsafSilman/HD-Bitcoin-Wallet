import EC_Util
import Address_Util
import os

class Multisig:
	#Class for multisig address
	#Needs to accept private key (64) or compressed public(66) or full public (130) hex
	def __init__(self,number_of_signatures,number_of_keys,list_of_keys=[]):
		#Testing if correct paramaters for address
		if number_of_signatures > number_of_keys:
			raise TypeError('Number of Signatures greater than number of keys')
		assert number_of_keys <= 15
		self.signatures = number_of_signatures
		self.keys = number_of_keys

		#If no list provided, will generate own address
		if list_of_keys == []:
			self.private = True
			self.key_list = sorted(self.create_list_of_private_keys(self.keys))
			self.redem_script = self.Create_multisig_redeem_script(self.key_list,self.signatures)
			self.key_hash = Address_Util.hash160(self.redem_script)
			self.address = Address_Util.base58CheckEncode(0x05,self.key_hash)
		
		#If private key
		elif len(list_of_keys[0]) == 64:
			#checing each key for validity
			assert len(list_of_keys) == number_of_keys
			for i in list_of_keys:
				try:
					assert len(i) == 64
				except:
					raise
			#Comiting data to object
			else:
				self.private = True
				self.key_list = sorted(list_of_keys)
				self.redem_script = self.Create_multisig_redeem_script(self.key_list,self.signatures)
				self.key_hash = Address_Util.hash160(self.redem_script)
				self.address = Address_Util.base58CheckEncode(0x05,self.key_hash)
			
		#If public key
		elif len(list_of_keys[0]) == 66 or len(list_of_keys[0]) == 130:
			#Checking Validity
			assert len(list_of_keys) == number_of_keys
			for i in list_of_keys:
				try:
					assert len(i) == 66 or len(i) == 130
				except:
					raise
			else:
				self.private = False
				self.key_list = sorted(list_of_keys)
				self.redem_script = self.Create_multisig_redeem_script(self.key_list,self.signatures)
				#asserting redem script length
				try:
					assert len(self.redem_script.decode('hex')) <= 520
				except AssertionError:
					raise TypeError("Redem script length exceded 520 bytes, invalid address")
				self.key_hash = Address_Util.hash160(self.redem_script)
				self.address = Address_Util.base58CheckEncode(0x05,self.key_hash)
		else:
			raise Exception('Unknown error')
	def create_list_of_private_keys(self,n):
	    list_of_keys = []
	    for i in range(n):
	        list_of_keys.append(os.urandom(32).encode('hex'))
	    return list_of_keys

	def Create_multisig_redeem_script(self,list_of_keys, Signatures_required):
	    #addresses sorted private or public
	    #this code is messy
	    try:
			#Private key code
			assert self.private
			return_output = "%s" % chr(80+Signatures_required)
			public_list = []
			for i in list_of_keys:
				public_list.append(Address_Util.private_key_to_compressed(i).decode('hex'))
			for i in sorted(public_list):
				return_output += '%s%s' % (chr(len(i)),i)
			return_output += '%s%s' %(chr(80+len(list_of_keys)),'ae'.decode('hex'))
			return return_output.encode('hex')
	    
	    except AssertionError:
	    	#Public key code
			return_output = "%s" % chr(80+Signatures_required)
			public_list = []
			for i in list_of_keys:
				public_list.append(i.decode('hex'))
			for i in sorted(public_list):
				return_output += '%s%s' % (chr(len(i)),i)
			return_output += '%s%s' %(chr(80+len(list_of_keys)),'ae'.decode('hex'))
			return return_output.encode('hex')
	    
	def dump(self):
		print "Number of Keys        : %s" % self.keys
		print "Number of Signatures  : %s" % self.signatures
		print "Private keys          : %s" % self.private
		print 
 		print "Key List (sorted)     : %s" % self.key_list
		print 
		print "Redem Script (sorted) : %s" % self.redem_script
		print "Key Hash              : %s" % self.key_hash
		print
		print "Bitcoin Address       : %s" % self.address

if __name__ == '__main__':
	Multisig(2,3,['a49588f894c2bd25b16d291ed82ba52462137abffc8a7bd60914693788607c39', 'aaedf0c56143c1d6b2743457a910530fc33ef1b5a461326b33769f4ce8805569', '8eb25cc86eccbe6db161773d4824b3b41dda2daa1b36d127642697a82cf501eb']).dump()
	print '\n'
	Multisig(2,4,['04d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645cd85328a6fb29940e858e7e55842ae2bd115d1ed7cc0e82d934e929c97648cb0a','04d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645cd85228a6fb29940e858e7e55842ae2bd115d1ed7cc0e82d934e929c97648cb0a','03aeb681df5ac19e449a872b9e9347f1db5a0394d2ec5caf2a9c143f86e232b0d9','02d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645c']).dump()

	os.system('pause')
