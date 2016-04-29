import hashlib
import EC_Util

#Basic Address Funcions
def hash160(data):
	#Takes hex input
	#Return hash160 of input as hex
	ripemd160 = hashlib.new('ripemd160')
	data = data.decode('hex')
	first_hash = (hashlib.sha256(data).digest())

	ripemd160.update(first_hash)
	return ripemd160.hexdigest()

def base58Encode(string):
	#Accepts only hex
	#Ouputs base58 equivilent
	Base58_Chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
	leading_zeros = 0
	output = ''
	#Converting Input
	converted_integer = int(string,16)

	#Counting zero's for bitcoin address
	for i in range(0,len(string),2):
		if string[i:i+2] == '00':
			leading_zeros += 1
			continue
		break
	#Encodes hex
	while converted_integer > 0:
		output += Base58_Chars[converted_integer%58]
		converted_integer /= 58
	#String reversed according to specification
	return '1'*leading_zeros + output[::-1]

def base58Decode(string):
	#Accepts base58 input
	#Ouputs hex equivilent for bitcoin, output is padded
	Base58_Chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
	output = 0
	
	final = ''
	#Adds zeros for each leading 1's
	for i in range(len(string)):
		char = string[i]
		if char == '1':
			final += '00'
			continue
		break
		
	string = string[::-1] #String reversed according to specifications

	for i in range(len(string)):
		char   = string[i]
		value  = Base58_Chars.find(char)
		output += value*(58**i)
	
	final += '%x' % output
	return '0'*(len(final)%2) + final #Length Padded

def base58CheckEncode(version,string):
	"""
	Accepts version argument as string or number (base 16)
	Accepts hex string only, string generally should the keyhash without version byte
	Returns Bitcoin Address
	"""
	try:
		#Test if hex number, pads number
		unpadded = '%x' % version
		padded = '%s%s' % ('0'*(len(unpadded)%2),unpadded)
	except TypeError:
		#Test if string, pads number
		padded = '%s%s' % ('0'*(len(version)%2),version)
	
	payload = (padded + string).decode('hex')
	checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[0:4]
	result = (payload + checksum).encode('hex')
	return base58Encode(result)
	
def checkaddress(address):
	#Accepts base58Checkencoded address
	#Return Boolean
	key_hash = base58Decode(address).decode('hex')
	checksum1 = key_hash[len(key_hash)-4:] #Presented Checksum
	checksum2 = hashlib.sha256(hashlib.sha256(key_hash[:len(key_hash)-4]).digest()).digest()[0:4] #Calculated Checksum
	return checksum1==checksum2 

#EC Functions
#All of these functions use bitcion specified public and private keys
#Public keys are given as serialized keys

def public_key_to_compressed(xraw):
    #Takes hex input of full public key (or compressed, so it wont crash)
    #Returns compressed public key in hex
    if xraw[:2]=='04':
        if int(xraw[66:],16) % 2 == 0:
            xcomp = '02%s' % xraw[2:66]
        else:
            xcomp = '03%s' % xraw[2:66]
    else:
        xcomp = xraw
    return xcomp

def compressed_key_to_full(public_key):
	#Accepts hex input of compressed public key
    #Returns full public key
	(xpoint,ypoint) = EC_Util.Compressed_to_full_point(public_key[2:],public_key[:2]) #Padds points in function
	return '04%s%s' % (xpoint, ypoint)

def private_key_to_public(privatekey):
    #Accepts hex input
    #Returns full Public Key

    #Calculating x,y coordinates on graph
    privatekey = int((privatekey),16)
    xcoord, ycoord = EC_Util.EccMultiply(privatekey)
    #Converting to Hex
    x_point,y_point = ('%x' % xcoord,'%x' % ycoord)
    #Padding with leading zeros
    x_point = '%s%s' % ('0'*(64-len(x_point)),x_point)
    y_point = '%s%s' % ('0'*(64-len(y_point)),y_point)

    return '04'+x_point+y_point

def private_key_to_compressed(privatekey):
	#Takes hex input of private key (NOT WIF)
	#Returns compressed public key in hex
	full_key = private_key_to_public(privatekey)
	return public_key_to_compressed(full_key)

#Address Functions
def public_key_to_address(key):
	#Takes hex input (compressed or uncompressed). This function has no check builtin so only pass valid keys
	#Returns bitcoin address
	return base58CheckEncode(0,hash160(key))

def private_key_to_WIF(private_key):
	#Takes private key as hex input
	#Returns WIF base58CheckEncoded
	return base58CheckEncode(0x80,private_key)

def private_key_to_compressed_WIF(private_key):
	#Takes private key as hex input
	#Returns compressed WIF base58CheckEncoded
	payload = private_key + '01'
	return base58CheckEncode(0x80,payload)

def WIF_to_private_key(wif):
	#Takes WIF, Compressed or Uncompressed
	#Returns hex private key
	return base58Decode(wif)[2:66]

if __name__ == "__main__":
    print WIF_to_private_key('5JvNwFKSiA2P3HDfyg4772KdtqQWb2vjDGWBoU4TsMJLes41V62')
    print private_key_to_public('91878a573a82c6d71c5c261daacdafa8bec65f7af133504dbcff22e5ecb4115d')
    print public_key_to_address('041c4020b8495552fe5b057523f30ef76a6f70759155ec3f96e97ba04ac2cf4996fe5b42bc07f68961b3d2d0075245daaa48b6b990508e8bbd741ea6c10fe75a72')

	#Address Functions
	assert base58Encode('00005d1a239d4ec666643d350c7bb8fc44d2881128f82b4da6') == '112vXrAkfzxJV4APHHP6XiBAZbD71et1py'
	assert base58Decode('112vXrAkfzxJV4APHHP6XiBAZbD71et1py') == '00005d1a239d4ec666643d350c7bb8fc44d2881128f82b4da6'
	assert base58CheckEncode(0x00,'005D1A239D4EC666643D350C7BB8FC44D2881128') == '112vXrAkfzxJV4APHHP6XiBAZbD71et1py'
	assert checkaddress('112vXrAkfzxJV4APHHP6XiBAZbD71et1py')

	#Private Keys
	assert private_key_to_WIF('0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d') == '5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ'
	assert WIF_to_private_key('5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ') == '0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d'
	assert private_key_to_compressed('0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d') == '02d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645c'

	#Public Keys
	assert public_key_to_address('04d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645cd85228a6fb29940e858e7e55842ae2bd115d1ed7cc0e82d934e929c97648cb0a') == '1GAehh7TsJAHuUAeKZcXf5CnwuGuGgyX2S'
	assert public_key_to_address('02d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645c') == '1LoVGDgRs9hTfTNJNuXKSpywcbdvwRXpmK'
	assert compressed_key_to_full('02d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645c') == '04d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645cd85228a6fb29940e858e7e55842ae2bd115d1ed7cc0e82d934e929c97648cb0a'
