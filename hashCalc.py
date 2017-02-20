##########################################################################
### Hash Calculator
### Description: Simple hash calculator based on standard Python libraries
### Author: Daniel Fernández Pérez
### Notes: 
###  - sys.exit(1) if finished without errors
###  - sys.exit(2) if finished with any error
##########################################################################

# Required imports:
## hashlib for hasing functions
## sys for accessing command line arguments and system functions
## getopt for parsing coomand line arguments

import hashlib, sys, getopt

# calc - Function to calculate the hash based on user input
# input: 
## hash, specifies the hashing method defined by user
## format, specifies the format of the input: string (s) or file (f)
## input, defines either the string or the file to calculate hash 
# output:
## hash calculation or error message
# notes:
## using encode('utf-8') when managing strings to avoid encoding errors
## using open(input, 'rb') to open file as binary and avoid format issues

def calc(hash,format,input):
	if hash == 'md5':
		if format in ("f", "file"):
			try:
				open(input)
			except (OSError, IOError) as e:
				print ('There has been an issue accessing the file.')
				sys.exit(2)
			return hashlib.md5(open(input, 'rb').read()).hexdigest()
		elif format in ("s","string"):
			return hashlib.md5(input.encode('utf-8')).hexdigest()
	elif hash == 'sha1':
		if format in ("f", "file"):
			try:
				open(input)
			except (OSError, IOError) as e:
				print ('There has been an issue accessing the file.')
				sys.exit(2)
			return hashlib.sha1(open(input, 'rb').read()).hexdigest()
		elif format in ("s","string"):
			return hashlib.sha1(input.encode('utf-8')).hexdigest()
	elif hash == 'sha384':
		if format in ("f", "file"):
			try:
				open(input)
			except (OSError, IOError) as e:
				print ('There has been an issue accessing the file.')
				sys.exit(2)
			return hashlib.sha384(open(input, 'rb').read()).hexdigest()
		elif format in ("s","string"):
			return hashlib.sha384(input.encode('utf-8')).hexdigest()
	elif hash == 'sha256':
		if format in ("f", "file"):
			try:
				open(input)
			except (OSError, IOError) as e:
				print ('There has been an issue accessing the file.')
				sys.exit(2)
			return hashlib.sha256(open(input, 'rb').read()).hexdigest()
		elif format in ("s","string"):
			return hashlib.sha256(input.encode('utf-8')).hexdigest()
	elif hash == 'sha512':
		if format in ("f", "file"):
			try:
				open(input)
			except (OSError, IOError) as e:
				print ('There has been an issue accessing the file.')
				sys.exit(2)
			return hashlib.sha512(open(input, 'rb').read()).hexdigest()
		elif format in ("s","string"):
			return hashlib.sha512(input.encode('utf-8')).hexdigest()
	elif hash == 'all':
		if format in ("f", "file"):
			try:
				open(input)
			except (OSError, IOError) as e:
				print ('There has been an issue accessing the file.')
				sys.exit(2)
			print ('MD5: ', hashlib.md5(open(input, 'rb').read()).hexdigest())
			print ('SHA1: ', hashlib.sha1(open(input, 'rb').read()).hexdigest())
			print ('SHA256: ', hashlib.sha256(open(input, 'rb').read()).hexdigest())
			print ('SHA384: ', hashlib.sha384(open(input, 'rb').read()).hexdigest())
			print ('SHA512: ', hashlib.sha512(open(input, 'rb').read()).hexdigest())
			return ''
		elif format in ("s","string"):
			print ('MD5: ', hashlib.md5(input.encode('utf-8')).hexdigest())
			print ('SHA1: ', hashlib.sha1(input.encode('utf-8')).hexdigest())
			print ('SHA256: ', hashlib.sha256(input.encode('utf-8')).hexdigest())
			print ('SHA384: ', hashlib.sha384(input.encode('utf-8')).hexdigest())
			print ('SHA512: ', hashlib.sha512(input.encode('utf-8')).hexdigest())
			return ''
	else:
		print ('Unsuported hash type.')
		sys.exit(2)

# displayHelp - Function to display usage help
# input:
## none
# output:
## usage help message on console
		
def displayHelp():
	print ('Usage: hashCalc.py -m <hashMethod> -f <inputFormat> -i <input>')
	print ('- Hash Methods available: md5, sha1, sha256, sha384 and sha512')
	print ('  Use "all" (without inverted commas) to calculate all hash methods')
	print ('- Input formats accepted: string (s) and file (f).')
	print ('  If format is file, use full path.')

# askForHash - Function to get hash value from user
# input:
## none
# output:
## input entered by the user in the console	

def askForHash():
	choice = ''
	
	print ('Do you want to compare with a previous hash value? (Y/N)')
	choice = input ('> ').lower()
	
	if choice in ("y","yes"):
		print ('Please enter hash value to compare.')
		return input ('> ')
	elif choice in ("n","no"):
		print ('No problem. Exiting...')
		sys.exit(1)
	else:
		print ('Answer not valid. Exiting...')
		sys.exit(2)

# compareHash - Function to compare 2 hash values
# input:
## oldHash especifies the hash calculated by the program
## newHash especifies the hash manually entered by the user
# ouput:
## result of comparison on console

def compareHash(oldHash,newHash):
	if oldHash == newHash:
		print ('Both hash values are equal')
	else:
		print ('Hash values do not match')
	
# main - Function to handle the main functionality of the program
# input:
## argv, list or arguments user passed to the program
# output:
## hash calculation, help information or error message
	
def main(argv):
	input = ''
	hashMethod = ''
	inputFormat = ''
	hashResult = ''
	
	try:
		opts, args = getopt.getopt(argv,"hm:f:i:",["mhash=","iformat=","input="])
	except getopt.GetoptError:
		displayHelp()
		sys.exit(2)
	if not argv:
		print('No arguments have been passed.')
		displayHelp()
		sys.exit(2)
	elif len(argv)<6:
		print('Invalid arguments passed.')
		displayHelp()
		sys.exit(2)
	else:
		for opt, arg in opts:
			if opt.lower() in ("-?","-h","-help"):
				displayHelp()
				sys.exit(1)
			elif opt.lower() in ("-m","--mhash"):
				hashMethod = arg.lower()
			elif opt.lower() in ("-f","--iformat"):
				inputFormat = arg.lower()
			elif opt.lower() in ("-i","--input"):
				input = arg.lower()
	
		hashResult = calc(hashMethod,inputFormat,input)
		print (hashResult)
		if hashMethod !='all':
			compareHash (hashResult, askForHash())
		sys.exit(1)

if __name__ == "__main__":
	# First argument is the name of the program, so it can be ignored
	main(sys.argv[1:])