##########################################################################
### Hash Calculator
### Description: Simple hash calculator based on standard Python libraries
### Author: Daniel Fernández Pérez
##########################################################################

# Required imports:
## hashlib for hasing functions
## sys for accessing command line arguments and system functions
## getopt for parsing coomand line arguments

import hashlib, sys, getopt

# calc - Function to calculate the hash based on user input
# input: 
## hash specifies the hashing method defined by user
## format specifies the format of the input: string (s) or file (f)
## input defines either the string or the file to calculate hash 
# output:
## hash calculation or error message

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
	else:
		print ('Unsuported hash type.')
		sys.exit(2)

# displayHelp - Function to display usage help
# input:
## none
# output:
## usage help massage on console
		
def displayHelp():
	print ('usage: hashCalc.py -m <hashMethod> -f <inputFormat> -i <input>')
	print ('- Hash Methods available: md5, sha1, sha384, sha256 and sha512')
	print ('- Input formats accepted: string (s) and file (f).')
	print ('  If format is file, use full path.')

# main - Function to handle the main functionality of the program
# input:
## argv list or arguments used passed to the program
# output:
## Hash calculation, help information or error message
	
def main(argv):
	input = ''
	hashMethod = ''
	inputFormat = ''
	try:
		opts, args = getopt.getopt(argv,"hm:f:i:",["mhash=","iformat=","input="])
	except getopt.GetoptError:
		displayHelp()
		sys.exit(2)
	if not argv:
		print('No arguments have been passed.')
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
	
		print (calc(hashMethod,inputFormat,input))
		sys.exit(1)

if __name__ == "__main__":
	# First argument is the name of the program, so it can be ignored
	main(sys.argv[1:])