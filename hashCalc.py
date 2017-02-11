import hashlib, sys, getopt

def calc(hash,format,input):
	if hash == 'md5':
		if format in ("f", "file"):
			return hashlib.md5(open(input, 'rb').read()).hexdigest()
		elif format in ("s","string"):
			return hashlib.md5(input.encode('utf-8')).hexdigest()
	elif hash == 'sha1':
		if format in ("f", "file"):
			return hashlib.sha1(open(input, 'rb').read()).hexdigest()
		elif format in ("s","string"):
			return hashlib.sha1(input.encode('utf-8')).hexdigest()
	elif hash == 'sha384':
		if format in ("f", "file"):
			return hashlib.sha384(open(input, 'rb').read()).hexdigest()
		elif format in ("s","string"):
			return hashlib.sha384(input.encode('utf-8')).hexdigest()
	elif hash == 'sha256':
		if format in ("f", "file"):
			return hashlib.sha256(open(input, 'rb').read()).hexdigest()
		elif format in ("s","string"):
			return hashlib.sha256(input.encode('utf-8')).hexdigest()
	elif hash == 'sha512':
		if format in ("f", "file"):
			return hashlib.sha512(open(input, 'rb').read()).hexdigest()
		elif format in ("s","string"):
			return hashlib.sha512(input.encode('utf-8')).hexdigest()
	else:
		print ('Unsuported hash type.')
		sys.exit(2)

			
def displayHelp():
	print ('usage: hashCalc.py -c <hashMethod> -f <inputFormat> -i <input>')
	print ('- Hash Methods available: md5, sha1, sha384, sha256 and sha512')
	print ('- Input formats accepted: string (s) and file (f).')
	print ('  If format is file, use full path.')

def main(argv):
	input = ''
	hashMethod = ''
	inputFormat = ''
	try:
		opts, args = getopt.getopt(argv,"hc:f:i:",["chash=","iformat=","input="])
	except getopt.GetoptError:
		displayHelp
		sys.exit(2)
	if not argv:
		print('No arguments have been passed.')
		sys.exit(2)
	else:
		for opt, arg in opts:
			if opt in ("-?","-h","-help"):
				displayHelp
				sys.exit(1)
			elif opt in ("-c","--chash"):
				hashMethod = arg.lower()
			elif opt in ("-f","--iformat"):
				inputFormat = arg.lower()
			elif opt in ("-i","--input"):
				input = arg.lower()
	
		print (calc(hashMethod,inputFormat,input))
		sys.exit(1)

if __name__ == "__main__":
	main(sys.argv[1:])