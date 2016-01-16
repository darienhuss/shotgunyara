import argparse
from hexdump import hexdump

def main():
	parser = argparse.ArgumentParser(description='Given a string, create 255 xor encoded versions of that string')
	parser.add_argument('-s','--string',help='String to be encoded',required=True)
	parser.add_argument('-u','--utf',help='If the string is unicode',required=False,action='store_true',default=False)
	parser.add_argument('-o','--output',help='Out filename/location',required=True)
	parser.add_argument('-pe','--pe',help='Is target a PE? Will add simple MZ magic check',required=False,default=True)

	args = parser.parse_args()
	string = args.string
	utf = args.utf
	filename = args.output
	pe = args.pe

	if utf:
		tmp = ''
		for c in string:
			tmp += '%s\x00' % c
		string = tmp.rstrip('\x00')

	rule = 'rule xor_string {\n\tstrings:\n'
	if pe:
		rule += '\t\t$MZ = "MZ"\n'
	for i in range(1,256):
		rule += '\t\t$s%i = { ' % i
		for c in string:
			rule += '%02X ' % (ord(c)^i)
		rule += '}\n'
	if pe:
		rule +='\tcondition:\n\t\t$MZ at 0 and any of them\n}'
	else:
		rule += '\tcondition:\n\t\tany of them\n}'

	with open(filename, 'wb') as f:
		f.write(rule)

if __name__ == '__main__':
  main()