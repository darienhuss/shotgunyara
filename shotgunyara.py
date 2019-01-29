import os
import sys
import base64
import difflib
import argparse


def encode(string_to_encode,alphabet):
	return base64.b64encode(string_to_encode)

def longest(a, b):
	match = difflib.SequenceMatcher(None, a, b)
	m = match.find_longest_match(0, len(a), 0, len(b))
	return a[m.a:m.a+m.size]

def generate_b64(rule,in_string,counter):
	alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
	rule += '\t\t//original string: %s\n' % in_string
	for t in [3, 4, 5]:
		init_string1 = encode(os.urandom(t) + in_string + os.urandom(6),alphabet) #initialize first string
		for i in range(100):
			init_string2 = encode(os.urandom(t) + in_string + os.urandom(6),alphabet)
			init_string1 = longest(init_string1, init_string2)
		rule += '\t\t$s%i = "%s" ascii wide\n' % (counter,init_string1)
		counter+=1
	return rule, counter


def generate_xor(rule,in_string):
	rule += '\t\t//original string: %s\n' % in_string
	for i in range(1,256):
		rule += '\t\t$s%i = { ' % i
		for c in in_string:
			rule += '%02X ' % (ord(c)^i)
		rule += '}\n'
	return rule

def main():
	parser = argparse.ArgumentParser(description='Given a string, create 255 xor encoded versions of that string')
	parser.add_argument('-s','--string',help='Single string to be encoded, provided via command line',required=False)
	parser.add_argument('-f','--file',help='File containing list of strings separated by new line. This option only supported with base64',required=False)
	parser.add_argument('-u','--utf',help='If the string is unicode',required=False,action='store_true',default=False)
	parser.add_argument('-o','--output',help='Out filename/location, default: "shotgun.yar"',required=False)
	parser.add_argument('-p','--printonly',help='Just print the output instead of writing to file',action="store_true",required=False)
	parser.add_argument('-pe','--pe',help='Is target a PE? Will add simple MZ magic check',required=False)
	parser.add_argument('-x','--xor',help='Create 255 xor encoded versions of a string. NOTE: You should instead use "xor" modified in YARA 3.8.0',required=False,action='store_true')
	parser.add_argument('-b','--b64',help='Create three variations of a base64 string based on three padding possibilities',required=False,action='store_true')
	parser.add_argument('-n','--name',help='Signature name, default: "shotgun_rule"',required=False)
	parser.add_argument('-i','--include',help='Include the original string in the rule as well',action='store_true',required=False)


	args = parser.parse_args()
	in_string = args.string
	in_filename = args.file
	utf = args.utf
	out_filename = args.output
	pe = args.pe
	xor = args.xor
	b64 = args.b64
	name = args.name
	include = args.include
	printonly = args.printonly

	if not in_string and not in_filename:
		print('Need to specify either --string or --file option, exiting')
		sys.exit()

	if (not b64 and not xor) or (b64 and xor):
		print('Need to specify either --b64 or --xor option and not both, exiting')
		sys.exit()

	if in_filename and not b64:
		print('File option only works with base64 / --b64 option, exiting')
		sys.exit()

	#if no name provided, set to default shotgun_rule
	if not name:
		name = 'shotgun_rule'

	if not out_filename and not printonly:
		out_filename = 'shotgun.yar'

	in_string_list = []
	if in_filename:
		with open(in_filename, 'rb') as f:
			in_string_list = f.read().splitlines()


	if in_string and utf:
		tmp = ''
		for c in in_string:
			tmp += '%s\x00' % c
		in_string = tmp.rstrip('\x00')

	rule = 'rule %s {\n\tstrings:\n' % name
	if pe:
		rule += '\t\t$stub = "This program cannot be run in DOS mode"\n\n'

	#if xor option is set, do xor
	if xor:
		rule = generate_xor(rule,in_string)

	elif b64:
		#if there is just one string
		counter = 1
		if in_string:
			if include:
				rule += '\t\t$s%i = "%s" ascii wide //original string\n\n' % (counter,in_string)
				counter+=1
			rule, counter = generate_b64(rule,in_string,counter)
		elif in_string_list:
			for in_string in in_string_list:
				rule, counter = generate_b64(rule,in_string,counter)
				rule+='\n'
			#strip the trailing newline
			rule = rule[:-1]

	if pe:
		rule += '\tcondition:\n\t\t(uint16(0) == 0x5A4D or $stub) and any of ($s*)\n}'
	else:
		rule += '\tcondition:\n\t\tany of them\n}'

	if printonly:
		print(rule)
	elif out_filename:
		with open(out_filename, 'wb') as f:
			f.write(rule)

if __name__ == '__main__':
  main()