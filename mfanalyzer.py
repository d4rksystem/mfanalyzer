#!/usr/bin/env python2.7

#################################################
## mfanalyzer: A tool for quick and dirty analysis of suspicious files.
## Designed to be run in Remnux, but should work on any Ubuntu or Debian system with Python and required tools installed.
## Many thanks to the authors of the many tools used in this script!
##################################################
## Author: Kyle Cucci (@d4rksystem)
## Version: 2.2 (24 Jan 2022)
##################################################

# ----- Imports -----

import argparse
import os
import time

# Helper modules
import config
import tools
import subprocess
import auxiliary

# ----- Main -----

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='A tool for running various other analysis tools on a file to determine potential malicious indicators...')
    parser.add_argument('infile', action='store', help='File to assess.', nargs="*")
    filetypeGroup = parser.add_mutually_exclusive_group()
    filetypeGroup.add_argument('--pe', default='', action='store_true', help='Run PE/EXE analysis tools.')
    filetypeGroup.add_argument('--bin', default='', action='store_true', help='Run raw binary file / shellcode analysis tools.')
    filetypeGroup.add_argument('--doc', default='', action='store_true', help='Run MS document analysis tools.')
    filetypeGroup.add_argument('--pdf', default='', action='store_true', help='Run PDF file analysis tools.')
    filetypeGroup.add_argument('--rtf', default='', action='store_true', help='Run RTF file analysis tools.')
    filetypeGroup.add_argument('--zip', default='', action='store_true', help='Run ZIP file analysis tools.')
    parser.add_argument('-s', '--strings', action='store_true', default='', help='Dump plain and encoded strings.')
    parser.add_argument('-y', '--yara', action='store_true', default='', help='Run Yara ruleset on file. Rules should be stored in rules.yara!')
    parser.add_argument('-x', '--xorbrute', action='store_true', default='', help='Bruteforce potential XORed strings. Warning: Takes extra time!')
    parser.add_argument('-d', '--dump', action='store_true', default='', help='Attempt to dump RTF or VBA objects from file (Used with --rtf or --doc options')
    parser.add_argument('-o', '--open', action='store_true', default='', help='Once script is complete, open all resulting analysis files in text editor for better viewing.')
    args = parser.parse_args()
    
# Format input file for analysis
infile = (", ".join(args.infile))		

# Create output directory
config.outDir = auxiliary.createDir('./mfanalyzer-%s/' % (int(time.time())))

if args.pe:
	
	tools.call_portex(infile)
	#tools.call_pescanner(infile) #Removed due to errors. Will likely remove completely.
	tools.call_floss(infile)
	tools.call_balbuzard(infile)
	tools.call_malconf(infile)
	
if args.bin:
	
	tools.call_flossShellcode(infile)
	tools.call_xorsearch(infile)
	tools.call_malconf(infile)

if args.doc:
	
	tools.call_exif(infile)
	tools.call_oleid(infile)
	tools.call_olevba(infile)
	tools.call_oledump_strings(infile)
	tools.call_pcodedmp(infile)

	if args.dump:

		tools.call_oledump(infile)

if args.pdf:
	
	tools.call_exif(infile)
	tools.call_pdfid(infile)
	tools.call_pdfcop(infile)
	tools.call_pdfparser(infile)
	tools.call_peepdf(infile)

if args.rtf:

	tools.call_exif(infile)
	tools.call_rtfdump(infile)
	tools.call_rtfobj(infile)

	if args.dump:

		tools.call_rtfobjDump(infile)
	
if args.strings:
	
	tools.call_strings(infile)
	tools.call_stringSifter()
	tools.call_interestingStrings(infile)
	tools.call_stringsEncoded(infile)
	tools.call_base64dump(infile)
	tools.call_xorsearch(infile)

if args.yara:
	
	tools.call_yara(infile)
	
if args.zip:
	
	tools.call_zipdump(infile)

if args.xorbrute:

	tools.call_brxor(infile)
	tools.call_xorhunt(infile)

print('\n[+] Done! All results and dumped files are located in %s.' % (config.outDir))

if args.open:
	
	auxiliary.openTextEditor(config.outDir)
	


