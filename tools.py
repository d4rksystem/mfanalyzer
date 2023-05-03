#!/usr/bin/env python2.7

#################################################
## This module contains the tool callers and associated parameters.
##################################################

# ----- Imports -----

import subprocess
import config
import os

# ----- Tool Callers -----

def call_file(infile):
	
	print('[*] Running file command to determine the filetype...')
	
	try:
		subprocess.call([config.file, infile])
	except subprocess.CalledProcessError as e:
		print e.output
		
def call_pescanner(infile):
	
	print('[*] Analyzing PE file (pescanner)...')
	
	outFile = open("%spescanner.txt" % (config.outDir), "w")
	
	try:
		subprocess.call([config.pescanner, infile], stdout = outFile)
	except subprocess.CalledProcessError as e:
		print e.output
		
	outFile.close()

def call_portex(infile):
	
	print('[*] Analyzing PE file (portex)...')

	outFile = open("%sportex.txt" % (config.outDir), "w")

	try:
		subprocess.call([config.portex, infile], stdout = outFile)
	except subprocess.CalledProcessError as e:
		print e.output
	
	outFile.close()

def call_exescan(infile):
	
	print('[*] Analyzing PE file (portex)...')

	outFile = open("%sportex.txt" % (config.outDir), "w")

	try:
		subprocess.call([config.portex, infile], stdout = outFile)
	except subprocess.CalledProcessError as e:
		print e.output
	
	outFile.close()
	
def call_malconf(infile):
	
	print('[*] Attempting to extract malware config (malconf) ...')

	outFile = open("%smalconf.txt" % (config.outDir), "w")

	try:
		subprocess.call([config.malconf, infile], stdout = outFile)
	except subprocess.CalledProcessError as e:
		print e.output
	
	outFile.close()
	
def call_balbuzard(infile):
	
	print('[*] Attempting to extract juicy info (balbuzard) ...')

	outFile = open("%sbalbuzard.txt" % (config.outDir), "w")

	try:
		subprocess.call([config.balbuzard, infile], stdout = outFile)
	except subprocess.CalledProcessError as e:
		print e.output
	
	outFile.close()

def call_strings(infile):
	
	print('[*] Extracting strings...')
	
	outFile = open("%sstrings.txt" % (config.outDir), "w")

	try:
		subprocess.call([config.strings, '--bytes=8', infile], stdout = outFile)
	except subprocess.CalledProcessError as e:
		print e.output
	
	outFile.close()
	
def call_stringSifter():
	
	print('[*] Ranking strings using FLARE StringSifter...')
	
	infile = "%sstrings.txt" % (config.outDir)
	outFile = open("%sranked-strings.txt" % (config.outDir), "w")

	try:
		process = subprocess.Popen([config.stringsifter, infile], stdout = outFile)
		process.wait()
	except subprocess.CalledProcessError as e:
		print e.output
	
	outFile.close()
	
def call_interestingStrings(infile):
	
	print('[*] Extracting interesting strings (using provided strings file)...')
	
	outFile = open("%sinteresting-strings.txt" % (config.outDir), "w")
	
	try:
		# Run string command and set stdout to pipe.
		stringsCmd = subprocess.Popen([config.strings, infile], stdout = subprocess.PIPE)
		
		# Run grep command with the strings command as input.
		grepCmd = subprocess.Popen(['grep', '-i', '-f', 'stringslist'], stdin = stringsCmd.stdout, stdout = outFile)
		
	except subprocess.CalledProcessError as e:
		print e.output
	
	outFile.close()

def call_stringsEncoded(infile):
	
	print('[*] Extracting encoded strings...')
	
	outFile = open("%sstrings-encoded.txt" % (config.outDir), "w")

	try:
		subprocess.call([config.strings, '--encoding=l', '--bytes=8', infile], stdout = outFile)
	except subprocess.CalledProcessError as e:
		print e.output
	
	outFile.close()

def call_floss(infile):
	
	print('[*] Attempting to deobfuscate strings (FLOSS)...')
	
	outFile = open("%sfloss.txt" % (config.outDir), "w")

	try:
		subprocess.call([config.floss, '--no-static-strings', '-g', infile], stdout = outFile)
	except subprocess.CalledProcessError as e:
		print e.output
	
	outFile.close()

def call_flossShellcode(infile):
	
	print('[*] Attempting to deobfuscate strings (FLOSS)...')
	
	outFile = open("%sfloss.txt" % (config.outDir), "w")

	try:
		subprocess.call([config.floss, '--no-static-strings', '-g', '-s', infile], stdout = outFile)
	except subprocess.CalledProcessError as e:
		print e.output
	
	outFile.close()

def call_base64dump(infile):
	
	print('[*] Extracting base64 strings (base64dump)...')
	
	outFile = open("%sstrings-base64.txt" % (config.outDir), "w")
	
	try:
		subprocess.call([config.base64dump, infile], stdout = outFile)
	except subprocess.CalledProcessError as e:
		print e.output
	
	outFile.close()

def call_xorsearch(infile):
	
	print('[*] Searching for shellcode and XORed data (XORsearch)...')
	
	outFile = open("%sshellcode.txt" % (config.outDir), "w")
	
	try:
		subprocess.call([config.xorsearch, '-W', '-d', '3', '-p', infile], stdout = outFile)
	except subprocess.CalledProcessError as e:
		print e.output
	
	outFile.close()

def call_xorhunt(infile):
	
	print('[*] Searching for XORed strings from stringslist (XORsearch)...')
	
	outFile = open("%sxorsearch-stringslist.txt" % (config.outDir), "w")
	
	try:
		subprocess.call([config.xorsearch, '-i', '-f', 'stringslist', infile], stdout = outFile)
		
	except subprocess.CalledProcessError as e:
		print e.output
	
	outFile.close()

def call_yara(infile):
	
	print('[*] Running Yara ruleset...')
	
	outFile = open("%syara.txt" % (config.outDir), "w")
	
	try:
		subprocess.call([config.yara, '-s', 'rules.yara', infile], stdout = outFile)
		
	except subprocess.CalledProcessError as e:
		print e.output
	
	outFile.close()
	
def call_exif(infile):
	
	print('[*] Extracting metadata (exiftool)...')
	
	outFile = open("%sexif.txt" % (config.outDir), "w")
	
	try:
		subprocess.call([config.exif, infile], stdout = outFile)
	except subprocess.CalledProcessError as e:
		print e.output
	
	outFile.close()

def call_oleid(infile):
	
	print('[*] Extracting OLE information (oleid)...')
	
	outFile = open("%soleid.txt" % (config.outDir), "w")
	
	try:
		subprocess.call([config.oleid, infile], stdout = outFile)
	except subprocess.CalledProcessError as e:
		print e.output
	
	outFile.close()

def call_oledump(infile):
	
	print('[*] Extracting detailed OLE information (oledump)...')
	
	outFile = open("%soledump.txt" % (config.outDir), "w")
	
	try:
		subprocess.call([config.oledump, infile], stdout = outFile)
	except subprocess.CalledProcessError as e:
		print e.output
	
	outFile.close()
	
def call_oledump_strings(infile):
	
	print('[*] Extracting VBA strings (oledump)')
	
	outFile = open("%soledump_strings.txt" % (config.outDir), "w")
	
	try:
		subprocess.call([config.oledump, '-S', '-s', 'a', infile], stdout = outFile)
	except subprocess.CalledProcessError as e:
		print '[!] Error in olevba! Perhaps this file has no VBA code to dump?'
	
	outFile.close()

def call_olevba(infile):
	
	print('[*] Extracting VBA code (olevba)...')
	
	outFile = open("%solevba.txt" % (config.outDir), "w")
	
	try:
		subprocess.call([config.olevba, infile], stdout = outFile)
	except subprocess.CalledProcessError as e:
		print '[!] Error in olevba! Perhaps this file has no VBA code to dump?'
	
	outFile.close()

def call_pcodedmp(infile):
	
	print('[*] Extracting P-code (pcodedmp)...')
	
	outFile = open("%spcodedmp.txt" % (config.outDir), "w")
	
	try:
		subprocess.call([config.pcodedmp, '-d', infile], stdout = outFile)
	except subprocess.CalledProcessError as e:
		print e.output
	
	outFile.close()

def call_zipdump(infile):
	
	print('[*] Extracting ZIP data (zipdump)...')
	
	outFile = open("%szipdump.txt" % (config.outDir), "w")
	
	try:
		subprocess.call([config.zipdump, '-e', infile], stdout = outFile)
	except subprocess.CalledProcessError as e:
		print e.output
		
	outFile.close()
	
def call_pdfid(infile):
	
	print('[*] Extracting PDF data (pdfid)...')
	
	outFile = open("%spdfid.txt" % (config.outDir), "w")
	
	try:
		subprocess.call([config.pdfid, '-f', '-e', infile], stdout = outFile)
	except subprocess.CalledProcessError as e:
		print e.output
		
	outFile.close()

def call_pdfparser(infile):
	
	print('[*] Listing embedded PDF objects (pdf-parser)...')
	
	outFile = open("%spdfparser.txt" % (config.outDir), "w")
	
	try:
		subprocess.call([config.pdfparser, infile, '-O', '-k', '/URI'], stdout = outFile)
	except subprocess.CalledProcessError as e:
		print e.outputs
	
	try:
		subprocess.call([config.pdfparser, infile, '-O', '-k', '/JS'], stdout = outFile)
	except subprocess.CalledProcessError as e:
		print e.outputs
		
	try:
		subprocess.call([config.pdfparser, infile, '-O', '-k', '/JavaScript'], stdout = outFile)
	except subprocess.CalledProcessError as e:
		print e.outputs
	
	outFile.close()

def call_peepdf(infile):
	
	print('[*] Analyzing PDF objects (peepdf)...')
	
	outFile = open("%speepdf.txt" % (config.outDir), "w")
	
	try:
		subprocess.call([config.peepdf, infile], stdout = outFile)
	except subprocess.CalledProcessError as e:
		print e.output
		
	outFile.close()
	
def call_pdfcop(infile):
	
	print('[*] Analyzing PDF (pdfcop)...')
	
	outFile = open("%spdfcop.txt" % (config.outDir), "w")
	
	try:
		subprocess.call([config.pdfcop, infile], stdout = outFile)
	except subprocess.CalledProcessError as e:
		print e.output
		
	outFile.close()

def call_rtfdump(infile):
	
	print('[*] Dumping RTF objects list (rtfdump)...')
	
	outFile = open("%srtfdump.txt" % (config.outDir), "w")
	
	try:
		subprocess.call([config.rtfdump, infile], stdout = outFile)
	except subprocess.CalledProcessError as e:
		print e.output
		
	outFile.close()

def call_rtfobj(infile):
	
	print('[*] Dumping RTF objects list (rtfobj)...')
	
	outFile = open("%srtfobj.txt" % (config.outDir), "w")
	
	try:
		subprocess.call([config.rtfobj, infile], stdout = outFile)
	except subprocess.CalledProcessError as e:
		print e.output
		
	outFile.close()

def call_rtfobjDump(infile):
	
	print('[*] Dumping RTF objects (rtfobj)...')
	
	try:
		subprocess.call([config.rtfobj, '-s', 'all', '-d', config.outDir, infile])
	except subprocess.CalledProcessError as e:
		print e.output

def call_brxor(infile):
	
	print('[*] Brute-forcing possible XORed strings (brxor)...')
	
	outFile = open("%sbrxor.txt" % (config.outDir), "w")
	
	try:
		subprocess.call([config.brxor, infile], stdout = outFile)
	except subprocess.CalledProcessError as e:
		print e.output
	
	
	
	
