#!/usr/bin/env python3

#################################################
## This module contains auxiliary functions.
##################################################

# ----- Imports -----

import os
import config
import time

# ----- Aux Functions -----

def openTextEditor(outDir):

	print('[+] Preparing to open in text editor...')
	time.sleep(3)

	os.system(config.textEditor + ' %s*.txt &' % (config.outDir))

def createDir(newDir):
	try:
		if not os.path.exists(newDir):
			os.makedirs(newDir)
			print ('[*] Created output directory: ' +  newDir + '.')
		
	except OSError:
		print ('[!] Error Creating directory: ' +  newDir + '!')
	
	return newDir
