#!/usr/bin/python
# -*- coding: iso-8859-15 -*-

#############################################################################
##                                                                         ##
## Pac4Mac.py --- Plug And Check For Mac OS X                              ##
##                                                                         ##
## Copyright (C) 2010  Arnaud Malard sganama(at)gmail.com                  ##
##                                                                         ##
## This program is free software; you can redistribute it and/or modify it ##
## under the terms of the GNU General Public License version 2 as          ##
## published by the Free Software Foundation; version 2.                   ##
##                                                                         ##
## This program is distributed in the hope that it will be useful, but     ##
## WITHOUT ANY WARRANTY; without even the implied warranty of              ##
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       ##
## General Public License for more details.                                ##
##                                                                         ##
#############################################################################
##
##  Ref. http://www.sud0man.blogspot.com
##
##    
## Revision 0.1  2013/09 amalard


import sys, os
import time
import os.path
import re
import thread
import datetime

############################################
	#Functions
############################################
def print_red(text):
	print ('\033[22;31m' + text + '\033[0;m')
			
def print_in(text):
	print ('\033[0;34m' + text + '\033[1;m')
		
def print_green(text):
	print ('\033[22;32m' + text + '\033[0;m')

def print_log(text):
	print ('\033[0;38m' + text + '\033[1;m')

def print_red_bold(text) :
	print ('\033[1;31m' + text + '\033[0;m')

def print_green_bold(text):
	print ('\033[1;32m' + text + '\033[0;m')


############################################
	#Main program
############################################




os.system('clear')


var_attack = "null"

while var_attack != "q":                                                             
	print_red_bold("\n\n=======================================================================================")
	print_green("                       Pac4Mc, Plug And Check for Mac OS X :) ")
	print_green("               		          Forensics framework \n\n")

	var_version=os.popen('uname -r | cut -d "." -f 1').read().strip("\n")
	if var_version == "12" : print_log("launched from: Mountain Lion / 10.8 ")
	elif var_version == "11" : print_log("launched from: Lion / 10.7")
	elif var_version == "10" : print_log("launched from: Snow Leopard Mac OS X / 10.6 ")
	elif var_version == "13" : print_red("launched from: Mavericks / 10.9 (not tested under this version)")
	else: 
		#print_red("\n\nUnsupported OS version.\n\n")
		var_version = "13"
		raw_input("\n\nOS not comptatible, features will be limited...\n\n")
		#exit()

	print_log("date: " + str(datetime.datetime.now()))

	print_red_bold("=======================================================================================\n\n")


	print_green_bold("1: Data Dump from standard user or root access (from Macbook to analyze)")
	print_green("2: Data Dump from Single Mode access (from Macbook to analyze)")
	print_green("3: Data Dump from mounted volumes (from investigator's Macbook)")
	print_green("4: Live Dump (from Macbook to analyze/from investigator's Macbook)")
	print_green("5: Clone disk (from Macbook to analyze/from investigator's Macbook)")
	print_green("6: File system Dump (from RAW image/from mounted volume)")
	print_green_bold("\n7: Analyze results of previous dump stages (from investigator's Macbook)")


	var_attack = raw_input("\nYour choice (q to quit) > ")

	var_priv=os.popen('echo $UID').read().strip("\n")




	if var_attack == "1": 
		if var_priv == "0" : os.system('python dumpPY/dumpMAIN.py ' + var_version + ' rootaccess')
		else:
			os.system('python dumpPY/dumpMAIN.py ' + var_version + ' useraccess')
	elif var_attack == "2": 
		os.system('python dumpPY/dumpMAIN.py ' + var_version + ' singlemode')
	elif var_attack == "3":
		os.system('python dumpPY/dumpFromVolume.py ')
	elif var_attack == "4":
		os.system('python dumpPY/dumpLIVE.py ' + var_version)
	elif var_attack == "5":
		os.system('python dumpPY/dumpDD.py')
	elif var_attack == "6":
		os.system('python2.7 dumpPY/dumpLowLevel.py')
	elif var_attack == "7":
		os.system('python analysis/AN_start.py ')
	elif var_attack == "q": 
		print_red_bold("\n\n=======================================================================================")
		print_green("                                 End of Frensic Analyis !")
		print_red_bold("=======================================================================================\n\n")
		exit()
	else: 
		print_red("\nPlease to choose 1, 2, 3, 4, 5, 6 or 7\n")


