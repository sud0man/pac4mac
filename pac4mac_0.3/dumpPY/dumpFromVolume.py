#! /usr/bin/python
# -*- coding: iso-8859-15 -*-


import sys, os
import time
import os.path
import re
import commands
import sqlite3 as lite
import time,datetime


############################################
#[Variables Initialization]
############################################
#Source file / os version
file_os_version="/System/Library/CoreServices/SystemVersion.plist"

#directory for results
var_datestart = time.strftime('%y%m%d-%Hh%M%S',time.localtime())
dir_results = 'results/' + str(var_datestart)

#file log pac4mac 
file_history_dest = dir_results + '/#log_pac4mac.txt'


############################################
#[Functions]
############################################

def print_red(text):
	print ('\033[22;31m' + text + '\033[0;m')
		
def print_in(text):
	print ('\033[0;34m' + text + '\033[1;m')

def print_green(text):
	print ('\033[22;32m' + text + '\033[0;m')

def print_log(text):
	print ('\033[0;38m' + text + '\033[1;m')


#[create file]
############################################
def fct_writefile(var_x, file_x):
	file = open(file_x,'a')
	file.write(var_x)
	file.close()
	
def fct_writefile_del(var_x, file_x):
	file = open(file_x,'w')
	file.write(var_x)
	file.close()
############################################


###################################################################################################################################
										     #[Data Dump]
###################################################################################################################################
def fct_data_dump():

	vol_target = "null"
	
	while vol_target == "null":
		print_log("\nAvailable mounted removable disks > ")
		mounted_vol=os.popen('mount | grep Volume | cut -d "/" -f 5').read()
		print_green(mounted_vol)
		vol_target=raw_input("Select the target disk [ex: Macintosh HD 1] (b to back) > ")
		
		if vol_target != "b": 
			select_vol_target = "/Volumes/" + vol_target
			if os.path.isdir(select_vol_target) and vol_target != "":
				select_vol_target = select_vol_target.replace(" ","\ ")
				var_version = os.popen("cat " + select_vol_target + file_os_version + " | grep '<string>10\.' |uniq").read()
				filtre = re.compile('\<string\>(.*)\<\/string\>',re.IGNORECASE)
				res = filtre.findall(var_version)
				for i in res :
					var_version = i
					if "10.6" in var_version:
						var_version = "10"
					elif "10.7" in var_version:
						var_version = "11"
					elif "10.8" in var_version:
						var_version = "12"
					elif "10.9" in var_version:
						var_version = "13"
					elif "10.10" in var_version:
						var_version = "14"
					elif "10.11" in var_version:
						var_version = "15"
					elif "10.12" in var_version:
						var_version = "16"
					else: 
						print_red("\nUnsupported OS version...")
						var_version = "16"
					os.system('python dumpPY/dumpMAIN.py ' + var_version + ' target ' + select_vol_target)
			else:
				print_red("\nPlease to select a valid disk or partition ...\n")
				vol_target = "null"





		################################################################################################################
####################################################################################################################################
												   #MAIN PROGRAM
####################################################################################################################################
		################################################################################################################


print_red("\n            ====Data Dump from mounted Volume or Target Mode====")
print_green("================<============================================>============\n")
print_log("\nFrom investigator's Macbook, this option allows to dump data through Firewire wire and Target Mode")
print_log("To use Target Mode, press T during system boot \nPlug Firewire wire between your Mac and Mac to analyse and press any key")

print_log("\n\nFrom investigator's Macbook, this option allows also to dump data from mounted Volume of a raw disk image")

var_action = raw_input("\n\nPress any key to continue (b to back) > ")

if var_action == "b" :
	exit()
else:
	fct_data_dump()