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
var_datestart = time.strftime('%y%m%d-%Hh%M%S',time.localtime())
dir_path_ddrescue = 'tools/dd/'


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
	file_x = file_x.replace("\ "," ")
	file = open(file_x,'a')
	file.write(var_x)
	file.close()
	
def fct_writefile_del(var_x, file_x):
	file_x = file_x.replace("\ "," ")
	file = open(file_x,'w')
	file.write(var_x)
	file.close()
###########################################

# main fucntion
def fct_copy_dd():

	#directory for results
	root_dir_results = 'results/'
	dir_results = root_dir_results + str(var_datestart)

	disk_to_clone = "null"

	while disk_to_clone == "null":
		print_log("\nAvailable disks > ")
		disk_avail = os.popen("diskutil list").read()
		print_green(disk_avail)
		disk_to_clone=raw_input("Select the source disk to clone [ex : disk1s1] (b to back) > ")

		if disk_to_clone != "b":
			if os.path.exists("/dev/r" + disk_to_clone):
				print_log("\nInformation about [" + disk_to_clone + "] disk > ")
				info_disk = os.popen("diskutil info " + disk_to_clone).read()
				print_green(info_disk)
				launch_dd2 = raw_input("Are you sure to clone " + disk_to_clone + " disk ? [y]/n > ")
				if launch_dd2 == "n" : 
					disk_to_clone = "null"
				else:
					other_target = raw_input("\nDo you want to backup disk image to " + dir_results + " ? [y]/n >  " )
					if other_target == 'n': 
						select_vol_target = fct_select_target()
						dir_results = select_vol_target + "/Pac4Mac/" + dir_results
						dir_pac4mac = select_vol_target + "/Pac4Mac/"

						if not os.path.isdir(dir_pac4mac):
							os.makedirs(dir_pac4mac)

						if not os.path.isdir(root_dir_results):
							os.makedirs(root_dir_results)
							os.system('chmod 777 ' + root_dir_results)

						if not os.path.isdir(dir_results):
							os.makedirs(dir_results)
					
					else:
						if not os.path.isdir(dir_results):
							os.makedirs(dir_results)
					
					dir_path_DD = dir_results + "/disk_image"
					file_dump_DD = dir_path_DD + "/image_DD.raw"
					file_log_dd = dir_path_DD + "/image_DD.log"
					file_history_dest = dir_results + "/#log_pac4mac.txt"

					os.makedirs(dir_path_DD)

					var_log = str(datetime.datetime.now()) + ": " + "Disk Cloning [" + disk_to_clone + "]\n"
					fct_writefile(var_log, file_history_dest)

					print_green("\nBe patient, copy of " + disk_to_clone +  " to " + file_dump_DD + " \n...")
					print_red("\nIf cloning fails, you can resume it with following command > ")
					print_log('sudo ' + dir_path_ddrescue + 'ddrescue -v /dev/r' + disk_to_clone + ' "' +  file_dump_DD + '" "' + file_log_dd + '" -T')
					os.system(dir_path_ddrescue + 'ddrescue -v /dev/r' + disk_to_clone + ' "' +file_dump_DD + '" "' + file_log_dd + '"')
					print_green("\nCloning with success !\n")
					os.system('chmod -Rf 777 ' + dir_results)
					os.system('chmod -Rf 777 ' + dir_results + "/*")
					raw_input()
			else:
				print_red("\nPlease to select a valid disk or partition ...\n")
				disk_to_clone = "null"
		else:
			exit()

def fct_select_target():
	mounted_vol = "null"

	while mounted_vol == "null":
		print_log("\nAvailable mounted removable disks > ")
		mounted_vol = os.popen('mount | grep Volume | cut -d "/" -f 5').read()
		print_green(mounted_vol)
		
		vol_target = raw_input("Select the target disk [ex: USBDisk, Macintosh HD] (b to back) > ")
		
		if vol_target != "b":		
			select_vol_target = "/Volumes/" + vol_target
			if os.path.isdir(select_vol_target):
				return select_vol_target
			else:
				print_red("\nPlease to select a valid disk or partition ...\n")
				mounted_vol = "null"
		else:
			exit()

		################################################################################################################
####################################################################################################################################
												   #MAIN PROGRAM
####################################################################################################################################
		################################################################################################################

var_uid = os.geteuid()
if var_uid != 0:
	print_red("\nPlease run program with root privileges\n")
	sys.exit()

print_log("\nFrom investigator's Macbook, you can copy local disk through Firewire wire and Target Mode")
print_log("From Macbook to analyse, you can copy local disk to removable disk")

print_red("\n          ==== Plug source disk (Macbook or USB Disk) to copy ====")
print_green("========================================================================")
launch_dd = raw_input("Press enter when the source disk is plugged (b to back) ")
if launch_dd != "b":
	fct_copy_dd()



