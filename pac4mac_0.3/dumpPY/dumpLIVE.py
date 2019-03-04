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

#python version
python3X = "python3.3"

#directory for results
var_datestart = time.strftime('%y%m%d-%Hh%M%S',time.localtime())
root_dir_results = 'results/'
dir_results = root_dir_results + str(var_datestart)

#inception
dir_path_RAM = dir_results + '/ram_dump'
dir_path_incept = 'tools/inception/'
file_dump_RAM_DMA = dir_path_RAM + '/RAM_memory.dmp'

#Mac Memory Reader
dir_path_osxpmem = 'tools/pmem/OSXPMem/'
file_dump_RAM = '../../../' + dir_path_RAM + '/RAM_memory.dmp'

CheckOut4Mac_path = 'tools/CheckOut4Mac/chk4mac_0.2.py'

#file log pac4mac 
file_history_dest = dir_results + '/#log_pac4mac.txt'

#userfile files
dir_users_info = dir_results + '/#users_info'
file_userslist = dir_users_info + '/users_list.txt'

#pid files
path_pid = dir_results + '/PID'
file_pid = path_pid + '/pid.txt'

#lsof files
file_lsof = path_pid + '/lsof_by_pid.txt'

#vmmap files
file_vmmap = path_pid + '/vmmap_by_pid.txt'

#directory for database
dir_db = 'db/'
db_search_sys = dir_db + 'system_live.db'

#log files
file_log = dir_results + '/main_dump.txt'

#MacOS_version
var_version = sys.argv[1]

#file version osx
file_version_dest = dir_results + '/#macosx_version.txt'


############################################
#[Functions]
############################################

def print_red(text):
	print ('\033[22;31m' + text + '\033[0;m')

def print_red_bold(text):
	print ('\033[1;31m' + text + '\033[0;m')
		
def print_in(text):
	print ('\033[0;34m' + text + '\033[1;m')

def print_green(text):
	print ('\033[22;32m' + text + '\033[0;m')

def print_log(text):
	print ('\033[0;38m' + text + '\033[1;m')


#[create file]
############################################
def fct_writefile(var_x, file_x):
	file_to_write = open(file_x,'a')
	file_to_write.write(var_x)
	file_to_write.close()
	
def fct_writefile_del(var_x, file_x):
	file_to_write = open(file_x,'w')
	file_to_write.write(var_x)
	file_to_write.close()
############################################


#####################################################################################################################
										     #[Exploit DMA]
####################################################################################################################
def fct_exploit_DMA():
	print_red("\n                     ====Exploit DMA Access====")
	print_log("\nNote : Please to install libforensic1394 [" +  dir_path_incept + "README.md" + "]")
	print_log("Note2 : Please to custom [#!/usr/bin/env python3.X] into [" + dir_path_incept + "incept.py]")
	print_log("Note3 : Please to custom variable [python3X] into [" + sys.argv[0] + "]\n")
	
	var_attack = "null"
	while var_attack == "null":
		print_green("\nPlug Firewire wire between your Mac and Mac to analyse AND : ")
		print_green("1: Dump volatile memory")
		print_green("2: Unlock session")

		var_attack = raw_input("\nYour choice (b to back) > ")
		if var_attack == "1": 
			fct_dump_RAM_DMA()
			var_attack = "null"
		elif var_attack == "2": 
			fct_unlock_DMA()
			var_attack = "null"
		elif var_attack == "b": 
			var_attack = "no_null"
		else: 
			print_red("\nPlease to choose 1 or 2 ...\n")
			var_attack = "null"


#[dump RAM]
def fct_dump_RAM_DMA():
	print_red("\n========================================================================")
	print_red("                   ==== dump of volatile memory ====")
	print_red("========================================================================")
	var_dump_mem = raw_input("Do you want to dump volatile memory by DMA ? y/[n] > ")
	if var_dump_mem == "y":
		
		if not os.path.isfile(file_dump_RAM_DMA):

			if not os.path.isdir(root_dir_results):
				os.makedirs(root_dir_results)
				os.system('chmod 777 ' + root_dir_results)
			if not os.path.exists(dir_results):
				os.makedirs(dir_results)
			if not os.path.exists(dir_path_RAM):
				os.makedirs(dir_path_RAM)

			#log activity
			var_log=str(datetime.datetime.now()) + ": " + "Dump volatile memory by DMA\n"
			fct_writefile(var_log, file_history_dest)
			fct_writefile_del(os_version, file_version_dest)
			print_green("\nOS detected > " + os_version )

			print_green("Start of dumping, be patient ...")
			start_time=time.clock()
			try:
				os.system(python3X + " " + dir_path_incept + "incept -D " + file_dump_RAM_DMA)
				duration=time.clock() - start_time
				duration = (duration*100)*3
				print_green("Dumping with success !")
				print_log ("Duration of dump : " + str(duration) + " seconds")
				print_log("RAM image is stored into " + file_dump_RAM_DMA)
				os.system('chmod -R 777 ' + dir_results)
			except:
				print_log("RAM dump is not possible ...")
		else:
			print_log(file_dump_RAM_DMA + " existing ... Please to launch a new instance of Pac4Mac.")
	else:
		print_log("RAM dump not launched")
	print_red("========================================================================")
	print_red("                 ==== \\dump of volatile memory ====")
	print_red("========================================================================")


#[unlock session]
def fct_unlock_DMA():
	print_red("\n\n========================================================================")
	print_red("       ==== unlocking session/privileges escalation by DMA ACCESS ====")
	print_red("========================================================================")
	print_log("You could unlock session with all non-blank passwords ...")
	print_log("You could escalade your privileges to gain root access ... ")
	var_unlock = raw_input("Do you want to attempt to launch these operations ? y/[n] > ")
	if var_unlock == "y": 
		os.system(python3X + " " + dir_path_incept + "incept test test")
		print_green("\nYou can try to open any session with all non-blank passwords !")
		print_green("You can try to launch 'su root' to get root privileges !")
	else: 
		print_log("Unlock session not launched")
		print_log("Privileges escalation not launched")
	print_red("========================================================================")
	print_red("     ==== \\unlocking session/privileges escalation by DMA ACCESS ====")
	print_red("========================================================================")


#####################################################################################################################
										     #[Dump RAM with root priv]
######################################################################################################################
def fct_dump_RAM_soft():

	print_red("\n\n========================================================================")
	print_red("                   ==== dump of VOLATILE MEMORY ====")
	print_red("========================================================================")
	print_log("[RAM_DUMP] to extract volatile memory")
	var_dump_mem=raw_input("Do you want to dump volatile memory ? y/[n] > ")
	if var_dump_mem == "y":

		if not os.path.isfile(file_dump_RAM_DMA):

			if not os.path.isdir(root_dir_results):
				os.makedirs(root_dir_results)
				os.system('chmod 777 ' + root_dir_results)

			if not os.path.exists(dir_results):
				os.makedirs(dir_results)
			
			if not os.path.exists(dir_path_RAM):
				os.makedirs(dir_path_RAM)

			#log activity
			var_log = str(datetime.datetime.now()) + ": " + "Dump of Volatile Memory (Software)\n"
			fct_writefile(var_log, file_history_dest)
			fct_writefile_del(os_version, file_version_dest)
			print_green("\nOS detected > " + os_version )

			#good right
			os.system('chmod -R 741 ' + dir_path_osxpmem)
			os.system('chown -R root:wheel ' + dir_path_osxpmem)
			
			current_cwd = os.getcwd()
			os.chdir(dir_path_osxpmem)

			print_log("Start of dumping, be patient ...")
			start_time = time.clock()
			try:
				commands.getoutput("./osxpmem " + file_dump_RAM)
				duration=time.clock() - start_time
				duration = (duration*10000)*3
				print_log ("Duration of dump : " + str(duration) + " seconds")
				os.chdir(current_cwd)
				print_log("[\RAM_DUMP] RAM image is stored into " + dir_path_RAM + "/RAM_memory.dmp")
				os.system('chmod -R 777 ' + dir_results)
			except:
				print_log("\n[\RAM_DUMP] RAM dump is not possible ...")
		else:
			print_log(file_dump_RAM_DMA + " existing ... Please to launch a new instance of Pac4Mac.")

	else : print_log("\n[\RAM_DUMP] RAM dump not launched")
	print_red("========================================================================")
	print_red("                 ==== \\dump of VOLATILE MEMORY ====")
	print_red("========================================================================")



###################################################################################################################################
										     #[Check_live]
######################################################################################################################
def fct_Checkout4Mac():

	if not os.path.isdir(root_dir_results):
		os.makedirs(root_dir_results)
		os.system('chmod 777 ' + root_dir_results)

	if not os.path.exists(dir_results):
		os.makedirs(dir_results)

	
	#log activity
	var_log = str(datetime.datetime.now()) + ": " + "CheckOut4Mac\n"
	fct_writefile(var_log, file_history_dest)

	fct_writefile_del(os_version, file_version_dest)
	print_green("\nOS detected > " + os_version)


	os.system("sudo python " + CheckOut4Mac_path)

############################################

############################################
def fct_get_system_conf():

	if not os.path.isdir(root_dir_results):
		os.makedirs(root_dir_results)
		os.system('chmod 777 ' + root_dir_results)

	if not os.path.exists(dir_results):
		os.makedirs(dir_results)

	print_log("\nThe results will be stored in > " + dir_results)
	print_green("========================================================================")

	#log activity
	var_log = str(datetime.datetime.now()) + ": " + "Live Activties\n"
	fct_writefile(var_log, file_history_dest)

	fct_writefile_del(os_version, file_version_dest)
	print_green("\nOS detected > " + os_version)


	#dump user
	var_userslist = os.popen("/usr/bin/dscacheutil -q user|grep -B 5 '/bash'|grep name|cut -c '7-'").read().strip("\n")
	if not os.path.isdir(dir_users_info):
		os.makedirs(dir_users_info)
	fct_writefile(var_userslist,file_userslist)

	#extract username list
	file_user = open(file_userslist,'r')
	lines_username = file_user.readlines()
	file_user.close()	

	#extract pid user/root
	print_red_bold("\n[] Dump PID")
	if not os.path.exists(path_pid):
		os.makedirs(path_pid)
	print_green("========================================================================")
	print_log("[PID] Extraction of root and user PID numbers")
	print_green("Launching of the command, be patient ...\n...\n...")

	lsof_root = os.popen("lsof -u root | tr -s ' ' | cut -d' ' -f2 | sort -u").read()
	lsof_user = os.popen("lsof -u root | tr -s ' ' | cut -d' ' -f2 | sort -u").read()

	fct_writefile_del("[PID ROOT]\n" + lsof_root, file_pid)
	fct_writefile("[PID USER]\n" + lsof_user, file_pid)

	print_log("[PID] Stored into " + file_pid)
	print_green("========================================================================")

	#lsof and vmmap on pid
	print_green("========================================================================")
	print_log("[LSOF_VMMAP] Launching of lsof and vmmap commands on all the PID]")
	print_green("Launching of the command, be patient ...\n...\n...")
	
	file_user = open(file_pid,'r')
	lines_pid = file_user.readlines()
	file_user.close()

	for i in range(len(lines_pid)):
		if "PID" not in lines_pid[i] :
			vmmap_data = os.popen("vmmap " + lines_pid[i]).read()
			fct_writefile(vmmap_data, file_vmmap)
			lsof_data = os.popen("lsof -p " + lines_pid[i]).read()
			fct_writefile(lsof_data, file_lsof)
	
	print_log("[LSOF_VMMAP] Stored into " + file_lsof + " and " + file_vmmap)
	print_green("========================================================================")

	os.system('python dumpPY/dumpMAIN.py ' + var_version + ' LIVE ' + dir_results)




		################################################################################################################
####################################################################################################################################
												   #MAIN PROGRAM
####################################################################################################################################
		################################################################################################################

var_uid = os.geteuid()
if var_uid != 0 : 
	print_red("\nPlease run program with root privileges.\n")
	sys.exit()

#version
if var_version == "12":
	os_version = "Mountain Lion / 10.8"
elif var_version == "11":
	os_version = "Lion / 10.7"
elif var_version == "10":
	os_version = "Snow Leopard / 10.6"
elif var_version == "13":
	os_version = "Mavericks / 10.9"
elif var_version == "14":
	os_version = "Yosemite / 10.10"
elif var_version == "15":
	os_version = "El Capitan / 10.11"
elif var_version == "16":
	os_version = "Sierra / 10.12"
elif var_version == "17":
        os_version = "High Sierra / 10.13"
elif var_version == "18":
        os_version = "Mojave / 10.14"
else:
	print_red("\nUnsupported OS version.")
	os_version = "Unknown version"





print_red("\n                      ====Live Dump features====")
print_green("========================================================================\n")


var_action = "null"
while var_action == "null":
	print_green("1: Exploit DMA accesses (from investigator's Macbook)")
	print_green("2: Dump RAM (from Macbook to analyze)")
	print_green("3: Dump of Network and System state (from Macbook to analyze)")
	print_green("4: Detect recent malicious activities with CheckOut4Mac (from Macbook to analyze)")


	var_action=raw_input("\nYour choice (b to back) > ")

	if var_action == "1": 
		fct_exploit_DMA()
		var_action = "null"
	elif var_action == "2": 
		fct_dump_RAM_soft()
		var_action = "null"
	elif var_action == "3": 
		var_action = "null"
		fct_get_system_conf()
	elif var_action == "4": 
		var_action = "null"
		fct_Checkout4Mac()
	elif var_action == "b": 
		var_action = "no_null"
	else: 
		print_red("\nPlease to choose 1, 2, 3 or 4 ...\n")
		var_action = "null"
