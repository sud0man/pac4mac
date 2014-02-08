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
#directory for results
var_datestart = time.strftime('%y%m%d-%Hh%M%S',time.localtime())
root_dir_results = 'results/'
dir_results = root_dir_results + str(var_datestart)
file_history_dest = dir_results + "/#log_pac4mac.txt"
dir_results_catalogfile = dir_results + "/catalogFiles/"

#tools path
path_to_disktype = "tools/disk_utilities/disktype"
path_to_mmls = "tools/disk_utilities/mmls"
path_to_fsstat = "tools/disk_utilities/fsstat"
path_to_fls = "tools/disk_utilities/fls"
path_to_icat = "tools/disk_utilities/icat"



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


####################################################################################################################################
												   #MMLS
####################################################################################################################################
def fct_mmls():
	
	part_to_analyse = "null"

	while part_to_analyse == "null":
		mmls_res = os.popen(path_to_mmls + " " + disk_to_analyse).read()
		print_log("\n[MMLS] - Information about partition table of [" + disk_to_analyse + "] > ")
		print_green(mmls_res)
		offset_start = ""
		while offset_start == "":
			offset_start = raw_input("Please to type a Start Octet of partition to analyze (ex: 0000000002) > ")

		fsstat_res = os.popen(path_to_fsstat + " -o " + offset_start + " " + disk_to_analyse).read()
		print_log("\n[FSSTAT] - Information about partition [" + offset_start + "] > ")
		print_green(fsstat_res)

		launch_analysis = raw_input("Are you sure to work with this partition ? [y]/n > ")
		if launch_analysis == "n":
			part_to_analyse = "null"
		else:
			file_dump_infodisk = dir_results + "/partitions_infos" + disk_to_analyse.replace("/","_") + ".info"
			fct_writefile_del(mmls_res + "\n\n", file_dump_infodisk)
			fct_writefile(fsstat_res, file_dump_infodisk)
			print_red("\nTechnical informations are stored into " + file_dump_infodisk)
			return(offset_start)


####################################################################################################################################
												   #Dump File system with FLS (for timeline with MActime)
####################################################################################################################################
def fct_dump_fls_timeline():

	timezone = ""

	while timezone == "":
		timezone = raw_input("\nPlease to type time zone (eg.: CET) > ")


	file_dump_fls = dir_results + "/image_tree_" + disk_to_analyse.replace("/","_") + "-" + part_to_analyse + "." + str(timezone) + ".timeline.fls"
	file_history_dest = dir_results + "/#log_pac4mac.txt"



	launch_fls = raw_input("Are you sure to launch fls (can take a long time) ? [y]/n > ")
	if launch_fls != "n":
		var_log = "[FLS] - " + str(datetime.datetime.now()) + ": Builting of File System tree (timeline) of [" + disk_to_analyse + "] from [" + part_to_analyse + "]\n"
		fct_writefile(var_log, file_history_dest)
		print_green("\n[FLS] - Builting of File System tree of [" + disk_to_analyse + "] from [" + part_to_analyse + "], be patient \n...\n ")
		os.system(path_to_fls + " -z " + str(timezone) + " -r -f hfs -s 0 -m '/' -o " + part_to_analyse + " " + disk_to_analyse + ">'" + file_dump_fls + "'")
		print_red("Information is stored into " + file_dump_fls + "\n")


###################################################################################################################################
												   #Dump File system with FLS
####################################################################################################################################
def fct_dump_fls():

	timezone = ""

	while timezone == "":
		timezone = raw_input("\nPlease to type time zone (eg.: CET) > ")

	file_dump_fls = dir_results + "/image_tree_" + disk_to_analyse.replace("/","_") + "-" + part_to_analyse + "." + str(timezone) + ".fls"
	file_history_dest = dir_results + "/#log_pac4mac.txt"


	launch_fls = raw_input("Are you sure to launch fls (can take a long time) ? [y]/n > ")
	if launch_fls != "n":
		var_log = "[FLS] - " + str(datetime.datetime.now()) + ": Builting of File System tree of [" + disk_to_analyse + "] from [" + part_to_analyse + "]\n"
		fct_writefile(var_log, file_history_dest)
		print_green("\n[FLS] - Builting of File System tree of [" + disk_to_analyse + "] from [" + part_to_analyse + "], be patient \n...\n ")
		os.system(path_to_fls + " -z " + str(timezone) + " -r -a -p -f hfs -o " + part_to_analyse + " " + disk_to_analyse + ">'" + file_dump_fls + "'")
		print_red("Information is stored into " + file_dump_fls + "\n")


####################################################################################################################################
												   #Dump CatalogFile, JournalFile and HFS Volume Header
####################################################################################################################################
def fct_dump_volumeheader():
	
	if not os.path.isdir(dir_results_catalogfile):
		os.makedirs(dir_results_catalogfile)

	file_dump_vh = dir_results_catalogfile + "volume_header" + disk_to_analyse.replace("/","_") + "-" + part_to_analyse + ".volheader"

	sector_size = raw_input("\nPlease to type size of sector in byte (ex: 512) > ")
	if sector_size == "512":
		count_sector = 2
	else:
		count_sector = 1
	start_volume_header = int(part_to_analyse) + 2

	var_log = "[DD] - " + str(datetime.datetime.now()) + ": Cloning of Volume Header File of [" + disk_to_analyse + "] from [" + part_to_analyse + "]\n"
	fct_writefile(var_log, file_history_dest)

	print_green("\n[DD] - Cloning of Volume Header File of [" + disk_to_analyse + "] from [" + part_to_analyse + "], be patient \n...\n")
	os.system('dd if=' + disk_to_analyse + ' skip=' + str(start_volume_header) + ' bs=' + str(sector_size) + ' count=' + str(count_sector) + ' > ' + file_dump_vh)
	print_red("\nInformation is stored into " + file_dump_vh + "\n")
	return file_dump_vh


def fct_dump_catalogfile():

	if not os.path.isdir(dir_results_catalogfile):
		os.makedirs(dir_results_catalogfile)

	file_dump_ctg = dir_results_catalogfile + "/catlog_file" + disk_to_analyse.replace("/","_") + "-" + part_to_analyse + ".ctg"

	cat_id = os.popen(path_to_fls + " -o " + part_to_analyse + " " + disk_to_analyse + "| grep -i catalogfile | awk '{print$2}'").read().strip("\n")
	cat_id = cat_id.strip(":")

	var_log = "[ICAT] - " + str(datetime.datetime.now()) + ": Copy of Catalog File of [" + disk_to_analyse + "] from [" + part_to_analyse + "]\n"
	fct_writefile(var_log, file_history_dest)

	print_green("\n[ICAT] - Copy of Catalog file of [" + disk_to_analyse + "] from [" + part_to_analyse + "], be patient \n...\n")
	os.system(path_to_icat + ' -o ' + part_to_analyse + ' ' + disk_to_analyse + ' ' + cat_id + ' > ' + file_dump_ctg)
	print_red("Information is stored into " + file_dump_ctg + "\n")
	return file_dump_ctg


def fct_dump_journalfile():

	if not os.path.isdir(dir_results_catalogfile):
		os.makedirs(dir_results_catalogfile)

	file_dump_journ = dir_results_catalogfile + "/journal_file" + disk_to_analyse.replace("/","_") + "-" + part_to_analyse + ".journal"

	cat_id = os.popen(path_to_fls + " -o " + part_to_analyse + " " + disk_to_analyse + "| grep -i .journal | grep -v info | awk '{print$2}'").read().strip("\n")
	cat_id = cat_id.strip(":")

	var_log = "[ICAT] -" + str(datetime.datetime.now()) + ": Copy of Journal File of [" + disk_to_analyse + "] from [" + part_to_analyse + "]\n"
	fct_writefile(var_log, file_history_dest)

	print_green("\n[]ICAT] - Copy of Journal file of [" + disk_to_analyse + "] from [" + part_to_analyse + "], be patient \n...\n")
	os.system(path_to_icat + ' -o ' + part_to_analyse + ' ' + disk_to_analyse + ' ' + cat_id + ' > ' + file_dump_journ)
	print_red("Information is stored into " + file_dump_journ + "\n")
	return file_dump_journ




####################################################################################################################################
												   #Select RAW image or live disk
####################################################################################################################################

def fct_select_target():
	#directory for results
	dir_results = 'results/' + str(var_datestart)

	disk_to_analyse = "null"

	while disk_to_analyse == "null":
		print_log("\nAvailable disks > ")
		disk_avail = os.popen("diskutil list").read()
		#disk_avail = os.popen("fdisk -l").read()
		print_green(disk_avail)
		disk_to_analyse=raw_input("Select the target disk or RAW image to analyse [ex : disk0, disk0s2 or /tmp/MonImage.dd ] (b to back / s to get interactive shell) > ")

		if disk_to_analyse == "s":
			print_red("Type exit to quit interactive shell\n")
			os.system("/bin/bash")
			disk_to_analyse = "null"

		elif disk_to_analyse != "b":
			if "disk" in disk_to_analyse:
				disk_to_analyse = "/dev/r" + disk_to_analyse

			if os.path.exists(disk_to_analyse):
				print_log("\nInformation about [" + disk_to_analyse + "] > ")
				disk_to_analyse = disk_to_analyse.replace(" ","\ ")
				info_disk = os.popen(path_to_disktype + " " + disk_to_analyse).read()
				print_green(info_disk)
				launch_dd2 = raw_input("Are you sure to work with " + disk_to_analyse + " ? [y]/n > ")
				if launch_dd2 == "n" : 
					disk_to_analyse = "null"
				else:
					if not os.path.isdir(root_dir_results):
						os.makedirs(root_dir_results)
						os.system('chmod 777 ' + root_dir_results)
					if not os.path.isdir(dir_results):
						os.makedirs(dir_results)
					file_dump_disktype = dir_results + "/partitions_infos_all.info"
					fct_writefile_del(info_disk + "\n\n", file_dump_disktype)
					print_red("Information is stored into " + file_dump_disktype + "\n")
					return disk_to_analyse
			else:
				print_red("\nPlease to select a valid disk or image ...\n")
				disk_to_analyse = "null"

		else:
			return "back"


		################################################################################################################
####################################################################################################################################
												   #MAIN PROGRAM
####################################################################################################################################
		################################################################################################################
var_uid = os.geteuid()
if var_uid != 0 : 
	print_red("\nPlease run program with root privileges.\n")
	exit()


print_red("\n            		====Low Level Analysis====")
print_green("========================================================================\n")


var_action = "null"
while var_action == "null":
	print_green("1: Build a File System Tree with FLS to IDENTIFY ALL FILES")
	print_green("2: Build a File System Tree with FLS to generate TIMELINE with MACTIME")
	print_green("3: Dump CatalogFile, JournalFile and Header Volume")

	var_action=raw_input("\nYour choice (b to back) > ")

	if var_action == "1": 
		disk_to_analyse = fct_select_target()
		if disk_to_analyse != "back":
			part_to_analyse = fct_mmls()
			fct_dump_fls()
		var_action = "null"

	elif var_action == "2": 
		disk_to_analyse = fct_select_target()
		if disk_to_analyse != "back":
			part_to_analyse = fct_mmls()
			fct_dump_fls_timeline()
		var_action = "null"

	elif var_action == "3": 
		disk_to_analyse = fct_select_target()
		if disk_to_analyse != "back":
			part_to_analyse = fct_mmls()
			file_dump_vh = fct_dump_volumeheader()
			file_dump_ctg = fct_dump_catalogfile()
			file_dump_journ = fct_dump_journalfile()
		var_action = "null"
	elif var_action == "4":
		fct_xattr()
	elif var_action == "b": 
		var_action = "no_null"
	else: 
		print_red("\nPlease to choose 1, 2  or 3 ...\n")
		var_action = "null"

os.system('chmod -Rf 777 ' + dir_results)
os.system('chmod -Rf 777 ' + dir_results + "/*")