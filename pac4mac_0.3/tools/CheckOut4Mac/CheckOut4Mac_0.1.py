#!/usr/bin/python
# -*- coding: iso-8859-15 -*-

#############################################################################
##                                                                         ##
## CheckOut4Mac-0.1.py --- PoC to detect recent and malicious activies on  ##
## your Mac                                                                ##
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
##  Ref. https://code.google.com/p/checkout4mac/


import sys, os, getopt
import time
import os.path
import re
import locale
import datetime

################################################
#PLEASE TO DEFINE USER VARIABLES TO DEFINE !!!
################################################

# In first, you can disable control just with comment #. 
# All is into fct_all_dump() function.

# Secondly, you can custom a lot of dir and files 

#################################################

#variables

#current user
username = os.popen("echo $HOME |cut -f 3 -d '/'").read().strip("\n")

#timezone
timezone="utc+1"
#path where your applications are installed (.app)
path_applications = ["/Applications"]
maxdepth_find = "3"

#default log paths
var_log = "/var/log/"
path_to_syslog = "/var/log/asl/"
var_audit_log = "/var/audit/"

#define directories or files paths containing your secret informations (used to search if they have been read / do not use ~)
dir_secret_content=["/Users/" + username + "/.Trash" ,"/tmp"]

#define files paths if they have been modified (do not use ~)
dir_modify=["/Users/" + username + "/Library/Preferences/com.apple.loginitems.plist","/etc/passwd"]

#define directories path wherein you want to check if files or directories have been added (do not use ~)
dir_add=["/System/Library/XPCServices/","/System/Library/LaunchAgents/","/Library/LaunchAgents/","/Users/" + username + "/Library/LaunchAgents/","/System/Library/LaunchDaemons/","/Library/LaunchDaemons/","/private/var/db/launchd.db/"]

#define paths containing your file in format .mbox (do not use ~)
path_to_mailbox=["/Users/" + username + "/Library/Mail/V2/IMAP-sganama\@imap.gmail.com/NSC2013.mbox/"]




################################################
################################################


################################################
#FUNCTIONS
################################################
def usage():

    print_green("\n")
    print_green("Did anyone have access to your Mac during your dinner or party ?")
    print_green("")
    print_green_bold("==>" + sys.argv[0] + " checks that !\n")
    print_red("\n" + sys.argv[0] + " [options]\n\n Options: ")
    print_red(" -h | --help >    to display this page")
    print_red(" -v | --verbose > more verbose, to display launched commands")
    print_red(" -a | --all_os >  to launch all the checks for Lion AND Mountain Lion. Without this option, program identifies OS version automatically\n")
    print_red(" -d | --date >  to check only at this date (format:dd/mm)")
    print_red(" -l | --log_path >  to indicate the system and install logs path (default is /var/log/)")
    print_red(" -s | --syslog_path >  to indicate the syslog logs path (default is /var/log/asl/)")
    print_red(" -b | --auditlog_path >  to indicate the audit logs path (default is /var/audit/)")
    print_red(" -L | --log_only > only log files to check\n")
    print_red(" Examples: \n  #" + sys.argv[0] + "\n  #" + sys.argv[0] + " -av\n  #" + sys.argv[0] + " -v -d 25/12\n  #for i in `seq 15 30`; do " + sys.argv[0] + " -d $i/6; done\n  #" + sys.argv[0] + " -l /Volumes/usb/log/\n")
    print_red(" Version: 0.1")
    print_red(" Author: @sud0man/sud0man.blogspot.com\n")


def print_red(text) :
    print ('\033[22;31m' + text + '\033[0;m')

def print_red(text) :
    print ('\033[1;31m' + text + '\033[0;m')
        
def print_debug(text) :
    print ('\033[0;34m' + text + '\033[1;m')

def print_green(text) :
    print ('\033[22;32m' + text + '\033[0;m')

def print_green_bold(text) :
    print ('\033[1;32m' + text + '\033[0;m')

def print_log(text) :
    print ('\033[0;38m' + text + '\033[1;m')



def fct_check_date(your_date) :
    month_ok=0
    day_ok=0
    filter=re.compile('(.+)\/(.+)',re.IGNORECASE)

    if your_date == "":
        your_date = os.popen('date +"%d/%m"').read()

    if "/" not in your_date:
        print_red("Date is not valid.")
        return(month_ok,0,0,0,0,day_ok)

    res = filter.findall(str(your_date).strip('\n'))
    for i in res : 
        your_day_backup = int(i[0])
        your_month = int(i[1])
        your_month_backup = str(your_month)
        #your_month_backup=2
 
    if int(your_month_backup)<13:
        #convert month
        j=int(your_month_backup)-1
        #your_month_local=Fév
        your_month_local=locale.nl_langinfo(locale.ABMON_1+j)
        locale.setlocale(locale.LC_ALL, 'en_US')
        #your_month_us=Feb
        your_month_us=locale.nl_langinfo(locale.ABMON_1+j)
        locale.setlocale(locale.LC_ALL, '')
        month_ok=1

        #check day
        if int(your_day_backup) < 32:
            if len(str(your_day_backup)) == 1:
                your_day_backup = " " + str(your_day_backup)
            day_ok=1

        else : 
            print_red("Day is not valid.")
            return(month_ok,0,0,0,0,day_ok)
            
    else: 
        print_red("Month is not valid.")
        return(month_ok,0,0,0,0,day_ok)

    #return
    return(month_ok,your_month_us,your_month_local,str(your_month_backup),str(your_day_backup),day_ok)


def fct_define_date() :
    month_ok=0
    day_ok=0

    while (month_ok == 0) or (day_ok == 0):
        your_date=raw_input("\n[] When did you leave your hotel room ? (eg: 13/6 // empty for today) > ")
        month_ok,your_month_us,your_month_local,your_month_backup,your_day_backup,day_ok=fct_check_date(str(your_date))

    your_date_backup_us=str(your_month_us) + " " + str(your_day_backup)
    your_date_backup_local=str(your_month_local) + " " + str(your_day_backup)

    return (str(your_date_backup_us),str(your_date_backup_local),str(your_month_backup),str(your_month_us),str(your_month_local),str(your_day_backup))


def fct_define_hour() :
    hour_ok=0

    while (hour_ok == 0):
        start_hour=raw_input("\n[] At what time did you leave your hotel room (without minute // empty for all day long) ? > ")

        if start_hour=="" : 
            hour_ok=1
            stop_hour=""
        else : 
            if int(start_hour) < 24:
                hour_ok=1

                range_hour=raw_input("\n[] How long did you leave your hotel room (empty for 1h) ? > ")

                if range_hour == "" : range_hour = 1

                start_hour=start_hour.strip('\n')

                #define stop_hour
                stop_hour=start_hour

                for x in range(1,int(range_hour)):
                    stop_hour=int(start_hour)+x
                    if stop_hour == 24 :
                        raw_input("\n!! : Detection of analysis on several days, please to launch an occurrence of CheckOut4Mac per day.\n     Press Enter to continue")
                        stop_hour = 23
                        break
                break

            else :
                print_red("Hour is not valid.")
                hour_ok=0

    return (str(start_hour),str(stop_hour))
    

def fct_system_log(path_log,pattern,grep_file,post_grep,last_grep):
    if os.path.exists(path_log.replace('.*','')):
        if post_grep == "no_detail" : 
            cmd=grep_file + " -i '" + pattern + "' " +  path_log + "|" + path_grep + " -i '" + your_date_us + "'" + last_grep +"|awk '{print$1,$2,$3}'"
        elif post_grep == "all_detail" : 
            cmd=grep_file + " -i '" + pattern + "' " + path_log + "|" +  path_grep + " -i '" + your_date_us + "'" + last_grep
        else: 
            cmd=grep_file + " -i " + post_grep + " '" + pattern + "' " + path_log + "|" + path_grep + " -i '" + your_date_us + "'" + last_grep

        if debug_mode == 1 : print_debug("[DEBUG] "+ str(cmd))
        os.system(cmd)
    else : print (path_log + " does not exist.")


def fct_audit_log(path_log_audit,pattern,post_grep,grep_date,sed_pattern):
    if os.path.exists(path_log_audit):
        cmd="praudit -xn " + path_log_audit + "|egrep '" + pattern + "' " + post_grep + "|" + path_grep + " -i '" + your_date_us + "' " + grep_date + "|sed '" + sed_pattern + "'"

        if debug_mode == 1 : print_debug("[DEBUG] "+ str(cmd))
        os.system(cmd)
    else : print (path_log_audit + " does not exist.")


def fct_syslog_read(path_to_syslog,pattern):
    check_path=path_to_syslog + str(formated_date_point) + ".U0.G80.asl"
    if os.path.isfile(check_path) :
        cmd="syslog -T " + timezone + " -F raw -f " + path_to_syslog + str(formated_date_point) + ".*|" + path_grep + " '" + pattern + "'|" + path_grep + " -i '" + your_date_us + "'|cut -d ] -f 2|sed -e 's/\ \[Time//g'"
        if debug_mode == 1 : print_debug("[DEBUG] "+ str(cmd))
        os.system(cmd)
    else : print (check_path + " does not exist.")


def fct_stat_file(stat_file):
    if os.path.exists(path):
        cmd="stat -f \'%N %z %Sa\' " + stat_file + "|" + path_grep + " -i '" + your_date_us + "'|" + path_grep + " " + your_year
        if debug_mode == 1 : print_debug("[DEBUG] "+ str(cmd))
        os.system(cmd)
    else : print (stat_file + " does not exist.")

def fct_stat_dir_N1(path_dir,pattern_egrep):
    if os.path.exists(path_dir):
        cmd="stat -f \'%N %z %Sa\' " + path_dir + "/*|" + path_grep + " -i '" + your_date_us + "'|" + path_grep + " " + your_year + "|egrep -i '" + pattern_egrep + "'" 
        if debug_mode == 1 : print_debug("[DEBUG] "+ str(cmd))
        os.system(cmd)
    else : print (path_dir + " does not exist.")


def fct_stat_dir_access(path_dir_last_access,name_filter):
    for path in path_dir_last_access:
        if os.path.isfile(path.replace("\@","@")) or os.path.isdir(path.replace("\@","@")):
            cmd=path_find + " " + path + " -type f " + name_filter + " -exec stat -f \'%Sa %N\' \'{}\' + |" + path_grep + " -i '" + your_date_us + "'|grep " + your_year
            if debug_mode == 1 : print_debug("[DEBUG] "+ str(cmd))
            os.system(cmd)
        else : print (path + " does not exist.")

def fct_stat_dir_modify(path_dir_last_modif):
    for path in path_dir_last_modif:
        if os.path.isfile(path) or os.path.isdir(path):
            cmd=path_find + " " + path + " -type f -exec stat -f \'%Sm %N\' \'{}\' + |" + path_grep + " -i '" + your_date_us + "'|grep " + your_year
            if debug_mode == 1 : print_debug("[DEBUG] "+ str(cmd))
            os.system(cmd)
        else : print (path + " does not exist.")

def fct_stat_dir_create(path_dir_last_create):
    for path in path_dir_last_create:
        if os.path.exists(path):
            cmd=path_find + " " + path + " -type f -exec stat -f \'%SB %N\' \'{}\' + |" + path_grep + " -i '" + your_date_us + "'|grep " + your_year
            if debug_mode == 1 : print_debug("[DEBUG] "+ str(cmd))
            os.system(cmd)
        else : print (path + " does not exist.")


def fct_last_access_ls(path_dir,date_egrep,pattern_egrep):
    if os.path.exists(path_dir):
        cmd="ls -lu " + path_dir + "|egrep -i '" + date_egrep + "'|egrep '" + pattern_egrep + "'| awk '{print $7,$6,$8,$9}'"
        if debug_mode == 1 : print_debug("[DEBUG] "+ str(cmd))
        os.system(cmd)
    else : print (path_dir + " does not exist.")


def fct_all_dump():
    #######################################################################################
    #######################################################################################
    print_green_bold("\n[]STARTUP ACTIVITIES ...")
    #######################################################################################
    print_green("[][]Startup dates/hours")
    if os_check == "a" : print("[On Lion and Mountain Lion]")
    fct_system_log(path_log_system,"BOOT_TIME",path_grep,"no_detail","")
    fct_system_log(path_log_system_archive,"BOOT_TIME",path_bzgrep,"no_detail","")
    #######################################################################################
    print_green("[][]Stopping dates/hours")
    if os_check == "a" : print("[On Lion and Mountain Lion]")
    fct_system_log(path_log_system,"SHUTDOWN_TIME",path_grep,"no_detail","")
    fct_system_log(path_log_system_archive,"SHUTDOWN_TIME",path_bzgrep,"no_detail","")
    #######################################################################################
    print_green("[][]Hibernation dates/hours")
    if os_check == "a" or os_check == "m" :
        if os_check == "a" : print("[On Mountain Lion]")
        fct_system_log(path_log_system,"hibernate_setup(0) took",path_grep,"no_detail","")
        fct_system_log(path_log_system_archive,"hibernate_setup(0) took",path_bzgrep,"no_detail","")
    if os_check == "a" or os_check == "l" :
        if os_check == "a" : print("[On Lion]")
        fct_system_log(path_log_system,"PMScheduleWakeEventChooseBest",path_grep,"no_detail","")
        fct_system_log(path_log_system_archive,"PMScheduleWakeEventChooseBest",path_bzgrep,"no_detail","")
    #######################################################################################
    print_green("[][]Out of hibernation dates/hours")
    if os_check == "a" or os_check == "m" :
        if os_check == "a" : print("[On Mountain Lion]")
        fct_system_log(path_log_system,"Wake reason",path_grep,"no_detail","")
        fct_system_log(path_log_system_archive,"Wake reason",path_bzgrep,"no_detail","")
    if os_check == "a" or os_check == "l" :
        if os_check == "a" : print("[On Lion]")
        fct_syslog_read(path_to_syslog,"Message Wake")


    #######################################################################################
    #######################################################################################
    print_green_bold("\n[]SESSION ACTIVITIES ...")
    #######################################################################################
    print_green("[][]Locked session dates/hours")
    if os_check == "a" or os_check == "m" :
        if os_check == "a" : print("[On Mountain Lion]")
        fct_system_log(path_log_system,'Application App:"loginwindow"',path_grep,"no_detail","")
        fct_system_log(path_log_system_archive,'Application App:"loginwindow"',path_bzgrep,"no_detail","")
    if os_check == "a" or os_check == "l" :
        if os_check == "a" : print("[On Lion]")
        fct_system_log(path_log_windowserver,"loginwindow",path_bzgrep,"no_detail","")
    #######################################################################################
    print_green("[][]Attempt to unlock session without success")
    if os_check == "a" or os_check == "m" :
        if os_check == "a" : print("[On Mountain Lion]")
        fct_system_log(path_log_system,"The authtok is incorrect.",path_grep,"-B 9","|" + path_grep + " 'Got user'|awk '{print$1,$2,$3,$9,$10}'")
        fct_system_log(path_log_system_archive,"The authtok is incorrect.",path_bzgrep,"-B 9","|" + path_grep + " 'Got user'|awk '{print$1,$2,$3,$9,$10}'")
    if os_check == "a" or os_check == "l" :
        if os_check == "a" : print("[On Lion]")
        fct_system_log(path_log_security,"The authtok is incorrect.",path_grep,"-B 9","|" + path_grep + " 'Got user'|awk '{print$1,$2,$3,$9,$10}'")
        fct_system_log(path_log_security_archive,"The authtok is incorrect.",path_bzgrep,"-B 9","|" + path_grep + " 'Got user'|awk '{print$1,$2,$3,$9,$10}'")
        #alternative
        #sed_pattern='s/\&apos\;/\"/g'
        #fct_audit_log("user authentication", "-A 3 | grep 'failure' -B 4", "-A 3", sed_pattern)
    #######################################################################################
    print_green("[][]Unlocked session with success")
    if os_check == "a" or os_check == "m" :
        if os_check == "a" : print("[On Mountain Lion]")
        fct_system_log(path_log_system,"Establishing credentials",path_grep,"-A 1","|" + path_grep + " 'Got user'|awk '{print$1,$2,$3,$9,$10}'")
        fct_system_log(path_log_system_archive,"Establishing credentials",path_bzgrep,"-A 1","|" + path_grep + " 'Got user'|awk '{print$1,$2,$3,$9,$10}'")
    if os_check == "a" or os_check == "l" :
        if os_check == "a" : print("[On Lion]")
        fct_system_log(path_log_security,"Establishing credentials",path_grep,"-A 1","|" + path_grep + " 'Got user'|awk '{print$1,$2,$3,$9,$10}'")
        fct_system_log(path_log_security_archive,"Establishing credentials",path_bzgrep,"-A 1","|" + path_grep + " 'Got user'|awk '{print$1,$2,$3,$9,$10}'")
        #alternative
        #sed_pattern='s/\&apos\;/\"/g'
        #fct_audit_log("user authentication", "-A 3 | grep 'success' -B 4","-A 3", sed_pattern)

        
    #######################################################################################
    #######################################################################################
    print_green_bold("\n[]PHYSICAL CONNECTION ACTIVITIES ...")
    #######################################################################################
    if logonly == 0:
        print_green("[][]USB connections (loaded USB extensions)")
        if os_check == "a" or os_check == "m" :
            if os_check == "a" : print("[On Mountain Lion]")
            fct_stat_dir_N1("/System/Library/Extensions","IOUSBFamily.kext|IOUSBMassStorageClass.kext")
            #fct_last_access_ls("/System/Library/Extensions/",your_date_local_revert + "|" + your_date_us_revert,"IOUSBFamily.kext|IOUSBMassStorageClass.kext")
        if os_check == "a" or os_check == "l" :
            if os_check == "a" : print("[On Lion]")
            fct_last_access_ls("/System/Library/Extensions/",your_date_local + "|" + your_date_us,"IOUSBFamily.kext|IOUSBMassStorageClass.kext")
    #######################################################################################
    print_green("[][]USB plugged devices")
    if os_check == "a" or os_check == "m" :
        if os_check == "a" : print("[On Mountain Lion]")
        fct_system_log(path_log_system,"USBMSC",path_grep,"all_detail","|awk '{print$1,$2,$3\" => New plugged USB Device - USBMSC Identifier: \"$10\"(vendor)\",$11\"(Device) - To identify the plugged device : external_bin/usb.ids or http://www.linux-usb.org/usb.ids\"}'")
        fct_system_log(path_log_system_archive,"USBMSC",path_bzgrep,"all_detail","|awk '{print$1,$2,$3\" => New plugged USB Device - USBMSC Identifier: \"$10\"(vendor)\",$11\"(Device) - To identify the plugged device : external/usb.ids or http://www.linux-usb.org/usb.ids\"}'")
    if os_check == "a" or os_check == "l" :
        if os_check == "a" : print("[On Lion]")
        fct_system_log(path_log_kernel,"USBMSC",path_grep,"all_detail","|awk '{print$1,$2,$3\" => New plugged USB Device - USBMSC Identifier: \"$10\"(vendor)\",$11\"(Device) - To identify the plugged device : external_bin/usb.ids or http://www.linux-usb.org/usb.ids\"}'")
        fct_system_log(path_log_kernel_archive,"USBMSC",path_bzgrep,"all_detail","|awk '{print$1,$2,$3\" => New plugged USB Device - USBMSC Identifier: \"$10\"(vendor)\",$11\"(Device) - To identify the plugged device : external/usb.ids or http://www.linux-usb.org/usb.ids\"}'")
    #######################################################################################
    print_green("[][]File system events(USB, mounting, etc.)")
    if os_check == "a" : print("[On Lion and Mountain Lion]")
    fct_system_log(path_log_system,"fsevents",path_grep,"all_detail","")
    fct_system_log(path_log_system_archive,"fsevents",path_bzgrep,"all_detail","")
    #######################################################################################
    if logonly == 0:
        print_green("[][]Firewire connections with another machine or storage media (loaded Firewire extensions)")
        if os_check == "a" or os_check == "m" :
            if os_check == "a" : print("[On Mountain Lion]")
            fct_last_access_ls("/System/Library/Extensions/",your_date_local_revert + "|" + your_date_us_revert,"IOFireWireFamily.kext|IOFireWireIP.kext")
        if os_check == "a" or os_check == "l" :
            if os_check == "a" : print("[On Lion]")
            fct_last_access_ls("/System/Library/Extensions/",your_date_local + "|" + your_date_us,"IOFireWireFamily.kext|IOFireWireIP.kext")
    #######################################################################################
    print_green("[][]Firewire connections with another machine or storage media (activation of 'fw' interface)")
    if os_check == "a" : print("[On Lion and Mountain Lion]")
    fct_system_log(path_log_system,"fw",path_grep,"no_detail","|" + path_grep + " 'network changed'")
    fct_system_log(path_log_system_archive,"fw",path_bzgrep,"no_detail","|" + path_grep + " 'network changed'")
    #######################################################################################
    if logonly == 0:
        print_green("[][]Firewire connections to dump RAM (loaded extensions IOFireWireSBP2/iPodDriver) just a supposition")
        if os_check == "a" or os_check == "m" :
            if os_check == "a" : print("[On Mountain Lion]")
            #fct_stat_file("/System/Library/Extensions/iPodDriver.kext")
            fct_last_access_ls("/System/Library/Extensions/",your_date_local_revert + "|" + your_date_us_revert,"iPodDriver.kext|IOFireWireSBP2.kext")
        if os_check == "a" or os_check == "l" :
            if os_check == "a" : print("[On Lion]")
            fct_last_access_ls("/System/Library/Extensions/",your_date_local + "|" + your_date_us,"iPodDriver.kext|IOFireWireSBP2.kext")


    #######################################################################################
    #######################################################################################
    print_green_bold("\n[]ESCALATION PRIVILEGES ACTIVITIES ...")
    #######################################################################################
    
    #######################################################################################
    print_green("[][]Opened/Closed TTY terminals")
    if os_check == "a" : print("[On Lion and Mountain Lion]")
    fct_system_log(path_log_system,"ttys",path_grep,"all_detail","| egrep 'USER_PROCESS|DEAD_PROCESS'|sed -e 's/USER_PROCESS/OPENING TERMINAL/g' |sed -e 's/DEAD_PROCESS/CLOSING TERMINAL/g'| awk '{print $1,$2,$3,$6,$7,$9}'")
    fct_system_log(path_log_system_archive,"ttys",path_bzgrep,"all_detail","| egrep 'USER_PROCESS|DEAD_PROCESS'|sed -e 's/USER_PROCESS/OPENING TERMINAL/g' |sed -e 's/DEAD_PROCESS/CLOSING TERMINAL/g'| awk '{print $1,$2,$3,$6,$7,$9}'")
    #######################################################################################
    print_green("[][]ROOT commands executed with success")
    if os_check == "a" or os_check == "m" :
        if os_check == "a" : print("[On Mountain Lion]")
        fct_system_log(path_log_system,"sudo\[",path_grep,"all_detail","")
        fct_system_log(path_log_system_archive,"sudo\[",path_grep,"all_detail","")
    if os_check == "a" or os_check == "l" : 
        if os_check == "a" : print("[On Lion]")
        fct_system_log(path_log_security,"sudo\[",path_grep,"all_detail","")
        fct_system_log(path_log_security_archive,"sudo\[",path_bzgrep,"all_detail","")
        #alternative
        #fct_syslog_read("USER=root")
    #######################################################################################
    print_green("[][]Attempt to execute commands with SUDO without success")
    if os_check == "a" or os_check == "m" :
        if os_check == "a" : print("[On Mountain Lion]")
        fct_system_log(path_log_system,"incorrect password attempts",path_grep,"all_detail","")
        fct_system_log(path_log_system_archive,"incorrect password attempts",path_bzgrep,"all_detail","")
    if os_check == "a" or os_check == "l" : 
        if os_check == "a" : print("[On Lion]")
        fct_system_log(path_log_security,"incorrect password attempts",path_grep,"all_detail","")
        fct_system_log(path_log_security_archive,"incorrect password attempts",path_bzgrep,"all_detail","")
    #######################################################################################
    print_green("[][]User, password modification and creation")
    if os_check == "a" : print("[On Lion and Mountain Lion]")
    sed_pattern='s/\&apos\;/\"/g'
    fct_audit_log(path_log_audit,"create user|modify password|delete user","-A 3", "-A 3", sed_pattern)
    

    #######################################################################################
    #######################################################################################
    if logonly == 0:
        print_green_bold("\n[]APPLICATIONS ACTIVITIES ...")
    #######################################################################################
    
    #######################################################################################
        print_green("[][]Opened applications (last access dates)")
        if os_check == "a" or os_check == "m" : 
            if os_check == "a" : print("[On Mountain Lion]")
            for i in path_applications:
                cmd = "ls -lshtr /Users/" + username + "/Library/Caches/|egrep  -i '" + your_date_local_revert + "|" + your_date_us_revert + "'|awk '{print $7\" \"$8\" \"$9\" \"$10}'"
                #cmd=path_find + " " + i + " -maxdepth " + maxdepth_find + " -type f -exec ls -lu {} \; |" + path_grep + " Info.plist |egrep  -i '" + your_date_local_revert + "|" + your_date_us_revert + "'|grep -v root|awk '{$7=\"\"}1'"
                if debug_mode == 1 : print_debug("[DEBUG] "+ str(cmd))
                os.system(cmd)
        if os_check == "a" or os_check == "l" :
            if os_check == "a" : print("[On Lion]")
            for i in path_applications:
                cmd = "ls -lshtr /Users/" + username + "/Library/Caches/|egrep  -i '" + your_date_local + "|" + your_date_us + "'|awk '{print $7\" \"$8\" \"$9\" \"$10}'"
                #cmd=path_find + " " + i + " -maxdepth " + maxdepth_find + " -type f -exec ls -lu {} \; |" + path_grep + " Info.plist|egrep -i '" + your_date_local + "|" + your_date_us + "'|grep -v root|awk '{$7=\"\"}1'"
                if debug_mode == 1 : print_debug("[DEBUG] "+ str(cmd))
                os.system(cmd)
    #######################################################################################


    #######################################################################################
    #######################################################################################
    if logonly == 0:
        print_green_bold("\n[]FILES ACTIVITIES ...")
    #######################################################################################
        #######################################################################################
        print_green("[][]Modified files (like autorun App, LaunchAgents or LaunchDaemons)")
        if os_check == "a" : print("[On Lion and Mountain Lion]")
        fct_stat_dir_modify(dir_modify)
        #######################################################################################
        print_green("[][]Added files (like trojan or malware App)")
        if os_check == "a" : print("[On Lion and Mountain Lion]")
        fct_stat_dir_create(dir_add)
        #######################################################################################
        print_green("[][]Accessed files (like your secret files)")
        if os_check == "a" : print("[On Lion and Mountain Lion]")
        fct_stat_dir_access(dir_secret_content,"")
        #######################################################################################
        print_green("[][]Accessed Mails (last access dates) / please to use command << open >> to read mbox files")
        if os_check == "a" : print("[On Lion and Mountain Lion]")
        fct_stat_dir_access(path_to_mailbox,"-name *.emlx")
        #######################################################################################

    #######################################################################################
    #######################################################################################
    print_green_bold("\n[]NETWORK ACTIVITIES ...")
    #######################################################################################
    print_green("[][]Ethernet/WiFI connections (activation of 'enX' interface)")
    if os_check == "a" or os_check == "m" : 
        if os_check == "a" : print("[On Mountain Lion]")
        fct_system_log(path_log_system,"en",path_grep,"all_detail","|" + path_grep + " 'network changed'")
        fct_system_log(path_log_system_archive,"en",path_bzgrep,"all_detail","|" + path_grep + " 'network changed'")
    if logonly == 0:
        if os_check == "a" or os_check == "l" :
            if os_check == "a" : print("[On Lion]")
            cmd="egrep -i 'frequent transitions|network configuration changed' " + path_log_system + "|" + path_grep + " -i '" + your_date_us + "'"
            if debug_mode == 1 : print_debug("[DEBUG] " + str(cmd))
            os.system(cmd)
            cmd="bzegrep -i 'frequent transitions|network configuration changed' " + path_log_system_archive + "|" + path_grep + " -i '" + your_date_us + "'"
            if debug_mode == 1 : print_debug("[DEBUG] " + str(cmd))
            os.system(cmd)
    #######################################################################################
    if logonly == 0:
        print_green("[][]WiFI access points (last connection dates) / warning to the time zone")
        cmd="defaults read /Library/Preferences/SystemConfiguration/com.apple.airport.preferences| sed 's|\./|`pwd`/|g' | sed 's|.plist||g'|" + path_grep + " 'LastConnected' -A 3 |" + path_grep + " -A 3 " + formated_date_tiret
        if debug_mode == 1 : 
            print("[On Lion and Mountain Lion]")
            print_debug("[DEBUG] " + str(cmd))
        os.system(cmd)

    print ("\n\n")



################################################################################################
#MAIN PROGRAM
################################################################################################


debug_mode = 0
os_check = ""
option_d = ""
systemlog_path_arg = 0
syslog_path_arg = 0
auditlog_path_arg = 0
logonly = 0


your_priv=os.popen("id").read()
if "root" not in your_priv:
    print_red("Please to launch with root privileges !")
    sys.exit()

try:
   opts, args = getopt.getopt(sys.argv[1:],"avd:hl:s:b:L",["all_os","verbose","date","help","systemlog_path","syslog_path","auditlog_path","log_only"])
except getopt.GetoptError as err:
  print str(err)
  usage()
  sys.exit(2)
for opt,arg in opts:
    if opt in ("-h", "--help"):
        usage()
        sys.exit()
    if opt in ("-v", "--verbose"):
        debug_mode = 1 
    if opt in ("-a", "--all_os"):
        os_check = "a"
    if opt in ("-d", "--date"):
        option_d=arg
    if opt in ("-l", "--systemlog_path"):
        if os.path.exists(arg) : 
            systemlog_path_arg = 1
            var_log = arg
        else : 
            print(arg + " does not exist.\n")
            sys.exit()
    if opt in ("-s", "--syslog_path"):
        if os.path.exists(arg) : 
            syslog_path_arg = 1
            path_to_syslog = arg + "/"
        else : 
            print(arg + " does not exist.\n")
            sys.exit()
    if opt in ("-b", "--auditlog_path"):
        if os.path.exists(arg) : 
            auditlog_path_arg = 1
            var_audit_log = arg
        else : 
            print(arg + " does not exist.\n")
            sys.exit()
    if opt in ("-L", "--log_only"):
        logonly = 1





#log path
path_log_system = str(var_log) + "/system.log"
path_log_system_archive = str(var_log) + "/system.log.*"

path_log_security = str(var_log) + "/secure.log"
path_log_security_archive = str(var_log) + "/secure.log.*"

path_log_install = str(var_log) + "/install.log"
path_log_install_archive = str(var_log) + "/install.log.*"

path_log_windowserver = str(var_log) + "/windowserver.log"

path_log_audit = str(var_audit_log) + "/current"
path_log_audit_archive = str(var_audit_log) + "/*"

path_log_kernel = str(var_log) + "/kernel.log"
path_log_kernel_archive = str(var_log) + "/kernel.log.*"

#present year
your_year = str(datetime.date.today().year)


if os_check != "a":
    var_version=os.popen('uname -r | cut -d "." -f 1').read().strip("\n")
    if var_version == "12" : 
        os_check="m" #moutain
        path_grep="/usr/bin/grep"
        path_bzgrep="/usr/bin/bzgrep"
        path_find="/usr/bin/find"
    elif var_version == "11" : 
        os_check="l" #lion
        path_grep="/usr/bin/grep"
        path_bzgrep="/usr/bin/bzgrep"
        path_find="/usr/bin/find"
    else : 
        os_check="a" #lion and moutain
        path_grep="/usr/bin/grep"
        path_bzgrep="/usr/bin/bzgrep"
        path_find="/usr/bin/find"
else : 
    path_grep="/usr/bin/grep"
    path_bzgrep="/usr/bin/bzgrep"
    path_find="/usr/bin/find"
        
#if no option -d
if option_d =="":
    os.system("clear")
    print_red("\n")
    print_red("Did anyone have access to your Mac during your dinner or party ?")
    print_red("          ")
    print_red("                  ")
    action=raw_input("\n                 Press Enter to verify (q to quit) \n")

    if action == "q" : sys.exit()

    your_date_backup_us,your_date_backup_local,your_month_backup,your_month_us,your_month_local,your_day_backup=fct_define_date()
    #your_month_us="Jun"
    #your_month_local="Jui" #if language is FR
    #your_date_backup_us="Jun 28"
    #your_month_backup="06"
    #your_day_backup="28"
    start_hour,stop_hour=fct_define_hour()
    #start_hour=9
    #stop_hour=12

#if option -d
else :
    your_date=option_d
    month_ok,your_month_us,your_month_local,your_month_backup,your_day_backup,day_ok=fct_check_date(str(your_date))
    your_date_backup_us=str(your_month_us) + " " + str(your_day_backup)
    your_date_backup_local=str(your_month_local) + " " + str(your_day_backup)
    #no start_hour
    start_hour=""

#special_date  
if len(your_month_backup) == 1 : your_month_special = "0" + your_month_backup
else : your_month_special = your_month_backup 
if len(your_day_backup.strip('\ ')) == 1 : your_day_special = "0" + your_day_backup.strip('\ ')
else : your_day_special = your_day_backup
formated_date_point=your_year + "." + your_month_special + "." + your_day_special
formated_date_tiret=your_year + "-" + your_month_special + "-" + your_day_special


#start hour has been specified
if start_hour != "":
    #your_date is modified with start_hour parameter
    for h in range(int(start_hour),int(stop_hour)+1):
        if len(str(h)) == 1:
            h="0" + str(h)
        print_red("\n+++  ACTIVITIES ON " + str(your_day_backup) + "/" + str(your_month_backup) + " FROM " + str(h) + ":00 TO " + str(h) + ":59  +++") 
        h = " " + str(h) + ":"
        grep_hour="| " + path_grep + " '" + h + "'"
        #your_date="Jun 28 02:""
        your_date_us=your_date_backup_us + h
        your_date_local=your_date_backup_local + h


        #to check /System/Library/ on Lion
        '''
        if len(str(int(your_day_backup))) == 1 :
            your_date_local_system = os.popen("echo '" + your_date_local + "'|sed -e 's/\ \ /\ /g'").read().strip('\n')
            your_date_us_system = os.popen("echo '" + your_date_us + "'|sed -e 's/\ \ /\ /g'").read().strip('\n')
        '''
        your_date_us_revert = os.popen("echo '" + your_date_us + "'| awk -F ' ' '{print $2\" \"$1\" \"$3}'").read().strip('\n')
        your_date_local_revert = os.popen("echo '" + your_date_local + "'| awk -F ' ' '{print $2\" \"$1\" \"$3}'").read().strip('\n')

        fct_all_dump()

#start hour has not been specified (option -d or empty for your_hour)
else : 
    #your_date is not modified with hour
    your_date_us=your_date_backup_us
    your_date_local=your_date_backup_local

    #to check /System/Library/ on Lion
    '''
    if len(str(int(your_day_backup))) == 1 :
        your_date_local_system = os.popen("echo '" + your_date_local + "'|sed -e 's/\ \ /\ /g'").read().strip('\n')
        your_date_us_system = os.popen("echo '" + your_date_us + "'|sed -e 's/\ \ /\ /g'").read().strip('\n')
    '''
    your_date_us_revert = os.popen("echo '" + your_date_us + "'| awk -F ' ' '{print $2\" \"$1}'").read().strip('\n')
    your_date_local_revert= os.popen("echo '" + your_date_local + "'| awk -F ' ' '{print $2\" \"$1}'").read().strip('\n')
    print_red("\n+++  ACTIVITIES ON " + str(your_day_backup) + "/" + str(your_month_backup) + " FROM 00:00 TO 23:59  +++")
    grep_hour=""

    fct_all_dump()

raw_input("End of analysis, press any key to continue ...")
