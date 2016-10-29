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
#FUNCTIONS
################################################
def usage():

    print_green("\n")
    print_green("Did anyone have access to your Mac during your dinner or party ?")
    print_green("")
    print_green_bold("==>" + sys.argv[0] + " checks that !\n")
    print_red("\n Options: ")
    print_red(" -h or --help >    to display this page")
    print_red(" -v or --verbose > more verbose, to display launched commands")
    print_red(" -d or --date >  to check only at this date (format:dd/mm)")
    print_red(" -t or --target_path >  to indicate the mounted Volume HFS to analyse (default is /)")
    print_red(" -l or --log_path >  to indicate the system and install logs path (default is /var/log/)")
    #print_red(" -s or --syslog_path >  to indicate the syslog logs path (default is /var/log/asl/)")
    print_red(" -b or --auditlog_path >  to indicate the audit logs path (default is /var/audit/)")
    print_red(" -L or --log_only > only log files to check\n")
    print_red(" Examples: \n  #" + sys.argv[0] + "\n  #" + sys.argv[0] + " -v\n  #" + sys.argv[0] + " -v -d 25/12\n  #for i in `seq 15 30`; do " + sys.argv[0] + " -d $i/6; done\n  #" + sys.argv[0] + " -l /Volumes/usb/log/\n  #" + sys.argv[0] + " -t /Volumes/osx -l /Volumes/osx/var/log -b /Volumes/osx/var/audit/\n")
    print_red(" Version: 0.2")
    print_red(" Author: sud0man/sud0man.blogspot.com\n")


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
    

def fct_system_log(path_log,pattern,arg_grep,last_grep):
    if os.path.exists(path_log.replace('.*','').replace('*','')):
        if arg_grep == "no_detail" : 
            cmd="zegrep '" + pattern + "' " +  path_log + "|grep -i '" + your_date_us + "'|awk '{print$1,$2,$3}' |cut -d : -f 2-" + last_grep 
        elif arg_grep == "all_detail" : 
            cmd="zegrep '" + pattern + "' " + path_log + "|grep -i '" + your_date_us + "'" + last_grep + "|cut -d : -f 2-"
        else: 
            cmd="zegrep " + arg_grep + " '" + pattern + "' " + path_log + "|grep -i '" + your_date_us + "'" + last_grep

        if debug_mode == 1 : print_debug("[DEBUG] "+ str(cmd))
        os.system(cmd)
    else : print (path_log + " does not exist.")


"""
def fct_audit_log(path_log_audit,pattern,arg_grep,grep_date,sed_pattern):
    if os.path.exists(path_log_audit):
        cmd="praudit -xn " + path_log_audit + "|egrep '" + pattern + "' " + arg_grep + "|grep -i '" + your_date_us + "' " + grep_date + "|sed '" + sed_pattern
        print cmd
        if debug_mode == 1 : print_debug("[DEBUG] "+ str(cmd))
        os.system(cmd)
    else : print (path_log_audit + " does not exist.")
"""

def fct_audit_log_line(path_log_audit,pattern):
    new_pipe =  "| awk -F, '{print $6\"; ACTION: \"$4\"; FROM:\"$10\"; INFO:\"$19\"; RES:\"$21}' | cut -d \" \" -f 2-"
    if os.path.exists(path_log_audit):
        cmd="praudit -l " + path_log_audit + "|egrep '" + pattern + "' |grep -i '" + your_date_us + "' " + new_pipe
        if debug_mode == 1 : print_debug("[DEBUG] "+ str(cmd))
        os.system(cmd)
    else : print (path_log_audit + " does not exist.")

"""
def fct_syslog_read(path_to_syslog,pattern):
    if os.path.isdir(path_to_syslog) :
        cmd="syslog -T " + timezone + " -F raw -f " + path_to_syslog + str(formated_date_point) + ".*|grep '" + pattern + "'|grep -i '" + your_date_us + "'|cut -d ] -f 2|sed -e 's/\ \[Time//g'"
        if debug_mode == 1 : print_debug("[DEBUG] "+ str(cmd))
        os.system(cmd)
    else : print (check_path + " does not exist.")
"""

def fct_stat_file(stat_file):
    if os.path.exists(path):
        cmd="stat -q -f \'%N %z %Sa\' " + target_path_arg + stat_file + "|grep -i '" + your_date_us + "'|grep " + your_year
        if debug_mode == 1 : print_debug("[DEBUG] "+ str(cmd))
        os.system(cmd)
    else : print (stat_file + " does not exist.")

def fct_stat_dir_access(path_dir_last_access,filter_pipe):
    if os.path.isdir(path_dir_last_access):
        cmd="stat -q -f \'%Sa %N\' '" + target_path_arg + path_dir_last_access + "'*|grep -i '" + your_date_us + "'|grep " + your_year + filter_pipe
        if debug_mode == 1 : print_debug("[DEBUG] "+ str(cmd))
        os.system(cmd)
    else : print (path_dir_last_access + " does not exist.")

def fct_stat_dir_modify(path_dir_last_modif,filter_pipe):
    if os.path.isdir(path_dir_last_modif):
        cmd="stat -q -f \'%Sm %N\' '" + target_path_arg + path_dir_last_modif + "'*|grep -i '" + your_date_us + "'|grep " + your_year + filter_pipe
        if debug_mode == 1 : print_debug("[DEBUG] "+ str(cmd))
        os.system(cmd)
    else : print (path_dir_last_modif + " does not exist.")

def fct_stat_file_modify(path_file_last_modif,filter_pipe):
    if os.path.isfile(path_file_last_modif):
        cmd="stat -q -f \'%Sm %N\' '" + target_path_arg + path_file_last_modif + "'|grep -i '" + your_date_us + "'|grep " + your_year + filter_pipe
        if debug_mode == 1 : print_debug("[DEBUG] "+ str(cmd))
        os.system(cmd)
    else : print (path_file_last_modif + " does not exist.")

def fct_stat_dir_create(path_dir_last_create,filter_pipe):
    if os.path.exists(path_dir_last_create):
        cmd="stat -q -f \'%SB %N\' '"  + target_path_arg + path_dir_last_create + "'*|grep -i '" + your_date_us + "'|grep " + your_year + filter_pipe
        if debug_mode == 1 : print_debug("[DEBUG] "+ str(cmd))
        os.system(cmd)
    else : print (path_dir_last_create + " does not exist.")


def fct_all_dump():

    #######################################################################################
    #######################################################################################
    print_green_bold("\n[]STARTUP ACTIVITIES ...")
    #######################################################################################
    print_green("[][]BOOT dates/hours")
    fct_system_log(path_log_system_all,"BOOT_TIME","all_detail","|awk '{print$1,$2,$3,$6}'")
    #######################################################################################
    print_green("[][]SHUTDOWN dates/hours")
    fct_system_log(path_log_system_all,"SHUTDOWN_TIME","all_detail","|awk '{print$1,$2,$3,$6}'")
    #######################################################################################
    #######################################################################################
    print_green("[][]REBOOT dates/hours (reboot => wih button, rebooted => with terminal)")
    fct_system_log(path_log_system_all,"reboot by|rebooted by","all_detail","|awk '{print$1,$2,$3,$6}'|sort -u")
    #######################################################################################
    print_green("[][]Hibernation dates/hours")
    fct_system_log(path_log_system_all,"hibernate_setup(0) took|PMScheduleWakeEventChooseBest|sleep images","no_detail","| sed 's/$/ : Hibernation/'|sort -u")
    #######################################################################################
    print_green("[][]Out of hibernation dates/hours")
    fct_system_log(path_log_system_all,"full wake promotion|Previous sleep|Wake reason","no_detail","| sed 's/$/ : Out of hibernation/'|sort -u")
    #fct_system_log(path_log_system_all,"Wake reason","no_detail","| sed 's/$/ : Out of hibernation/'")
    #fct_syslog_read(path_to_syslog,"Message Wake")


    #######################################################################################
    #######################################################################################
    print_green_bold("\n[]SESSION ACTIVITIES ...")
    #######################################################################################
    print_green("[][]Attempting to unlock session next to a boot")
    #fct_system_log(path_log_system_all,"The authtok is incorrect.","-B 9","| grep 'Got user'|awk '{print$1,$2,$3,$9,$10}'")
    fct_audit_log_line(path_log_audit,"Login Window login proceeding")
    fct_system_log(path_log_system_all,"Login Window login proceeding","no_detail","|sort -u| sed 's/$/ : Attempting to unlock session after the boot/'")
    #######################################################################################
    print_green("[][]Attempting to unlock session without success")
    print_green("      Authentication without success by su or sudo commands are also notified ...")
    #fct_system_log(path_log_system_all,"The authtok is incorrect.","-B 9","| grep 'Got user'|awk '{print$1,$2,$3,$9,$10}'")
    fct_audit_log_line(path_log_audit,"user authentication'|grep -v '_securityagent' | grep -i 'failure")
    #######################################################################################
    print_green("[][]Unlocked session with success")
    print_green("      Authentication with su or sudo commands are also notified ...")
    #fct_system_log(path_log_system_all,"Establishing credentials","-A 1","| grep 'Got user'|awk '{print$1,$2,$3,$9,$10}'")
    fct_audit_log_line(path_log_audit,"user authentication'|grep -i 'success")
    #######################################################################################
    print_green("[][]Locked session dates/hours")
    fct_system_log(path_log_system_all,'Application App:"loginwindow"',"no_detail","|sort -u| sed 's/$/ : Locked Session/'")
    #######################################################################################
    print_green("[][]Attempting to unlock session (Yes : if two occurence with the same time, No: if just one occurence)")
    print_green("      WARNING 1 : there are several occurences when an user account is created")
    print_green("      WARNING 2 : there is always one occurence for each user account just after the boot")
    fct_system_log(path_log_accountpol_all,"AuthenticationAllowed","all_detail","")
  
    #######################################################################################

    #######################################################################################
    #######################################################################################
    print_green_bold("\n[]PHYSICAL CONNECTION ACTIVITIES ...")
    #######################################################################################
    print_green("[][]USB plugged devices")
    fct_system_log(path_log_system_all,"USBMSC","all_detail","|awk '{print$1,$2,$3\" => New plugged USB Device - USBMSC Identifier: \"$9\", \"$10\"(vendor), \"$11\"(Device) - To identify the plugged device : external_bin/usb.ids or http://www.linux-usb.org/usb.ids\"}'")
    #######################################################################################
    print_green("[][]File system events(USB, mounting, etc.)")
    fct_system_log(path_log_system_all,"fsevents","all_detail","|grep Volumes")
    #######################################################################################
    print_green("[][]Firewire connections with another machine or storage media (activation of 'fw' interface)")
    fct_system_log(path_log_system_all,"fw","all_detail","| grep 'network changed'")
    #######################################################################################



    #######################################################################################
    #######################################################################################
    print_green_bold("\n[]ESCALATION PRIVILEGES ACTIVITIES ...")
    #######################################################################################
    
    #######################################################################################
    print_green("[][]Opened/Closed TTY terminals")
    fct_system_log(path_log_system_all,"ttys","all_detail","| egrep 'USER_PROCESS|DEAD_PROCESS'|sed -e 's/USER_PROCESS/OPENING TERMINAL/g' |sed -e 's/DEAD_PROCESS/CLOSING TERMINAL/g'| awk '{print $1,$2,$3,$6,$7,$9}'")
    #######################################################################################
    print_green("[][]ROOT commands executed with success")
    fct_system_log(path_log_system_all,"sudo\[","all_detail","")
    #alternative
     #fct_syslog_read("USER=root")
    #######################################################################################
    print_green("[][]Attempting to execute commands with SUDO without success")
    fct_system_log(path_log_system_all,"incorrect password attempts","all_detail","")
    #######################################################################################
    print_green("[][]User, password modification and creation")
    fct_audit_log_line(path_log_audit,"create user|modify password|delete user")
    #######################################################################################
    print_green("[][]System Privileges asking")
    fct_system_log(path_log_authd_all,"authenticated as user","-A 1","|cut -d : -f 2-")
    #######################################################################################


    #######################################################################################
    if logonly == 0:
        print_green_bold("\n[]APPLICATIONS ACTIVITIES ...")
    #######################################################################################
    #######################################################################################
        print_green("[][]Executed applications")
        print_green("[Recent App - last modif]")
        print_green("      WARNING : date files can be updated during the boot")
        fct_stat_dir_modify("/Users/" + username + "/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.ApplicationRecentDocuments/","| awk -F\"/\" '{print $1 $NF}'|sed 's/$/ : Executed App/'|sort")
        ######################################################################################
        print_green("[Recent App - last access]")
        print_green("      WARNING : date files can be updated during the boot")
        fct_stat_dir_access("/Users/" + username + "/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.ApplicationRecentDocuments/", "| awk -F\"/\" '{print $1 $NF}'|sed 's/$/ : Executed App/'|sort")
        ######################################################################################
        print_green("[Caches]")
        fct_stat_dir_access("/Users/" + username + "/Library/Caches/","|sed 's/$/ : Executed App/'|sort")
        #######################################################################################
        print_green("[][]Creation of reporter crash plist")
        fct_stat_dir_create("/Users/" + username + "/Library/Application Support/CrashReporter/","|sed 's/$/ : Executed App/'|sort")
    #######################################################################################        
        print_green("[][]Recording App in csstore : lsregister")
        cmd = "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -dump | egrep -i 'reg date' -B 25 -A 4 | grep -B 25 -A 4 '" + formated_date_slash + " " + h + "' |sed 's/$/ : Recorded App/'"
        if debug_mode == 1 : print_debug("[DEBUG] "+ str(cmd))
        os.system(cmd)
    #######################################################################################        
        print_green("[][]Logging app 3rd party")
        fct_stat_dir_modify("/Users/" + username + "/Library/Logs/","|sort")



    print_green("\n[][]Installed applications")
    #######################################################################################
    print_green("[Installation pkg : Install.log]")
    fct_system_log(path_log_install_all,"Installation","-A 1","|sed 's/$/ : Installed pkg/'")
    
    if logonly == 0:
    #######################################################################################
        print_green("[Installation pkg : InstallHistory.plist]")
        cmd = "cat /Library/Receipts/InstallHistory.plist | grep -A 7 '" + formated_date_tiret + "T" + h + "'|sed 's/$/ : Installed pkg/'"
        if debug_mode == 1 : print_debug("[DEBUG] "+ str(cmd))
        os.system(cmd)
    #######################################################################################
        print_green("[Installation (or new) pkg : /var/db/receipts]")
        fct_stat_dir_modify("/var/db/receipts/","|sed 's/$/ : Installed pkg/'|sort")
    #######################################################################################
        print_green("[Creation of Sandbox directory for App]")
        fct_stat_dir_modify("/Users/" + username + "/Library/Containers/","|sed 's/$/ : Installed App/'|sort")
    #######################################################################################


    #######################################################################################
    if logonly == 0:
        print_green_bold("\n[]PERSISTENCE ACTIVITIES ...")
    #######################################################################################
    #######################################################################################
        print_green("[][]Added or modified files (like trojan or malware App)")
        print_green("[Modified directories for persistence (birth date)]")
        for item in dir_persist:
            fct_stat_dir_create(item,"|sed 's/$/ : Directory modification/'")
        
        print_green("[Files for persistence (modif date)]")
        for item in file_persist:
            fct_stat_file_modify(item,"|sed 's/$/ : File creation or modification/'")


    #######################################################################################
    #######################################################################################
    print_green_bold("\n[]NETWORK ACTIVITIES ...")
    #######################################################################################
    print_green("[][]Ethernet/WiFI connections (activation of 'enX' interface)")
    print_green("[Activation of enX]")
    fct_system_log(path_log_system_all,"network changed","all_detail","")
    print_green("[Link Down and Up]")
    fct_system_log(path_log_system_all,"Link up|Link down","all_detail","")

    #######################################################################################
    if logonly == 0:
        print_green("[][]WiFI access points (last connection dates) / warning to the time zone")
        cmd="defaults read " + target_path_arg.replace(" ","\ ") + "/Library/Preferences/SystemConfiguration/com.apple.airport.preferences| sed 's|\./|`pwd`/|g' | sed 's|.plist||g'| grep 'LastConnected' -A 9 | grep -A 9 " + formated_date_tiret    
        if debug_mode == 1 : 
            print_debug("[DEBUG] " + str(cmd))
        os.system(cmd)

    print ("\n\n")



################################################################################################
#MAIN PROGRAM
################################################################################################
################################################################################################
################################################################################################
################################################################################################
################################################################################################
################################################################################################


#check privileges
your_priv=os.popen("id").read()
if "root" not in your_priv:
    print_red("Please to launch with root privileges !")
    sys.exit()


#check version
var_version=os.popen('uname -r | cut -d "." -f 1').read().strip("\n")
if int(var_version) < 13 : 
    print("Version not compatible, please to run program from Mavericks(10.9) or more")
    #archive .gz from Maveriks (bz2 before)
    sys.exit()



#current user
username = os.popen("echo $HOME |cut -f 3 -d '/'").read().strip("\n")

#timezone
timezone="UTC"

#default log paths
var_log = "/var/log"
path_to_syslog = "/var/log/asl/"
var_audit_log = "/var/audit"


#define directories path wherein you want to check if files or directories have been added (do not use ~ and put / to the end of line)
dir_persist=[
            "/System/Library/LaunchAgents/",
            "/Library/LaunchAgents/",
            "/Users/" + username + "/Library/LaunchAgents/",
            "/System/Library/LaunchDaemons/",
            "/Library/LaunchDaemons/",
            "/private/var/db/launchd.db/",
            "/System/Library/Extensions/",
            "/Library/Extensions/",
            "/System/Library/StartupItems/",
            "/Library/StartupItems/",
            "/Library/Spotlight/",
            "/Library/Internet Plug-Ins/"
        ]

file_persist=[
            "/Users/" + username + "/Library/Preferences/com.apple.loginitems.plist",
            "/etc/rc.common",
            "/Users/" + username + "/Library/Preferences/com.apple.loginwindow.plist"
        ]




#flags
debug_mode = 0
os_check = ""
option_d = ""
systemlog_path_arg = 0
syslog_path_arg = 0
auditlog_path_arg = 0
target_path_arg = ""
logonly = 0
interactive = 0


#Read arguments
try:
   opts, args = getopt.getopt(sys.argv[1:],"vd:hl:s:b:Lt:",["verbose","date","help","systemlog_path","syslog_path","auditlog_path","log_only","target_path"])
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

    if opt in ("-t", "--target_path"):
        print("herllo")
        if os.path.exists(arg):
            target_path_arg = arg
            print target_path_arg
        else :
            print(arg + " does not exist.\n")
            sys.exit()

usage()

if option_d == "":
    print_green("\nPress any key to launch interactive mode\n or type q to quit\n")
    select_method = raw_input("> ")

    if "q" in select_method or "Q" in select_method :
        sys.exit()  
    else:
        interactive = 1



#log path
path_log_accountpol_all = str(var_log) + "/accountpolicy.log*"
path_log_system_all = str(var_log) + "/system.log*"
path_log_install_all = str(var_log) + "/install.log"
path_log_authd_all = str(var_log) + "/authd.log*"
path_log_audit = str(var_audit_log) + "/current"
path_log_audit_archive = str(var_audit_log) + "/*"

#present year
your_year = str(datetime.date.today().year)


        
#if no option -d
if option_d == "" or interactive == 1:
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
formated_date_slash= your_month_special + "/" + your_day_special + "/" + your_year


#start hour has been specified
if start_hour != "":
    #your_date is modified with start_hour parameter
    for h in range(int(start_hour),int(stop_hour)+1):
        if len(str(h)) == 1:
            h="0" + str(h)
        print_red("\n+++  ACTIVITIES ON " + str(your_day_backup) + "/" + str(your_month_backup) + " FROM " + str(h) + ":00 TO " + str(h) + ":59  +++") 
        h = str(h) + ":"
        grep_hour="| grep '" + h + "'"
        #your_date="Jun 28 02:""
        your_date_us=your_date_backup_us + " " + h
        your_date_local=your_date_backup_local + " " + h

        your_date_us_revert = os.popen("echo '" + your_date_us + "'| awk -F ' ' '{print $2\" \"$1\" \"$3}'").read().strip('\n')
        your_date_local_revert = os.popen("echo '" + your_date_local + "'| awk -F ' ' '{print $2\" \"$1\" \"$3}'").read().strip('\n')

        fct_all_dump()

#start hour has not been specified (option -d or empty for your_hour)
else : 
    #your_date is not modified with hour
    your_date_us=your_date_backup_us
    your_date_local=your_date_backup_local

    your_date_us_revert = os.popen("echo '" + your_date_us + "'| awk -F ' ' '{print $2\" \"$1}'").read().strip('\n')
    your_date_local_revert= os.popen("echo '" + your_date_local + "'| awk -F ' ' '{print $2\" \"$1}'").read().strip('\n')
    print_red("\n+++  ACTIVITIES ON " + str(your_day_backup) + "/" + str(your_month_backup) + " FROM 00:00 TO 23:59  +++")
    h=""
    grep_hour=""

    fct_all_dump()

print_red("End of analysis")
