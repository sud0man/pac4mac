#!/usr/bin/python
# -*- coding: iso-8859-15 -*-


#############################################################################
##                                                                         ##
## RAM_MacOSx_Cred-0.1.py --- PoC to identity MAC OS X system password into##
## RAM image 															   ##
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
##  Ref. https://code.google.com/p/fun-scripts/


import sys,os,re

###################################################################################################################
#print color
###################################################################################################################
def print_red(text) :
	print ('\033[22;31m' + text + '\033[0;m')
		
def print_in(text) :
	print ('\033[0;34m' + text + '\033[1;m')

def print_green(text) :
	print ('\033[22;32m' + text + '\033[0;m')

def print_log(text) :
	print ('\033[0;37m' + text + '\033[1;m')

	


TabCibles=[{
		"name":"Apple Credentials - login/password for locked session without autologon",
		"signature":"|grep -A 4 longname|grep -B 1 -A 2 managedUser",
		},
		{"name":"Apple Credentials - login/password for locked session with autologon",
		"signature":"|grep -B 2 -A 2 'buildin:authenticate,privileged' | grep admin -A 5 | grep UseeTags -B 1",
		},
		{"name":"Apple Credentials - login for locked session after startup",
		"signature":"|sed -ne 's_^.*<string>/Users/\\([^/]\\{1,20\}\\).*$_\\1_p'|sort -u",
		},		
		{"name":"Keychain login - password",
		"signature":"| grep -i 'login.keychain' -A 5 |grep -i 'tries' -A 4 | grep -i 'password' -A 1",
		},
		#{"name":"OpenVPN - passwords of private key",
		#"signature":"| A FAIRE"
		#},
		#{"name":"7Zip - passwords of encrypted files",
		#"signature":"| A FAIRE"
		#},
		{"name":"Mail - credentials",
		"signature":"|grep -A 10 'apple.mail.Account/hostname'"
		},
		{"name":"Mail - credentials (alternative)",
		"signature":"|grep -B 20 'ABMailRecent'"
		},
		{"name":"Mail - credentials (alternative 2)",
		"signature":"|grep -B 20 'ABMPerson'"
		},
		{"name":"Outlook client - domain credentials",
		"signature":"outlook"
		}
		
		 ]



def afficheMenu(cibles):
	i = 1
	print_log("\nTarget :")
	for t in cibles:
		print_green(" %2d: %s" % (i, t["name"]))
		i+=1


def usage():
	print_log("Usage: " + sys.argv[0] + " <RAM File in STRINGS format>\n")
	afficheMenu(TabCibles)
	sys.exit(1)


def search_string(index) :
  print_log("Search credentials : " + TabCibles[index-1]["name"])
  
  if TabCibles[index-1]["signature"] == "outlook" :
  	slash2="\\\\\\"
  	quote='"'
  	domain=raw_input("WINDOWS DOMAIN : ")
  	print_green("Found usernames for " + domain + " domain:")
  	#res_domain_user=os.popen("cat " + filename + "|sed -ne 's_^.*(\\{1,20\\}[^/])'").read()
  	#print_resgood(res_domain_user)
  	username=raw_input("WINDOWS USERNAME : ")
  	webmail_server=raw_input("WEBMAIL SERVER (ex:webmail.domain.com) : ")
  	
  	slash="\\\\\\"
  	TabCibles[index-1]["signature"]="|grep -i \"" + domain + slash + username + "\" -A 2 | grep -i " + webmail_server + " -B 2 -A 2"
  
  print_log("----------------------------")
  res=os.popen('cat ' + filename + TabCibles[index-1]["signature"]).read()
  print_green(res)
  print_log("----------------------------")

index = "null"

while index != "q":

	if len(sys.argv) < 2:
		usage()
	else : 
		afficheMenu(TabCibles)
		filename=sys.argv[1]
		index=raw_input("\nChoice (666 for all), q to quit : ")

	if index == "666":
		file=open(sys.argv[1],'r')
		i = 1
		for t in TabCibles:
			search_string(i)
			i+=1	

	elif index != "q": 
	  index=int(index.rstrip('\n\r'))
	  search_string(index)
