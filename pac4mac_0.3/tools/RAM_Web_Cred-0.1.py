#!/usr/bin/python
# -*- coding: iso-8859-15 -*-



#############################################################################
##                                                                         ##
## RAM_Web_Cred-0.1.py --- PoC to identity Web password into RAM image 	   ##
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



TabCibles=[
		#SOCIAL NETWORK
		{"name":"https://www.facebook.com",
		"cat":"SOCIAL NETWORK",
		"desc":"Identification des authentifiant de connexion sur Facebook.com",
		"signature":"email=([^&]+)&pass=([^&]+).*persistent=",
		"hasbeenfound":"0"
		},
		{"name":"https://www.linkedin.com",
		"cat":"SOCIAL NETWORK",
		"desc":"Identification des authentifiant de connexion sur Linkedin.com",
		"signature":"session_key=([^&]+)&session_password=([^&]+)",
		"hasbeenfound":"0"
		},
		{"name":"http://www.viadeo.com",
		"cat":"SOCIAL NETWORK",
		"desc":"Identification des authentifiant de connexion sur Viadeo.com",
		"signature":"&email=([^&]+)&password=([^&]+)&connexion=",
		"hasbeenfound":"0"
		},
		{"name":"https://twitter.com",
		"cat":"SOCIAL NETWORK",
		"desc":"Identification des authentifiant de connexion sur Twitter.com",
		"signature":"username_or_email%5D=(.+).*&session%5Bpassword%5D=([^&]+)",
		"hasbeenfound":"0"
		},
		#MAIL
		{"name":"https://mail.google.com",
		"cat":"MAIL",
		"desc":"Identification des authentifiant de connexion sur Google.com(mail)",
		"signature":"Email=([^&]+)&Passwd=([^&]+)",
		"hasbeenfound":"0"
		},
		{"name":"http://imp.free.fr",
		"cat":"MAIL",
		"desc":"Identification des authentifiant de connexion sur Free.fr(imp)",
		"signature":"mailbox=INBOX([^&]+)&imapuser=(.+)&passwd=([^&]+)",
		"hasbeenfound":"0"
		},
		{"name":"http://zimbra.free.fr",
		"cat":"MAIL",
		"desc":"Identification des authentifiant de connexion sur Free.fr(zimbra)",
		"signature":"login=([^&]+)&password=([^&]+)",
		"hasbeenfound":"0"
		},
		{"name":"http://vip.voila.fr",
		"cat":"MAIL",
		"desc":"Identification des authentifiant de connexion sur Voila.fr",
		"signature":"vip_ulo=([^&]+)&vip_upw=([^&]+)",
		"hasbeenfound":"0"
		},
		{"name":"http://id.orange.fr",
		"cat":"MAIL",
		"desc":"Identification des authentifiant de connexion sur Orange.fr",
		"signature":"credential=([^&]+)&pwd=([^&]+)",
		"hasbeenfound":"0"
		},
		{"name":"https://www.sfr.fr",
		"cat":"MAIL",
		"desc":"Identification des authentifiant de connexion sur Sfr.fr",
		"signature":"loginTicket=.*&username=([^&]+)&password=([^&]+)",
		"hasbeenfound":"0"
		},
		{"name":"https://www.espaceclient.bouyguestelecom.fr",
		"cat":"MAIL",
		"desc":"Identification des authentifiant de connexion sur Bouyguestelecom.fr",
		"signature":"_username=([^&]+)&j_password=([^&]+)",
		"hasbeenfound":"0"
		},
		{"name":"https://login.live.com",
		"cat":"MAIL",
		"desc":"Identification des authentifiant de connexion sur Hotmail.com",
		"signature":"login=([^&]+)&passwd=([^&]+)&type.*LoginOptions",
		"hasbeenfound":"0"
		},
		#E-COMMERCE
		{"name":"iTunes Apple Store",
		"cat":"E-COMMERCE",
		"desc":"Identification des authentifiant de connexion Apple Store via iTunes",
		"signature":"theAccountName=([^&]+)&theAccountPW=([^&]+)&",
		"hasbeenfound":"0"	
		},
		{"name":"https://signin.ebay.fr",
		"cat":"E-COMMERCE",
		"desc":"Identification des authentifiant de connexion sur Ebay.fr",
		"signature":"pageType.*userid=([^&]+)&pass=([^&]+)",
		"hasbeenfound":"0"	
		},
		{"name":"https://www.priceminister.com",
		"cat":"E-COMMERCE",
		"desc":"Identification des authentifiant de connexion sur Priceminister.com",
		"signature":"action=dologin&popup=.*&c=.*&rid=.*&login=([^&]+)&user_password=([^&]+)",
		"hasbeenfound":"0"	
		},
		{"name":"https://www.amazon.fr",
		"cat":"E-COMMERCE",
		"desc":"Identification des authentifiant de connexion sur Amazon.fr",
		"signature":"action=sign-in&protocol=.*&email=([^&]+)&password=([^&]+)",
		"hasbeenfound":"0"	
		},
		{"name":"https://clients.cdiscount.com",
		"cat":"E-COMMERCE",
		"desc":"Identification des authentifiant de connexion sur Cdiscount.com",
		"signature":"Mail=([^&]+)&.*vce1.*txtPassWord1=([^&]+)",
		"hasbeenfound":"0"	
		},
		{"name":"https://www.fnac.com",
		"cat":"E-COMMERCE",
		"desc":"Identification des authentifiant de connexion sur Fnac.com",
		"signature":"USEREMAIL=([^&]+)&USERPASSWORD=([^&]+)",
		"hasbeenfound":"0"	
		},
		{"name":"http://espace-client.voyages-sncf.com",
		"cat":"E-COMMERCE",
		"desc":"Identification des authentifiant de connexion sur Voyages-sncf.com(Espaceclient)",
		"signature":"login=([^&]+)&password=([^&]+)&CMD_signIn",
		"hasbeenfound":"0"	
		},
		{"name":"http://fr.vente-privee.com",
		"cat":"E-COMMERCE",
		"desc":"Identification des authentifiant de connexion sur Vente-privee.com",
		"signature":"txtEmail=([^&]+)&txtPassword=([^&]+)",
		"hasbeenfound":"0"	
		},
		{"name":"http://www.pixmania.com",
		"cat":"E-COMMERCE",
		"desc":"Identification des authentifiant de connexion sur Pixmania.com",
		"signature":"login=([^&]+)&password=([^&]+)&x.*moncompte",
		"hasbeenfound":"0"	
		},
		{"name":"http://client.rueducommerce.fr",
		"cat":"E-COMMERCE",
		"desc":"Identification des authentifiant de connexion sur Rueducommerce.fr",
		"signature":"AUT_LOGIN=([^&]+)&hasAccount=1&AUT_PASSWORD=([^&]+)",
		"hasbeenfound":"0"	
		},
		#BANQUE EN LIGNE
		{"name":"https://www.paris-enligne.credit-agricole.fr",
		"cat":"BANQUE",
		"desc":"Identification des authentifiant de connexion sur Crédit-Agricole.fr",
		"signature":"serieChiffresCode=([^&]+)&etapeIdentification=&numero=([^&]+)",
		"hasbeenfound":"0"	
		},
		{"name":"https://www.labanquepostale.fr",
		"cat":"BANQUE",
		"desc":"Identification des authentifiant de connexion sur Banque-postale.fr",
		"signature":"origin=particuliers&password=([^&]+)&cv=true&cvvs=&username=([^&]+)",
		"hasbeenfound":"0"	
		},
		{"name":"https://www.secure.bnpparibas.net",
		"cat":"BANQUE",
		"desc":"Identification des authentifiant de connexion sur Bnpparibas.net",
		"signature":"ch5=([^&]+)&ch1=([^&]+)",
		"hasbeenfound":"0"	
		},
		{"name":"https://www.professionnels.secure.societegenerale.fr",
		"cat":"BANQUE",
		"desc":"Identification des authentifiant de connexion sur la Société-Générale.fr(professionnels)",
		"signature":"USER=([^&]+)&CodSec=([^&]+)",
		"hasbeenfound":"0"	
		},
		{"name":"https://entreprises.societegenerale.fr",
		"cat":"BANQUE",
		"desc":"Identification des authentifiant de connexion sur la Société-Générale.fr(entretprises)",
		"signature":"xxx",
		"hasbeenfound":"0"	
		},
		{"name":"https://particuliers.societegenerale.fr",
		"cat":"BANQUE",
		"desc":"Identification des authentifiant de connexion sur la Société-Générale.fr(particuliers)",
		"signature":"xxx",
		"hasbeenfound":"0"	
		},
		{"name":"https://www.bred.fr",
		"cat":"BANQUE",
		"desc":"Identification des authentifiant de connexion sur Bred.fr",
		"signature":"typeDemande=ID&id=([^&]+)&pass=([^&]+)",
		"hasbeenfound":"0"	
		},
		{"name":"https://www.caisse-epargne.fr",
		"cat":"BANQUE",
		"desc":"Identification des authentifiant de connexion sur Caisse d'Epargne",
		"signature":"nuabbd=([^&]+)&ctx=.*&codconf=([^&]+)",
		"hasbeenfound":"0"	
		},
		{"name":"https://particuliers.secure.lcl.fr",
		"cat":"BANQUE",
		"desc":"Identification des authentifiant de connexion sur Lcl.fr",
		"signature":"agenceId.*&compteId=([^&]+)&CodeId=([^&]+)",
		"hasbeenfound":"0"	
		},
		{"name":"https://espaceclient.groupama.fr",
		"cat":"BANQUE",
		"desc":"Identification des authentifiant de connexion sur Groupama(espace client)",
		"signature":"LoginPortletFormID=([^&]+)&LoginPortletFormPassword1=([^&]+)",
		"hasbeenfound":"0"	
		},
		{"name":"https://www.hsbc.fr",
		"cat":"BANQUE",
		"desc":"Identification des authentifiant de connexion sur Hsbc.fr",
		"signature":"xxx",
		"hasbeenfound":"0"	
		},
		{"name":"https://www.cic.fr",
		"cat":"BANQUE",
		"desc":"Identification des authentifiant de connexion sur Cic.fr",
		"signature":"_cm_user=([^&]+)&_cm_pwd=([^&]+)",
		"hasbeenfound":"0"	
		}
		
		 ]


def afficheMenu(cibles):
	i = 1
	print_log("\nTarget :")
	for t in cibles:
		print_green(" %2d: %s" % (i, t["name"]))
		i+=1


def usage():
	print_log ("Usage: " + sys.argv[0] + " <RAM File in STRINGS format>\n")
	afficheMenu(TabCibles)
	sys.exit(1)


def search_string(index) :
  print_log ("Search credentials : " + TabCibles[index-1]["name"])

  #configuration du filtre via des expressions regulières afin d'identifier la chaîne d'authentification d'une cible 
  filtre=re.compile(TabCibles[index-1]["signature"],re.IGNORECASE)

  file=open(sys.argv[1],'r')
  #tant que la chaîne n'a pas été identifiée ou que le fichier n'a pas été entièrement analysé
  while 1:
    #lecture ligne par ligne du fichier
    ligne=file.readline()
    if ligne =="" : break
    ligne=ligne.rstrip('\n\r')
    try :
      res=filtre.search (ligne)
      print_green(" =>" + res.groups()[0]) #affichage login
      print_green(" =>" + res.groups()[1]) #affichage mot de passe
      #arrêt de la recherche via sortie de la boucle While si la chaîne a été identifiée
      break
    #login et mot de passe non trouvé
    except :
      pass


index = "null"

while index != "q":

	if len(sys.argv) < 2:
		usage()

	else : 
		afficheMenu(TabCibles)
		index=raw_input("\nChoice (666 for all, q to quit) : ")

	if index=="666" :
		file=open(sys.argv[1],'r')
		print_log ("Search all credentials : ")
	 	#tant que la chaîne n'a pas été identifiée ou que le fichier n'a pas été entièrement analysé
	 	while 1:
	    		#lecture ligne par ligne du fichier
	    		ligne=file.readline()
	    		if ligne =="" : break
	    		ligne=ligne.rstrip('\n\r')
			i = 1
			for t in TabCibles:
				try :
					filtre=re.compile(TabCibles[i-1]["signature"],re.IGNORECASE)      			
					res=filtre.search (ligne)
	     				print_green(" =>" + TabCibles[i-1]["name"] + ":" + res.groups()[0]) #affichage login
	      				print_green(" =>" + TabCibles[i-1]["name"] + ":" + res.groups()[1]) #affichage mot de passe
	      				#arrêt de la recherche via sortie de la boucle for si la chaîne a été identifiée
	      				break
	    				#login et mot de passe non trouvé
	    			except :
					i+=1
	      				pass
			

	elif index != "q": 
	  index=int(index.rstrip('\n\r'))
	  search_string(index)
