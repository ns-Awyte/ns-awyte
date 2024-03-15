import requests, json, base64, re
import sys

def self, host, username, password:
	self.host        = "awyte.goskope.com"
	self.baseurl     = "https://" + self.host
	self.username    = "awyte@netskope.com"
	self.password    = getpass.getpass()
	self.pwdChanged  = False
	self.token       = None
	self.session     = requests.Session() 
	self.request     = None
	self.headers     = {'X-Requested-With':'XMLHttpRequest', 'Content-Type':'application/json'}


print("version = " + self.version)
