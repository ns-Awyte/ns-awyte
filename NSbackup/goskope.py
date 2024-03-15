import requests, json, base64, re
from pprint import pprint
from bs4 import BeautifulSoup

class Auth:
	def __init__(self, host, username, password, newPassword=None):
		self.host        = host
		self.baseurl     = "https://" + self.host
		self.username    = username
		self.password    = password
		self.newPassword = newPassword
		self.pwdChanged  = False
		self.token       = None
		self.session     = requests.Session() 
		self.request     = None
		self.headers     = {'X-Requested-With':'XMLHttpRequest', 'Content-Type':'application/json'}

	### Legacy function for tenant login
	def login(self):
		return self.loginV3()
		# if self.version >= "98.0.0.0":
		# 	return self.loginV3()
		# elif self.version >= "97.0.0.0":
		# 	return self.loginV2()
		# else:
		# 	return self.loginV1()

	### Login for tenants with version >= R98
	def loginV3(self):
		print("called loginV3")

		if self.token is None:
			print("no token set, fetching one now")
			self.gettoken()

		data = {'username':self.username, 'password':self.password, 'token':self.token, 'local_login':1}

		### Note that this POST is json based, unlike V1 which is form(data) based
		self.request = self.session.post(self.baseurl + "/login/authenticate", json=data,\
                                                 headers=self.headers, allow_redirects=False)

		print("Authenticate result: " + str(self.request.status_code))
		#print(self.request.text)

		try:
			result = json.loads(self.request.text)
		except:
			result = {'status':'','errorCode':'','message':'','data':{'errorCode':''}}
			pass

		print("Authenticate output: " + json.dumps(result))

		errorCode   = result['data']['errorCode'] if 'errorCode' in result['data'] else ''
		requestText = self.request.text if self.request.text else ''

		self.gettoken()

		if self.request.status_code == 200 and (errorCode == 'first_login' or re.search("/login/firstPwdChange",requestText)):
			print("First login password change detected")

			#self.updateToken()

			postData = {'username':self.username, 'first_login_password':self.newPassword,
                                    'confirm_password':self.newPassword, 'token':self.token}

			self.request = self.session.post(self.baseurl + "/login/firstPwdChange", json=postData,\
                                                         headers=self.headers)

			print("First password change result: " + str(self.request.status_code))
			#print(self.request.text)

			try:
				result = json.loads(self.request.text)
			except:
				result = {'status':'','errorCode':'','message':'','data':{'errorCode':''}}
				pass

			print("First password change output: " + json.dumps(result))

			errorCode = result['data']['errorCode'] if 'errorCode' in result['data'] else ''

			if self.request.status_code in [200,303] or result['status'] == 'success':
				self.pwdChange = True

		if self.request.status_code == 200 and \
                   (errorCode == 'tos' or re.search("/login/setTOSSeen",self.request.text)):
			print("Terms of service detected")

			#self.updateToken()

			postData = {'token':self.token}

			self.request = self.session.post(self.baseurl + "/login/setTOSSeen", json=postData,\
                                                         headers=self.headers)

			print("Terms of service result: " + str(self.request.status_code))
			#print(self.request.text)

			try:
				result = json.loads(self.request.text)
			except:
				result = {'status':'','errorCode':'','message':'','data':{'errorCode':''}}
				pass

			print("Terms of service output: " + json.dumps(result))

			errorCode = result['data']['errorCode'] if 'errorCode' in result['data'] else ''

		if self.request.status_code == 200 and (errorCode == 'fed_ramp_view' or re.search("/login/setFedRampProceed",self.request.text)):
			print("Privacy notice detected")

			#self.updateToken()

			postData = {'token':self.token}

			self.request = self.session.post(self.baseurl + "/login/setFedRampProceed", json=postData,\
                                                         headers=self.headers)

			print("Privacy notice result: " + str(self.request.status_code))
			#print(self.request.text)

			try:
				result = json.loads(self.request.text)
			except:
				result = {'status':'','errorCode':'','message':'','data':{'errorCode':''}}
				pass

			print("Privacy notice output: " + json.dumps(result))

			errorCode = result['data']['errorCode'] if 'errorCode' in result['data'] else ''

		if self.request.status_code == 200 and result['status'] == 'error':
			errorCode = 'unknown' if not result['errorCode'] else result['errorCode']
			errorMsg  = 'unknown' if not result['message'] else result['message']

			print("Could not authenticate to " + self.host + " response.code:" + 
                              str(self.request.status_code) + " errorCode:" + errorCode + 
                              " message:" + errorMsg)
		
		#self.updateToken()

		return self.request

	### Legacy call to retrieve and update and return the tenant magic token
	def gettoken(self, request=None):
		print("called gettoken")

		self.request = self.session.get(self.baseurl + "/login/getToken", headers=self.headers)
		dataToken    = json.loads(self.request.text)['data']

		self.updateToken(dataToken)

		return self.token

	### Allows the token to be refreshed based on the last call or an obtained tenant token
	def updateToken(self, dataToken=None):
		print("called updateToken")

		if dataToken is None:
			dataToken = self.session.cookies.get_dict()['netskope']
                 
		clearToken = dataToken + self.host
		self.token = base64.urlsafe_b64encode(clearToken.encode('UTF-8')).decode('ascii')

		#print("dataToken:" + dataToken + " host:" + self.host + " token:" + self.token)

		return self.token
		

	### Internal function to stringify an object dump
	def __str__(self):
		return str(self.__class__) + ": " + str(self.__dict__)

class InlinePolicy3:
	def __init__(self, ns_host, session, token):
		self.host = ns_host
		self.session = session
		self.token = token

	def getpolicies(self):
		json_data = json.dumps({"token": self.token})
		hdrs = { 'X-Requested-With' : 'XMLHttpRequest', 'Content-Type' : 'application/json', 'Conection' : 'Close' }
		request = self.session.post("https://" + self.host + "/inline_policies/getPolicies", data = json_data, headers = hdrs)
		return(request)		

class DecryptionPolicy:
	def __init__(self, ns_host, session, token):
		self.host = ns_host
		self.session = session
		self.token = token

	def getpolicies(self):
		hdrs = { 'X-Requested-With' : 'XMLHttpRequest', 'Content-Type' : 'application/json;charset=utf-8' }
		json_data = json.dumps({"token": self.token})
		request = self.session.post("https://" + self.host + "/ssl_decryption/readAll", data = json_data, headers = hdrs)
		return(request)

class Categories:
	def __init__(self, ns_host, session, token):
		self.host = ns_host
		self.session = session
		self.token = token

	def getAllCategories(self):
		hdrs = { 'X-Requested-With' : 'XMLHttpRequest', 'Content-Type' : 'application/json;charset=utf-8' }
		json_data = json.dumps({"token": self.token})
		request = self.session.post("https://" + self.host + "/completions/getAllCategories", data = json_data, headers = hdrs)
		return(request)

class ApiPolicy:
	def __init__(self, ns_host, session, token):
		self.host = ns_host
		self.session = session
		self.token = token

	def getpolicies(self):
		json_data = json.dumps({"token": self.token})
		hdrs = { 'X-Requested-With' : 'XMLHttpRequest', 'Content-Type' : 'application/json', 'Conection' : 'Close' }
		request = self.session.post("https://" + self.host + "/api_policies/readAllApiPolicies", data = json_data, headers = hdrs)
		return(request)

class SecurityAssessmentPolicy:
	def __init__(self, ns_host, session, token):
		self.host = ns_host
		self.session = session
		self.token = token

	def getpolicies(self):
		json_data = json.dumps({
			"includeCrossCount": True,
			"filters": {},
			"token": self.token
			})
		hdrs = { 'X-Requested-With' : 'XMLHttpRequest', 'Content-Type' : 'application/json', 'Conection' : 'Close' }
		request = self.session.post("https://" + self.host + "/securityAssessmentPolicies/getAllPolicies", data = json_data, headers = hdrs)
		return(request)


class Web:
	def __init__(self, ns_host, session, token):
		self.host = ns_host
		self.session = session
		self.token = token

	def getweblists(self):
		json_data = json.dumps({"token": self.token})
		hdrs = { 'X-Requested-With' : 'XMLHttpRequest', 'Content-Type' : 'application/json' }
		request = self.session.post("https://" + self.host + "/web_list/readAllWebList", data = json_data, headers = hdrs)
		return(request)
	
	def getwebcats(self):
		json_data = json.dumps({"token": self.token})
		hdrs = { 'X-Requested-With' : 'XMLHttpRequest', 'Content-Type' : 'application/json' }
		request = self.session.post("https://" + self.host + "/web_category/readAllWebCategory", data = json_data, headers = hdrs)
		return(request)

class Malware:
	def __init__(self, ns_host, session, token):
		self.host = ns_host
		self.session = session
		self.token = token

	def getmalwareprofiles(self):
		json_data = json.dumps({"token": self.token})
		hdrs = { 'X-Requested-With' : 'XMLHttpRequest', 'Content-Type' : 'application/json' }
		request = self.session.post("https://" + self.host + "/malware_detection_profile/readAllMalwareDetectionProfile", data = json_data, headers = hdrs)
		return(request)

	def getfilehashlists(self):
		json_data = json.dumps({"token": self.token})
		hdrs = { 'X-Requested-With' : 'XMLHttpRequest', 'Content-Type' : 'application/json' }
		request = self.session.post("https://" + self.host + "/file_hash/readAllFileHash", data = json_data, headers = hdrs)
		return(request)

class DLP:
	def __init__(self, ns_host, session, token):
		self.host = ns_host
		self.session = session
		self.token = token

	def getdictionarylist(self):
		data = {"token": self.token}
		hdrs = { 'X-Requested-With' : 'XMLHttpRequest' }
		request = self.session.post("https://" + self.host + "/dlpDictionary/readAllDictionaryObjs", data = data, headers = hdrs)
		return(request)

	def getrules(self):
		data = {"token": self.token, "obj_loc": "custom", "region": "International"}
		hdrs = { 'X-Requested-With' : 'XMLHttpRequest' }
		request = self.session.post("https://" + self.host + "/dlpRule/readAllDlpRules", data = data, headers = hdrs)
		return(request)

	def getprofiles(self):
		data = {"token": self.token, "obj_loc": "custom", "region": "International", "industry": "All"}
		hdrs = { 'X-Requested-With' : 'XMLHttpRequest' }
		request = self.session.post("https://" + self.host + "/dlpProfile/readAllDlpProfiles", data = data, headers = hdrs)
		return(request)
	
	def getEPDLPdevicepolicies(self):
		data = {"token": self.token, "policy_type": "device"}
		hdrs = { 'X-Requested-With' : 'XMLHttpRequest' }
		request = self.session.post("https://" + self.host + "/endpoint_device_control_policies/getPolicies", data = data, headers = hdrs)
		return(request)	
	
	def getEPDLPcontentpolicies(self):
		data = {"token": self.token, "policy_type": "content"}
		hdrs = { 'X-Requested-With' : 'XMLHttpRequest' }
		request = self.session.post("https://" + self.host + "/endpoint_content_control_policies/getPolicies", data = data, headers = hdrs)
		return(request)	

class DomainProfile:
	def __init__(self, ns_host, session, token):
		self.host = ns_host
		self.session = session
		self.token = token

	def getprofiles(self):
		json_data = json.dumps({"token": self.token})
		hdrs = { 'X-Requested-With' : 'XMLHttpRequest', 'Content-Type' : 'application/json', 'Conection' : 'Close' }
		request = self.session.post("https://" + self.host + "/domain/readAllDomainProfiles", data = json_data, headers = hdrs)
		return(request)

class UserProfile:
	def __init__(self, ns_host, session, token):
		self.host = ns_host
		self.session = session
		self.token = token

	def getprofiles(self):
		json_data = json.dumps({"token": self.token})
		hdrs = { 'X-Requested-With' : 'XMLHttpRequest', 'Content-Type' : 'application/json', 'Conection' : 'Close' }
		request = self.session.post("https://" + self.host + "/userProfile/readAllProfile", data = json_data, headers = hdrs)
		return(request)

class FileProfile:
	def __init__(self, ns_host, session, token):
		self.host = ns_host
		self.session = session
		self.token = token

	def getprofiles(self):
		json_data = json.dumps({"token": self.token})
		hdrs = { 'X-Requested-With' : 'XMLHttpRequest', 'Content-Type' : 'application/json', 'Conection' : 'Close' }
		request = self.session.post("https://" + self.host + "/file_filter/readFilteredProfiles", data = json_data, headers = hdrs)
		return(request)

class Quarantine:
	def __init__(self, ns_host, session, token):
		self.host = ns_host
		self.session = session
		self.token = token

	def getprofiles(self):
		data = {"token": self.token}
		hdrs = { 'X-Requested-With' : 'XMLHttpRequest' }
		request = self.session.post("https://" + self.host + "/quarantine/readAllQuarantineProfiles", data = data, headers = hdrs)
		return(request)

class LegalHold:
	def __init__(self, ns_host, session, token):
		self.host = ns_host
		self.session = session
		self.token = token

	def getprofiles(self):
		json_data = json.dumps({"token": self.token})
		hdrs = { 'X-Requested-With' : 'XMLHttpRequest', 'Content-Type' : 'application/json', 'Conection' : 'Close' }
		request = self.session.post("https://" + self.host + "/legalHold/readAllLegalHoldProfiles", data = json_data, headers = hdrs)
		return(request)

class Forensic:
	def __init__(self, ns_host, session, token):
		self.host = ns_host
		self.session = session
		self.token = token

	def getprofiles(self):
		json_data = json.dumps({"token": self.token})
		hdrs = { 'X-Requested-With' : 'XMLHttpRequest', 'Content-Type' : 'application/json', 'Conection' : 'Close' }
		request = self.session.post("https://" + self.host + "/forensic/readAllProfile", data = json_data, headers = hdrs)
		return(request)

class Constraint:
	def __init__(self, ns_host, session, token):
		self.host = ns_host
		self.session = session
		self.token = token

	def getconstraints(self):
		json_data = json.dumps({"token": self.token})
		hdrs = { 'X-Requested-With' : 'XMLHttpRequest', 'Content-Type' : 'application/json', 'Conection' : 'Close' }
		request = self.session.post("https://" + self.host + "/constraints/readAllConstraintProfiles", data = json_data, headers = hdrs)
		return(request)

class NetworkLocation:
	def __init__(self, ns_host, session, token):
		self.host = ns_host
		self.session = session
		self.token = token

	def getnetworklocations(self):
		json_data = json.dumps({"token": self.token})
		hdrs = { 'X-Requested-With' : 'XMLHttpRequest', 'Content-Type' : 'application/json', 'Conection' : 'Close' }
		request = self.session.post("https://" + self.host + "/networkLocation/readAllNetLocationObjs", data = json_data, headers = hdrs)
		return(request)

class Notification:
	def __init__(self, ns_host, session, token):
		self.host = ns_host
		self.session = session
		self.token = token

	def getusertemplates(self):
		json_data = json.dumps({"token": self.token, "offset": "null"})
		hdrs = { 'X-Requested-With' : 'XMLHttpRequest', 'Content-Type' : 'application/json', 'Conection' : 'Close' }
		request = self.session.post("https://" + self.host + "/notification_template/readAllTemplates", data = json_data, headers = hdrs)
		return(request)

	def getemailtemplates(self):
		json_data = json.dumps({"token": self.token})
		hdrs = { 'X-Requested-With' : 'XMLHttpRequest', 'Content-Type' : 'application/json', 'Conection' : 'Close' }
		request = self.session.post("https://" + self.host + "/emailNotification/readAllEmailNotificationTemplates", data = json_data, headers = hdrs)
		return(request)

	def getcustomimages(self):
		data = {"token": self.token}
		hdrs = { 'X-Requested-With' : 'XMLHttpRequest' }
		request = self.session.post("https://" + self.host + "/settings/templates/readAllCustomImageNames", data = data, headers = hdrs)
		return(request)

class ManageCloudApps:
	def __init__(self, ns_host, session, token):
		self.host = ns_host
		self.session = session
		self.token = token

	def getcustomapps(self, searchstring=""):
		hdrs = { 'X-Requested-With' : 'XMLHttpRequest', 'Content-Type' : 'application/json'}
		json_data = json.dumps({
			"searchStr": searchstring,
			"offset":0,
			"limit":9999,
			"sortBy":"modify_time",
			"order":"desc",
			"token": self.token
		})
		self.request = self.session.post("https://" + self.host + "/settings/manage_custom_apps/getCustomAppsRules", data = json_data, headers = hdrs)
		return(self.request)

class PrivateApps:
	def __init__(self, ns_host, session, token):
		self.host = ns_host
		self.session = session
		self.token = token

	def getprivateapps(self, searchstring=""):
		hdrs = { 'X-Requested-With' : 'XMLHttpRequest', 'Content-Type' : 'application/json'}
		json_data = json.dumps({
			"searchStr": searchstring,
			"offset":0,
			"limit":9999,
			"sortBy":"publisher_name",
			"order":"asc",
			"searchByHost":"1",
			"searchByPublisher":"1",
			"token": self.token
		})
		self.request = self.session.post("https://" + self.host + "/settings/managePrivateApps/getPrivateApps", data = json_data, headers = hdrs)
		return(self.request)
	
	def getpublishers(self, searchstring=""):
		hdrs = { 'X-Requested-With' : 'XMLHttpRequest', 'Content-Type' : 'application/json'}
		json_data = json.dumps({
					"searchStr":searchstring,
					"offset":0,
					"limit":"9999",
					"sortBy":"publisher_name",
					"order":"asc",
					"token": self.token
				})
		self.request = self.session.post("https://" + self.host + "/settings/managePrivateApps/getPublishers", data = json_data, headers = hdrs)
		return(self.request)
		
class Steering:
	def __init__(self, ns_host, session, token):
		self.host = ns_host
		self.session = session
		self.token = token

	def getconfigs(self, searchou=""):
		json_data = json.dumps({
			"searchOu": searchou,
			"token": self.token})
		hdrs = { 'X-Requested-With' : 'XMLHttpRequest', 'Content-Type' : 'application/json', 'Conection' : 'Close' }
		request = self.session.post("https://" + self.host + "/settings/steering_config/getSteeringList", data = json_data, headers = hdrs)
		return(request)

class GRE:
	def __init__(self, ns_host, session, token):
		self.host = ns_host
		self.session = session
		self.token = token

	def getpoplist(self):
		json_data = json.dumps({
			"token": self.token})
		hdrs = { 'X-Requested-With' : 'XMLHttpRequest', 'Content-Type' : 'application/json', 'Conection' : 'Close' }
		request = self.session.post("https://" + self.host + "/settings/fwdProxyGRETunnels/getPopList", data = json_data, headers = hdrs)
		return(request)

class IPSec:
	def __init__(self, ns_host, session, token):
		self.host = ns_host
		self.session = session
		self.token = token

	def getpoplist(self):
		json_data = json.dumps({
			"token": self.token})
		hdrs = { 'X-Requested-With' : 'XMLHttpRequest', 'Content-Type' : 'application/json', 'Conection' : 'Close' }
		request = self.session.post("https://" + self.host + "/settings/fwdProxyIPSec/getPopList", data = json_data, headers = hdrs)
		return(request)

class PXC:
	def __init__(self, ns_host, session, token):
		self.host = ns_host
		self.session = session
		self.token = token

	def getconfigs(self):
		json_data = json.dumps({
			"token": self.token})
		hdrs = { 'X-Requested-With' : 'XMLHttpRequest', 'Content-Type' : 'application/json', 'Conection' : 'Close' }
		request = self.session.post("https://" + self.host + "/settings/forward_to_proxy/getAll", data = json_data, headers = hdrs)
		return(request)

class SamlProxy:
	def __init__(self, ns_host, session, token):
		self.host = ns_host
		self.session = session
		self.token = token

	def getreverseconfigs(self, type="reverse-proxy"):
		json_data = json.dumps({
			"type": type,
			"token": self.token})
		hdrs = { 'X-Requested-With' : 'XMLHttpRequest', 'Content-Type' : 'application/json', 'Conection' : 'Close' }
		request = self.session.post("https://" + self.host + "/samlproxy/getAllAppAcountConfigs", data = json_data, headers = hdrs)
		return(request)
	
	def getclientconfigs(self, type="client"):
		json_data = json.dumps({
			"type": type,
			"token": self.token})
		hdrs = { 'X-Requested-With' : 'XMLHttpRequest', 'Content-Type' : 'application/json', 'Conection' : 'Close' }
		request = self.session.post("https://" + self.host + "/samlproxy/getAllAppAcountConfigs", data = json_data, headers = hdrs)
		return(request)

class DownloadCert:
	def __init__(self, ns_host, session, token):
		self.host = ns_host
		self.session = session
		self.token = token

	def getcerts(self):
		hdrs = { 'X-Requested-With' : 'XMLHttpRequest', 'Content-Type' : 'application/json'}
		json_data = json.dumps({
					"offset":0,
					"limit":"99",
					"sortBy":"cert_name",
					"order":"asc",
					"token": self.token
				})
		self.request = self.session.post("https://" + self.host + "/settings/certificates/readAll", data = json_data, headers = hdrs)
		return(self.request)


class SSOConfig:
	def __init__(self, ns_host, session, token):
		self.host = ns_host
		self.session = session
		self.token = token

	def getconfigs(self):
		json_data = json.dumps({
			"token": self.token})
		hdrs = { 'X-Requested-With' : 'XMLHttpRequest', 'Content-Type' : 'application/json', 'Conection' : 'Close' }
		request = self.session.post("https://" + self.host + "/settings/sso/getSsoSettings", data = json_data, headers = hdrs)
		return(request)

class DeviceClassif:
	def __init__(self, ns_host, session, token):
		self.host = ns_host
		self.session = session
		self.token = token

	def getconfigs(self):
		json_data = json.dumps({
			"token": self.token})
		hdrs = { 'X-Requested-With' : 'XMLHttpRequest', 'Content-Type' : 'application/json', 'Conection' : 'Close' }
		request = self.session.post("https://" + self.host + "/settings/deviceClassification/getDeviceClassification", data = json_data, headers = hdrs)
		return(request)
	
class DeviceConfigProf:
	def __init__(self, ns_host, session, token):
		self.host = ns_host
		self.session = session
		self.token = token

	def getconfigs(self, searchConfig=""):
		json_data = json.dumps({
			"searchConfig": searchConfig,
			"token": self.token})
		hdrs = { 'X-Requested-With' : 'XMLHttpRequest', 'Content-Type' : 'application/json', 'Conection' : 'Close' }
		request = self.session.post("https://" + self.host + "/settings/clientConfiguration/getOUClientList", data = json_data, headers = hdrs)
		return(request)
	
class RBAC:
	def __init__(self, ns_host, session, token):
		self.host = ns_host
		self.session = session
		self.token = token

	def getconfigs(self):
		json_data = json.dumps({
			"token": self.token})
		hdrs = { 'X-Requested-With' : 'XMLHttpRequest', 'Content-Type' : 'application/json', 'Conection' : 'Close' }
		request = self.session.post("https://" + self.host + "/settings/tenant_role/getRoles", data = json_data, headers = hdrs)
		return(request)