import goskope
import sys, json

def getcreds(ns_tenant, ns_username, ns_password):
	nscreds = goskope.Auth(ns_tenant, ns_username, ns_password)
	nscreds.gettoken()
	nscreds.login()
	return(nscreds)

def tenantbackup(nscreds):
	#Initialize InlinePolicy3 Class
	inlinepolicy = goskope.InlinePolicy3(nscreds.host, nscreds.session, nscreds.token)
	
    #Get Inline Policies
	json_data = inlinepolicy.getpolicies()
	write_json("policies_real_time.json", json_data)
	print("Successfully got Real Time Protection policies")
	
    #Initialize DecryptionPolicy Class
	decryptionpolicy = goskope.DecryptionPolicy(nscreds.host, nscreds.session, nscreds.token)
	
    #Get Decryption Policies
	json_data = decryptionpolicy.getpolicies()
	write_json("policies_ssl_decryption.json", json_data)
	print("Successfully got Decryption policies")

    #Initialize getAllCategories Class
	categories = goskope.Categories(nscreds.host, nscreds.session, nscreds.token)
	
    #Get All Defined Categories 
	json_data = categories.getAllCategories()
	write_json("AllCategories.json", json_data)
	print("Successfully got All Categories")
		
    #Initialize Web Class
	Web = goskope.Web(nscreds.host, nscreds.session, nscreds.token)
	
    #Get All Defined Web Lists and Custom Categories 
	json_data = Web.getweblists()
	write_json("weblists.json", json_data)
	print("Successfully got All Web Lists") 
	json_data = Web.getwebcats()
	write_json("webcats.json", json_data)
	print("Successfully got All Custom Web Categories") 

    #Initialize ApiPolicy Class
	ApiPolicy = goskope.ApiPolicy(nscreds.host, nscreds.session, nscreds.token)
	
    #Get API Policies
	json_data = ApiPolicy.getpolicies()
	write_json("policies_Api.json", json_data)
	print("Successfully got ApiPolicy")
    
    #Initialize SecurityAssessmentPolicy Class
	SecurityAssessmentPolicy = goskope.SecurityAssessmentPolicy(nscreds.host, nscreds.session, nscreds.token)
	
    #Get SecurityAssessmentPolicy
	json_data = SecurityAssessmentPolicy.getpolicies()
	write_json("policies_SecurityAssessment.json", json_data)
	print("Successfully got SecurityAssessmentPolicy")

    #Initialize Malware Class
	Malware = goskope.Malware(nscreds.host, nscreds.session, nscreds.token)
	
    #Get Malware Profiles & File Hash Lists
	json_data = Malware.getmalwareprofiles()
	write_json("profiles_malware.json", json_data)
	print("Successfully got Malware Profiles")	
	json_data = Malware.getfilehashlists()
	write_json("hashlist_File.json", json_data)
	print("Successfully got File Hash Lists")		

    #Initialize DLP Class
	DLP = goskope.DLP(nscreds.host, nscreds.session, nscreds.token)
	
    #Get DLP Dictionaries, Dictionary Lists, Rules, Profiles
	json_data = DLP.getdictionarylist()
	write_json("DLP_dictionarylist.json", json_data)
	print("Successfully got DLP Dictionary List")	
	json_data = DLP.getrules()
	write_json("DLP_Rules.json", json_data)
	print("Successfully got DLP Rules")	
	json_data = DLP.getprofiles()
	write_json("DLP_Profiles.json", json_data)
	print("Successfully got DLP Profiles")	
	json_data = DLP.getEPDLPdevicepolicies()
	write_json("DLP_epdlpdevice.json", json_data)
	print("Successfully got EPDLP Device Control Policies")	
	json_data = DLP.getEPDLPcontentpolicies()
	write_json("DLP_epdlpcontent.json", json_data)
	print("Successfully got EPDLP Content Policies")

    #Initialize DomainProfile Class
	DomainProfile = goskope.DomainProfile(nscreds.host, nscreds.session, nscreds.token)
	
    #Get Domain Profiles
	json_data = DomainProfile.getprofiles()
	write_json("profiles_Domain.json", json_data)
	print("Successfully got Domain Profile")

    #Initialize UserProfile Class
	UserProfile = goskope.UserProfile(nscreds.host, nscreds.session, nscreds.token)
	
    #Get User Profiles
	json_data = UserProfile.getprofiles()
	write_json("profiles_User.json", json_data)
	print("Successfully got User Profiles")
	
    #Initialize FileProfile Class
	FileProfile = goskope.FileProfile(nscreds.host, nscreds.session, nscreds.token)
	
    #Get File Profiles
	json_data = FileProfile.getprofiles()
	write_json("profiles_File.json", json_data)
	print("Successfully got File Profiles")
	
    #Initialize Quarantine Class
	Quarantine = goskope.Quarantine(nscreds.host, nscreds.session, nscreds.token)
	
    #Get Quarantine Profiles
	json_data = Quarantine.getprofiles()
	write_json("profiles_Quarantine.json", json_data)
	print("Successfully got Quarantine Profiles")
	
    #Initialize LegalHold Class
	LegalHold = goskope.LegalHold(nscreds.host, nscreds.session, nscreds.token)
	
    #Get LegalHold Profiles
	json_data = LegalHold.getprofiles()
	write_json("profiles_LegalHold.json", json_data)
	print("Successfully got LegalHold Profiles")
		
    #Initialize Forensic Class
	Forensic = goskope.Forensic(nscreds.host, nscreds.session, nscreds.token)
	
    #Get Forensic Profiles
	json_data = Forensic.getprofiles()
	write_json("profiles_Forensic.json", json_data)
	print("Successfully got Forensic Profiles")

    #Initialize Constraint Class
	Constraint = goskope.Constraint(nscreds.host, nscreds.session, nscreds.token)
	
    #Get Constraint Profiles
	json_data = Constraint.getconstraints()
	write_json("profiles_Constraint.json", json_data)
	print("Successfully got Constraint Profiles")

    #Initialize NetworkLocation Class
	NetworkLocation = goskope.NetworkLocation(nscreds.host, nscreds.session, nscreds.token)
	
    #Get NetworkLocation Profiles
	json_data = NetworkLocation.getnetworklocations()
	write_json("profiles_NetworkLocations.json", json_data)
	print("Successfully got NetworkLocation Profiles")

    #Initialize Notification Class
	Notification = goskope.Notification(nscreds.host, nscreds.session, nscreds.token)
	
    #Get Notification Templates
	json_data = Notification.getusertemplates()
	write_json("Notification_User.json", json_data)
	print("Successfully got usertemplates Notifications Templates")
	json_data = Notification.getemailtemplates()
	write_json("Notification_User.json", json_data)
	print("Successfully got emailtemplates Notification Templates")
	json_data = Notification.getcustomimages()
	write_json("Notification_User.json", json_data)
	print("Successfully got customimages Notifications Templates")

	#Initialize ManageCloudApps Class
	ManageCloudApps = goskope.ManageCloudApps(nscreds.host, nscreds.session, nscreds.token)
	
    #Get Custom Cloud App definitions
	json_data = ManageCloudApps.getcustomapps()
	write_json("policies_customapps.json", json_data)
	print("Successfully got Custom App Definitions")
	
	#Initialize ManageCloudApps Class
	ManageCloudApps = goskope.ManageCloudApps(nscreds.host, nscreds.session, nscreds.token)
	
    #Get Custom Cloud & Firewall App definitions
	json_data = ManageCloudApps.getcustomapps()
	write_json("policies_customapps.json", json_data)
	print("Successfully got Custom Cloud & Firewall App Definitions")
	
	#Initialize PrivateApps Class
	PrivateApps = goskope.PrivateApps(nscreds.host, nscreds.session, nscreds.token)
	
    #Get Private Access App definitions
	json_data = PrivateApps.getprivateapps()
	write_json("policies_npa_apps.json", json_data)
	print("Successfully got Private Access App Definitions")

    #Get Private Access Publisher definitions
	json_data = PrivateApps.getpublishers()
	write_json("policies_npa_publisher.json", json_data)
	print("Successfully got Private Access Publisher Definitions")

    #Initialize Steering Class
	Steering = goskope.Steering(nscreds.host, nscreds.session, nscreds.token)
	
    #Get Steering Profiles
	json_data = Steering.getconfigs()
	write_json("profiles_Steering.json", json_data)
	print("Successfully got Steering Profiles")	
	
    #Initialize GRE Class
	GRE = goskope.GRE(nscreds.host, nscreds.session, nscreds.token)
	
    #Get GRE Profiles
	json_data = GRE.getpoplist()
	write_json("profiles_GRE.json", json_data)
	print("Successfully got GRE Profiles")	
	
    #Initialize IPSec Class
	IPSec = goskope.IPSec(nscreds.host, nscreds.session, nscreds.token)
	
    #Get IPSec Profiles
	json_data = IPSec.getpoplist()
	write_json("profiles_IPSec.json", json_data)
	print("Successfully got IPSec Profiles")	
	
    #Initialize PXC Class
	PXC = goskope.PXC(nscreds.host, nscreds.session, nscreds.token)
	
    #Get PXC Profiles
	json_data = PXC.getconfigs()
	write_json("profiles_PXC.json", json_data)
	print("Successfully got PXC Profiles")	
	
    #Initialize SamlProxy Class
	SamlProxy = goskope.SamlProxy(nscreds.host, nscreds.session, nscreds.token)
	
    #Get SamlProxy Profiles
	json_data = SamlProxy.getreverseconfigs()
	write_json("profiles_Reverse_SamlProxy.json", json_data)
	print("Successfully got Reverse Proxy SamlProxy Settings")	
	json_data = SamlProxy.getclientconfigs()
	write_json("profiles_client_SamlProxy.json", json_data)
	print("Successfully got Client Proxy SamlProxy Settings")		
	
    #Initialize DownloadCert Class
	DownloadCert = goskope.DownloadCert(nscreds.host, nscreds.session, nscreds.token)
	
    #Get Download Tenant CA Certs
	json_data = DownloadCert.getcerts()
	write_json("CAcerts.json", json_data)
	print("Successfully got Tenant CA Certs")	
	
    #Initialize SSOConfig Class
	SSOConfig = goskope.SSOConfig(nscreds.host, nscreds.session, nscreds.token)
	
    #Get Download Tenant Admin SSO Configuration
	json_data = SSOConfig.getconfigs()
	write_json("SSO_Admin_Config.json", json_data)
	print("Successfully got SSO Config")	

    #Initialize DeviceClassif Class
	DeviceClassif = goskope.DeviceClassif(nscreds.host, nscreds.session, nscreds.token)
	
    #Get Download Device Classification Configuration
	json_data = DeviceClassif.getconfigs()
	write_json("DeviceClassif_Config.json", json_data)
	print("Successfully got Device Classification Configs")	
	
    #Initialize DeviceConfigProf Class
	DeviceConfigProf = goskope.DeviceConfigProf(nscreds.host, nscreds.session, nscreds.token)
	
    #Get Download Device Configuration Profiles Configuration
	json_data = DeviceConfigProf.getconfigs()
	write_json("DeviceConfigProf_config.json", json_data)
	print("Successfully got Device Configuration Profiles Configs")	
	
    #Initialize RBAC Class
	RBAC = goskope.RBAC(nscreds.host, nscreds.session, nscreds.token)
	
    #Get Download RBAC Profiles Configuration
	json_data = RBAC.getconfigs()
	write_json("RBAC_config.json", json_data)
	print("Successfully got RBAC Profiles Configs")	
	return
	
def write_json(file, json_data):
	json_object = json.dumps(json_data.json(), indent=4)
	with open(file, "w") as outfile:
		outfile.write(json_object)
	return

if __name__ == "__main__":

	#Set Tenant VARs
	ns_tenant = sys.argv[1]
	ns_username = sys.argv[2]
	ns_password = sys.argv[3]

	#Get Creds
	nscreds = getcreds(ns_tenant, ns_username, ns_password)

	tenantbackup(nscreds)