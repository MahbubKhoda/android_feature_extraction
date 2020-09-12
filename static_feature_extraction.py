# it extracts permisison, API and ICC features from all the apps
# with .apk extension in the rootdir folder

import os
import subprocess
from androguard.misc import AnalyzeAPK
# from sets import Set

current_dir = os.getcwd()
permission_dir = os.path.join(current_dir,'permission_features')
icc_dir = os.path.join(current_dir,'icc_features')
api_dir = os.path.join(current_dir,'api_features')
rootdir = "/home/mahbub/Desktop/Malwares/Drebin/All"

if not os.path.exists(permission_dir):
	os.makedirs(permission_dir)

if not os.path.exists(icc_dir):
	os.makedirs(icc_dir)

if not os.path.exists(api_dir):
	os.makedirs(api_dir)


def write_permissions(a,permission_file_path):
	permisssions = a.get_permissions()
	with open(permission_file_path,'w') as f:
		for p in permisssions:
			f.write("permission::%s\n"%p)

def write_api(dx,api_file_path):

	# list of security sensitive APIs from pscout
	with open('jellybean_parsed.txt', 'r') as f:
		sensitive_api_list = [line.strip() for line in f]

	api_set = set()
	for classes in dx.get_classes():
		for meths in classes.get_methods():
			for classobj, methodobj, offset in meths.get_xref_to():
				if classobj.is_external():
					class_name = methodobj.get_class_name()
					class_name = class_name.replace('L','',1) #replace capital L only the first occurence
					class_name = class_name.replace('[','')
					class_name = class_name.replace(';','')
					class_name = class_name.replace('/','.')
					class_method = "%s %s"%(class_name,methodobj.get_name())
					# f.write("%s %s\n"%(class_name,methodobj.get_name()))
					if class_method in sensitive_api_list:
						api_set.add("api::%s->%s"%(class_name,methodobj.get_name()))
	
	with open(api_file_path,'w') as f:
		for api in api_set:
			f.write(api+'\n')

def write_icc(a,icc_file_path):
	activities = a.get_activities()
	services = a.get_services()
	receivers = a.get_receivers()
	providers = a.get_providers()
	features = a.get_features()
	with open(icc_file_path,'w') as f:
		for activity in activities:
			f.write("activity::%s\n"%activity)
			intent_filters = a.get_intent_filters('activity',activity)
			if 'action' in intent_filters:
				for intent in intent_filters['action']:
					f.write("intent::%s\n"%intent)
			if 'category' in intent_filters:
				for category in intent_filters['category']:
					f.write("intent::%s\n"%category)
		for service in services:
			f.write("service::%s\n"%service)
			intent_filters = a.get_intent_filters('service',service)
			if 'action' in intent_filters:
				for intent in intent_filters['action']:
					f.write("intent::%s\n"%intent)
			if 'category' in intent_filters:
				for category in intent_filters['category']:
					f.write("intent::%s\n"%category)
		for receiver in receivers:
			f.write("receiver::%s\n"%receiver)
			intent_filters = a.get_intent_filters('receiver',receiver)
			if 'action' in intent_filters:
				for intent in intent_filters['action']:
					f.write("intent::%s\n"%intent)
			if 'category' in intent_filters:
				for category in intent_filters['category']:
					f.write("intent::%s\n"%category)
		for provider in providers:
			f.write("provider::%s\n"%provider)
		for feature in features:
			f.write("feature::%s\n"%feature)
			

num = 0
for path, subdirs, files in os.walk(rootdir):
    for name in files:
        if name.endswith(".apk"):
            num = num +1
            filepath = os.path.join(path, name)
            appName = name[:-4]
            #print("File %d: %s"%(num,name))
            print(num)

            try:
                a, d, dx = AnalyzeAPK(filepath)
                
                permission_file_path = os.path.join(permission_dir,appName)
                write_permissions(a,permission_file_path)

                icc_file_path = os.path.join(icc_dir,appName)
                write_icc(a,icc_file_path)

                api_file_path = os.path.join(api_dir,appName)
                write_api(dx,api_file_path)
            
            except Exception as e:
                with open('exception.txt','a') as exceptionfile:
                	exceptionfile.write('{}\n'.format(appName))
                continue
            
            else:
            	pass