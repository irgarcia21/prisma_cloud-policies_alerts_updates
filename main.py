from __future__ import print_function
import json
import requests
import configparser
import datetime
import hashlib
import os

requests.packages.urllib3.disable_warnings() # Added to avoid warnings in output if proxy

#----------- Functions to be used -----------

def return_error (message):
    print("\nERROR: " + message)
    exit(1)

def get_parser_from_sections_file (file_name):
    file_parser = configparser.ConfigParser()
    try: # Checks if the file has the proper format
        file_parser.read(file_name)
    except (ValueError, configparser.MissingSectionHeaderError, configparser.DuplicateOptionError, configparser.DuplicateOptionError):
        return_error ("Unable to read file " + file_name)
    return file_parser

def read_value_from_sections_file (file_parser, section, option):
    value={}
    value['Exists'] = False
    if file_parser.has_option(section, option): # Checks if section and option exist in file
        value['Value'] = file_parser.get(section,option)
        if not value['Value']=='': # Checks if NOT blank (so properly updated)
            value['Exists'] = True
    return value

def read_value_from_sections_file_and_exit_if_not_found (file_name, file_parser, section, option):
    value = read_value_from_sections_file (file_parser, section, option)
    if not value['Exists']:
        return_error("Section \"" + section + "\" and option \"" + option + "\" not found in file " + file_name)
    return value['Value']

def write_str_to_file (file, msg):
    file.write(msg)
    file.flush()

def write_bool_to_file (file, bool):
    write_str_to_file (file, str(bool))

def write_list_to_file (file, list):
    for element in list: 
        write_object_to_file (file, element)

def write_dict_to_file (file, dict):
    for key, value in dict.items():
        write_str_to_file (file, '\n' + key + ' : ' )
        write_object_to_file (file, value)

def write_object_to_file (file, obj):
    if type(obj) is str:
        write_str_to_file (file, obj)
    elif type(obj) is bool:
        write_bool_to_file (file, obj)
    elif type(obj) is list:
        write_list_to_file (file, obj)
    elif type(obj) is dict:
        write_dict_to_file (file, obj)

def hash_dictionary (dict):
    hash = hashlib.sha256()
    string = json.dumps(dict)
    encoded = json.dumps(dict, sort_keys=False).encode()
    hash.update(encoded)
    return hash.hexdigest()

def update_objId_adding_hash (obj, id, hash):
    newValue = obj[id] + " ---> hash : " + hash
    objWithHash =  {"\n" + id : newValue}
    objWithHash.update(obj)
    del objWithHash[id]
    return(objWithHash)

def write_object_to_file_adding_hash (file, obj):
    hash = hash_dictionary(obj)
    if 'policyId' in obj.keys():
        obj = update_objId_adding_hash (obj, 'policyId', hash)
    elif 'policyScanConfigId' in obj.keys():
        obj = update_objId_adding_hash (obj, 'policyScanConfigId', hash)
    write_object_to_file (file, obj)

def filter_useful_policy_values (policy):
    if 'alerts' in policy.keys(): # not relevant so delete to improve performance and decrease file size
        del policy['alerts']
    if 'complianceMetadata' in policy.keys(): # not relevant so delete to improve performance and decrease file size
        del policy['complianceMetadata']
    if 'policySubTypes' in policy.keys(): # it may be relevant but it is deleted to avoid false positives in modified objects ("build" and "run" sometimes changes the order and makes hash to be different)
        del policy['policySubTypes']    
    return policy

def delete_elem_from_list_containing_substring (list, substring):
    for element in list:
        if substring in element:
            list.remove(element)
            break
    return list

def print_results (objsList,objsType):
    if (len(objsList)==0):
        print("\t NONE")
    else:
        for i in range(len(objsList)):
            obj=objsList[i]
            objContainsNameField = any (">>>>>>" in string for string in objsList) # If list comes from last execution file
            if (objContainsNameField):
                obj = obj.split("--->")
                id = obj[0]
                obj = obj[1].split(">>>>>>")
                obj = obj[1].split("\n")
                name=obj[0]
                print("\t " + id + name)
            else: # If we have the complete object
                if (objsType == "Policies"):
                    print("\t policyId \"" + obj['policyId'] + "\" name \"" + obj['name'] + "\"")
                elif (objsType == "Alert Rules"):
                    print("\t policyScanConfigId \"" + obj['policyScanConfigId'] + "\" name \"" + obj['name'] + "\"")

def dump_objs (apiResponse, objsType):
    objsList = apiResponse.json()
    if (objsType == "Policies"):
        write_object_to_file (configOutputFile, "---------- POLICIES ----------\n")
    elif (objsType == "Alert Rules"):
        write_object_to_file (configOutputFile, "\n\n---------- ALERT RULES ----------\n")
    for i in range(len(objsList)):
        obj=objsList[i]
        if (objsType == "Policies"):
            obj = filter_useful_policy_values (obj)
        write_object_to_file_adding_hash (configOutputFile, obj) # it writes all current objects 1 by 1 it to the file

def dump_objs_and_analyze_changes (apiResponse, objsType):  
    objsList = apiResponse.json()
    objsChanged = {}
    objsChanged['Created'] = []
    objsChanged['Modified'] = []
    objsChanged['Deleted'] = []

    if (objsType == "Policies"):
        objsChanged['Deleted'] = policiesLastExecution # it starts will all previous results and will be removed if they exist in this execution
        write_object_to_file (configOutputFile, "---------- POLICIES ----------\n")
    elif (objsType == "Alert Rules"):
        objsChanged['Deleted'] = alertRulesLastExecution # it starts will all previous results and will be removed if they exist in this execution
        write_object_to_file (configOutputFile, "\n\n---------- ALERT RULES ----------\n")

    for i in range(len(objsList)):
        obj=objsList[i]
        if (objsType == "Policies"):
            obj = filter_useful_policy_values (obj)
        write_object_to_file_adding_hash (configOutputFile, obj) # it writes all current objects 1 by 1 it to the file
        currentHash = hash_dictionary(obj)
        if (objsType == "Policies"):
            idExistedInLastExecution = any (obj['policyId'] in string for string in policiesLastExecution)
            hashExistedInLastExecution = any (currentHash in string for string in policiesLastExecution)
        elif (objsType == "Alert Rules"):
            idExistedInLastExecution = any (obj['policyScanConfigId'] in string for string in alertRulesLastExecution)
            hashExistedInLastExecution = any (currentHash in string for string in alertRulesLastExecution)
        if (idExistedInLastExecution):
            if (objsType == "Policies"):
                objsChanged['Deleted'] = delete_elem_from_list_containing_substring (objsChanged['Deleted'], obj['policyId'])
            elif (objsType == "Alert Rules"):
                objsChanged['Deleted'] = delete_elem_from_list_containing_substring (objsChanged['Deleted'], obj['policyScanConfigId'])
            if (not hashExistedInLastExecution):
                objsChanged['Modified'].append(obj)
        else:
            objsChanged['Created'].append(obj)

    print("\n" + objsType + " created:") ; print_results(objsChanged['Created'], objsType)
    print("\n" + objsType + " modified:") ; print_results(objsChanged['Modified'], objsType)
    print("\n" + objsType + " deleted:") ; print_results(objsChanged['Deleted'], objsType)
    
    return objsChanged

def analyze_impacted_alerts (apiResponse, policiesModified):
    alertRulesList = apiResponse.json()
       
    for i in range(len(alertRulesList)):
        alertRule=alertRulesList[i]
        if (alertRule['scanAll']):
            print("\t AlertId \"" + alertRule['policyScanConfigId'] + "\" Name \"" + alertRule['name'])
            print("\t\t All modified policies")
        else:
            alertRuleprinted = False
            policiesInAlertRule = alertRule['policies']
            for j in range(len(policiesInAlertRule)):
                policyInAlertRule = policiesInAlertRule[j]
                for k in range(len(policiesModified)):
                    policyModified=policiesModified[k]
                    if (policyInAlertRule==policyModified['policyId']):
                        if (alertRuleprinted == False):
                            alertRuleprinted = True
                            print("\t AlertId \"" + alertRule['policyScanConfigId'] + "\" Name \"" + alertRule['name'])
                        print("\t\t PolicyId \"" + policyInAlertRule + "\"")

#----------- Load info from last execution file (if any) -----------

metadataFilePath = "metadata.txt"
metadataFileExists = False
lastExecutionFileExists = False
if os.path.exists(metadataFilePath): # validate metadata file exists and last file execution is found
    metadataFileExists = True
    metadataFileParser = get_parser_from_sections_file (metadataFilePath)
    readLastFileName = read_value_from_sections_file (metadataFileParser, 'LAST_EXECUTION','LAST_FILE_NAME')
    if readLastFileName['Exists']:
        lastFileName = ("../" + readLastFileName['Value'])
        if os.path.exists(lastFileName):
            lastExecutionFileExists = True
if lastExecutionFileExists:
    print ("Previous execution found. Analyzing changes. Please wait...")
    lastFileCreated = open (lastFileName)
    allLinesLastExecution = lastFileCreated.readlines()
    policiesLastExecution = []
    alertRulesLastExecution = []
    for i in range(len(allLinesLastExecution)):
        if 'policyId' in allLinesLastExecution[i]:
            policiesLastExecution.append(allLinesLastExecution[i]+ " >>>>>> " + allLinesLastExecution[i+1])
        elif 'policyScanConfigId' in allLinesLastExecution[i]:
            alertRulesLastExecution.append(allLinesLastExecution[i]+" >>>>>> " + allLinesLastExecution[i+1])
else:
    print("No previous execution to compare. Pulling current config. Please wait...") # Nothing to load. It goes directly to next section
    
#----------- Prepare this execution file -----------

configFileName = datetime.datetime.now().strftime("%Y%m%d-%I%M%S%p") + ".txt"
configOutputFile = open ("../" + configFileName, 'w', encoding="utf-8")

#----------- Load API configuration from .ini file -----------

iniFilePath = "API_config.ini"
if not os.path.exists(iniFilePath): return_error("Config file " + iniFilePath + " does not exist")
iniFileParser = get_parser_from_sections_file (iniFilePath)
PRISMA_CLOUD_API_URL = read_value_from_sections_file_and_exit_if_not_found (iniFilePath, iniFileParser, 'URL', 'URL')

#----------- First API call for authentication -----------

action = "POST"
url = PRISMA_CLOUD_API_URL + read_value_from_sections_file_and_exit_if_not_found (iniFilePath, iniFileParser, 'AUTHENTICATION','LOGIN_URL')
json_header = {'Content-Type': 'application/json'}
data = {}
data['username'] = read_value_from_sections_file_and_exit_if_not_found (iniFilePath, iniFileParser,'AUTHENTICATION','ACCESS_KEY_ID')
data['password'] = read_value_from_sections_file_and_exit_if_not_found (iniFilePath, iniFileParser,'AUTHENTICATION','SECRET_KEY')
data_json = json.dumps(data)
apiResponse = requests.request(action, url, headers=json_header, data=data_json, verify=False) # verify=False to avoid CA certificate error if proxy between script and console
status = apiResponse.status_code

if (status != 200):
    print("Authentication with Prisma Cloud failed.")
    exit(-1)
else:
    authentication_response = apiResponse.json()
    token = authentication_response['token']
    auth_header = {read_value_from_sections_file_and_exit_if_not_found (iniFilePath, iniFileParser,'AUTHENTICATION','AUTHORIZATIONS'):token}
 
    #----------- Get policies modified -----------

    action = "GET"
    url = PRISMA_CLOUD_API_URL + read_value_from_sections_file_and_exit_if_not_found (iniFilePath, iniFileParser, 'POLICIES','POLICIES_URL')
    apiResponse = requests.request(action, url, headers=auth_header, verify=False) # verify=False to avoid CA certificate error if proxy between script and console
    status = apiResponse.status_code

    if (status != 200):
        print("Policies call failed with Status Code: " + str(status))
        exit(-1)
    else:
        if lastExecutionFileExists: 
            policiesChanged = dump_objs_and_analyze_changes (apiResponse, "Policies")
        else:
            dump_objs (apiResponse, "Policies") # Nothing to compare. It just dumps the current configuration

        #----------- Get Alert Rules modified -----------

        action = "GET"
        url = PRISMA_CLOUD_API_URL + read_value_from_sections_file_and_exit_if_not_found (iniFilePath, iniFileParser, 'ALERT_RULES','ALERT_RULES_URL')
        apiResponse = requests.request(action, url, headers=auth_header, verify=False) # verify=False to avoid CA certificate error if proxy between script and console
        status = apiResponse.status_code

        if (status != 200):
            print("Alert Rules call failed with Status Code: " + str(status))
            exit(-1)
        else:
            if lastExecutionFileExists: 
                alertsChanged = dump_objs_and_analyze_changes (apiResponse, "Alert Rules")

                #----------- Get Alert Rules impacted by modified Policies -----------
                
                print("\nAlert Rules impacted by changes in policies:")

                if (len(policiesChanged['Created'])==0) and (len(policiesChanged['Modified'])==0) and (len(policiesChanged['Deleted'])==0):
                    print("\t NONE\n")
                else:
                    analyze_impacted_alerts (apiResponse, policiesChanged['Modified']) # only modified policies need to be analyzed. If an alert rule selects specific policies (not scanAll) and one of its policies is created or deleted, the alert rule will appear as changed in the previous section
            
            else:
                dump_objs (apiResponse, "Alert Rules") # Nothing to compare. It just dumps the current configuration
                
            #----------- Change metadata file at finish (so only properly finished scripts) -----------
                
            if metadataFileExists:
                metadataFileParser.set('LAST_EXECUTION','LAST_FILE_NAME',configFileName)
                with open ('metadata.txt', 'w') as metadatafile:
                    metadataFileParser.write(metadatafile)
            else:
                metadataOutputFile = open ("metadata.txt", 'w', encoding="utf-8")
                write_object_to_file (metadataOutputFile, "[LAST_EXECUTION]\n")
                write_object_to_file (metadataOutputFile, "LAST_FILE_NAME = " + configFileName)

            print("\nExecution finished successfully\n")