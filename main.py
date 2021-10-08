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

def load_api_config (iniFilePath):
    if not os.path.exists(iniFilePath):
        return_error("Config file " + iniFilePath + " does not exist")
    iniFileParser = get_parser_from_sections_file (iniFilePath)
    api_config = {}
    api_config['BaseURL'] = read_value_from_sections_file_and_exit_if_not_found (iniFilePath, iniFileParser, 'URL', 'URL')
    api_config['AccessKey'] = read_value_from_sections_file_and_exit_if_not_found (iniFilePath, iniFileParser, 'AUTHENTICATION', 'ACCESS_KEY_ID')
    api_config['SecretKey'] = read_value_from_sections_file_and_exit_if_not_found (iniFilePath, iniFileParser, 'AUTHENTICATION', 'SECRET_KEY')
    return api_config

def handle_api_response (apiResponse):
    status = apiResponse.status_code
    if (status != 200):
        return_error ("API call failed with HTTP response " + str(status))

def run_api_call_with_payload (action, url, headers_value, payload):
    apiResponse = requests.request(action, url, headers=headers_value, data=json.dumps(payload), verify=False) # verify=False to avoid CA certificate error if proxy between script and console
    handle_api_response(apiResponse)
    return apiResponse

def run_api_call_without_payload (action, url, headers_value):
    apiResponse = requests.request(action, url, headers=headers_value, verify=False) # verify=False to avoid CA certificate error if proxy between script and console
    handle_api_response(apiResponse)
    return apiResponse

def login (api_config):
    action = "POST"
    url = api_config['BaseURL'] + "/login"
    headers = {
        'Content-Type': 'application/json'
    }
    payload = {
        'username': api_config['AccessKey'],
        'password': api_config['SecretKey'],
    }
    apiResponse = run_api_call_with_payload (action, url, headers, payload)
    authentication_response = apiResponse.json()
    token = authentication_response['token']
    return token

def get_policies (api_config):
    action = "GET"
    url = api_config['BaseURL'] + "/v2/policy"
    headers = {
        'x-redlock-auth': api_config['Token']
    }
    apiResponse = run_api_call_without_payload (action, url, headers)
    policies = apiResponse.json()
    return policies

def get_alertRules (api_config):
    action = "GET"
    url = api_config['BaseURL'] + "/v2/alert/rule"
    headers = {
        'x-redlock-auth': api_config['Token']
    }
    apiResponse = run_api_call_without_payload (action, url, headers)
    alertRules = apiResponse.json()
    return alertRules

def load_info_from_last_execution_file (lastExecutionfilePath):
    dataLastExecution = {}
    dataLastExecution['metadataFileExists'] = False
    dataLastExecution['lastExecutionFileExists'] = False
    if os.path.exists(lastExecutionfilePath): # validate metadata file exists and last file execution is found
        dataLastExecution['metadataFileExists'] = True
        dataLastExecution['metadataFileParser'] = get_parser_from_sections_file (lastExecutionfilePath)
        readLastFileName = read_value_from_sections_file (dataLastExecution['metadataFileParser'], 'LAST_EXECUTION','LAST_FILE_NAME')
        if readLastFileName['Exists']:
            lastFileName = (readLastFileName['Value'])
            if os.path.exists(lastFileName):
                dataLastExecution['lastExecutionFileExists'] = True
    if dataLastExecution['lastExecutionFileExists']:
        print ("Previous execution found. Analyzing changes. Please wait...")
        lastFileCreated = open (lastFileName)
        allLinesLastExecution = lastFileCreated.readlines()
        dataLastExecution['policiesLastExecution'] = []
        dataLastExecution['alertRulesLastExecution'] = []
        for i in range(len(allLinesLastExecution)):
            if 'policyId' in allLinesLastExecution[i]:
                dataLastExecution['policiesLastExecution'].append(allLinesLastExecution[i]+ " >>>>>> " + allLinesLastExecution[i+1])
            elif 'policyScanConfigId' in allLinesLastExecution[i]:
                dataLastExecution['alertRulesLastExecution'].append(allLinesLastExecution[i]+" >>>>>> " + allLinesLastExecution[i+1])
    else:
        print("No previous execution to compare. Pulling current config. Please wait...") # Nothing to load. It goes directly to next section
    return dataLastExecution

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

def dump_objs (configOutputFile, objsList, objsType):
    if (objsType == "Policies"):
        write_object_to_file (configOutputFile, "---------- POLICIES ----------\n")
    elif (objsType == "Alert Rules"):
        write_object_to_file (configOutputFile, "\n\n---------- ALERT RULES ----------\n")
    for i in range(len(objsList)):
        obj=objsList[i]
        if (objsType == "Policies"):
            obj = filter_useful_policy_values (obj)
        write_object_to_file_adding_hash (configOutputFile, obj) # it writes all current objects 1 by 1 it to the file

def dump_objs_and_analyze_changes (dataLastExecution, configOutputFile, objsList, objsType):
    objsChanged = {}
    objsChanged['Created'] = []
    objsChanged['Modified'] = []
    objsChanged['Deleted'] = []

    if (objsType == "Policies"):
        objsChanged['Deleted'] = dataLastExecution['policiesLastExecution'] # it starts will all previous results and will be removed if they exist in this execution
        write_object_to_file (configOutputFile, "---------- POLICIES ----------\n")
    elif (objsType == "Alert Rules"):
        objsChanged['Deleted'] = dataLastExecution['alertRulesLastExecution'] # it starts will all previous results and will be removed if they exist in this execution
        write_object_to_file (configOutputFile, "\n\n---------- ALERT RULES ----------\n")

    for i in range(len(objsList)):
        obj=objsList[i]
        if (objsType == "Policies"):
            obj = filter_useful_policy_values (obj)
        write_object_to_file_adding_hash (configOutputFile, obj) # it writes all current objects 1 by 1 it to the file
        currentHash = hash_dictionary(obj)
        if (objsType == "Policies"):
            idExistedInLastExecution = any (obj['policyId'] in string for string in dataLastExecution['policiesLastExecution'])
            hashExistedInLastExecution = any (currentHash in string for string in dataLastExecution['policiesLastExecution'])
        elif (objsType == "Alert Rules"):
            idExistedInLastExecution = any (obj['policyScanConfigId'] in string for string in dataLastExecution['alertRulesLastExecution'])
            hashExistedInLastExecution = any (currentHash in string for string in dataLastExecution['alertRulesLastExecution'])
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

def analyze_impacted_alerts (alertRulesList, policiesModified):
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

def update_metadata_file(metadataFileName, dataLastExecution, configFileName):
    if dataLastExecution['metadataFileExists']:
        dataLastExecution['metadataFileParser'].set('LAST_EXECUTION','LAST_FILE_NAME',configFileName)
        with open ('metadata.txt', 'w') as metadatafile:
            dataLastExecution['metadataFileParser'].write(metadatafile)
    else:
        metadataOutputFile = open (metadataFileName, 'w', encoding="utf-8")
        write_object_to_file (metadataOutputFile, "[LAST_EXECUTION]\n")
        write_object_to_file (metadataOutputFile, "LAST_FILE_NAME = " + configFileName)

def main():

    #----------- Load info from last execution file (if any) -----------
    
    metadataFileName = "metadata.txt"
    dataLastExecution = load_info_from_last_execution_file (metadataFileName)
        
    #----------- Prepare this execution file -----------

    configFileName = datetime.datetime.now().strftime("%Y%m%d-%I%M%S%p") + ".txt"
    configOutputFile = open (configFileName, 'w', encoding="utf-8")

    #----------- Load API configuration from .ini file -----------

    api_config = load_api_config ("API_config.ini")

    #----------- First API call for authentication -----------

    token = login(api_config)
    api_config['Token'] = token
    
    #----------- Get policies changed -----------

    policiesList = get_policies (api_config)
    if not dataLastExecution['lastExecutionFileExists']:
        dump_objs (configOutputFile, policiesList, "Policies") # Nothing to compare. It just dumps the current configuration
    else:
        policiesChanged = dump_objs_and_analyze_changes (dataLastExecution, configOutputFile, policiesList, "Policies")

    #----------- Get Alert Rules changed -----------

    alertRulesList = get_alertRules (api_config)
    if not dataLastExecution['lastExecutionFileExists']:
        dump_objs (configOutputFile, alertRulesList, "Alert Rules") # Nothing to compare. It just dumps the current configuration
    else:
        alertRulesChanged = dump_objs_and_analyze_changes (dataLastExecution, configOutputFile, alertRulesList, "Alert Rules")

        #----------- Get Alert Rules impacted by modified Policies -----------
            
        print("\nAlert Rules impacted by changes in policies:")

        if (len(policiesChanged['Created'])==0) and (len(policiesChanged['Modified'])==0) and (len(policiesChanged['Deleted'])==0):
            print("\t NONE\n")
        else:
            analyze_impacted_alerts (alertRulesList, policiesChanged['Modified']) # only modified policies need to be analyzed. If an alert rule selects specific policies (not scanAll) and one of its policies is created or deleted, the alert rule will appear as changed in the previous section
            
    #----------- Update metadata file at finish (so only properly finished scripts) -----------

    update_metadata_file (metadataFileName, dataLastExecution, configFileName)
    print("\nExecution finished successfully\n")

if __name__ == "__main__":
    main()