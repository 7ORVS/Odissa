import vt
import requests
import hashlib
import json

def calc_id(file_path) :
    with open(file_path,"rb") as f:
        bytes = f.read() # read entire file as bytes
        hash = hashlib.sha256(bytes).hexdigest();
    return hash

def VirusTotla_Scan(InputFile, OutputFolder, API_KEY):
    with open(OutputFolder+"/VT_Scan_Result.txt", "w") as output:

        with open(InputFile, "rb") as file:
            
            # Access and print the scan_id
            client = vt.Client(API_KEY)
            analysis = client.scan_file(file, wait_for_completion=True)
            output.write("Scan ID:" + str(analysis.id))
            output.write("\n")
            output.write("==========================================================================================================================\n")
            output.write("\n")
            # Access and print the scan results
            output.write("Vendors Results: \n")
            for vendor in analysis.results:
                if str(analysis.results[vendor]['category']) == 'malicious':
                    output.write(vendor + " : " + str(analysis.results[vendor]['category']) + " , " + str(analysis.results[vendor]['result']) + "\n")
            output.write("\n")
            output.write("==========================================================================================================================\n")
            output.write("Number of Vendors that marks this file as a malicious: " + str(analysis.stats['malicious']) + "\n")
            output.write("==========================================================================================================================\n")

def Sandbox_result (ID , OutputFolder, API_KEY):  

    id = ID
    
    url = "https://www.virustotal.com/api/v3/file_behaviours/"+id+"_Microsoft%20Sysinternals"

    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY
    }

    response = requests.get(url, headers=headers)

    json_Data = response.json()

    with open(OutputFolder+"/Microsoft_Sysinternal_Sandbox.txt", "w") as output:
        if "error" in json_Data:
            output.write(json_Data["error"]["message"])  
            

        else:
            interesting_data = json_Data["data"]["attributes"]
            if "command_executions" in interesting_data:
                output.write("Executed Commands: \n\n")
                for command in interesting_data["command_executions"]:
                    output.write(command+"\n")
                output.write("==========================================================================================================================\n")
            if "ip_traffic" in interesting_data:    
                output.write("IP Traffics: \n\n")
                for traffic in interesting_data["ip_traffic"]:
                    for ip in traffic:
                        output.write(str(traffic[ip])+ "\n")
                    output.write("----------------------------------------\n")
                output.write("==========================================================================================================================\n")
            
            
            if "dns_lookups" in interesting_data:
                output.write("DNS lookup: \n\n")    
                resolved_ips = interesting_data["dns_lookups"]
                for diction in resolved_ips:
                    if "resolved_ips" in diction:
                        output.write("Resolved IPs: \n")
                        for ip in diction["resolved_ips"]:
                            output.write(ip+"\n")
                        output.write("Hostname: \n")
                        output.write(diction["hostname"]+"\n")
                    else:
                        output.write("Hostname: \n")
                        output.write(diction["hostname"]+"\n")
                    output.write("----------------------------------------\n")
                output.write("==========================================================================================================================\n")

            if "registry_keys_set" in interesting_data:
                output.write("Regisrty set operations: \n\n")
                for RegOp in interesting_data["registry_keys_set"]:
                    output.write("Value: ")
                    output.write(RegOp["value"]+"\n")
                    output.write("Key: ")
                    output.write(RegOp["key"]+"\n")
                    output.write("----------------------------------------\n")
                output.write("==========================================================================================================================\n")
            
            if "files_deleted" in interesting_data:  
                output.write("Deleted files: \n\n")
                for DFiles in interesting_data["files_deleted"]:
                    output.write(DFiles+"\n")
                output.write("==========================================================================================================================\n")
            
            if "files_dropped" in interesting_data:  
                output.write("Dropped files: \n\n")
                for DrFiles in interesting_data["files_dropped"]:
                    output.write(str(DrFiles['path'])+"\n")
                output.write("==========================================================================================================================\n")

            if "prpcesses_created" in interesting_data:  
                output.write("Created processes \n\n")
                for CProcess in interesting_data["processes_created"]:
                    output.write(CProcess+"\n")
                output.write("==========================================================================================================================\n")

            if "processes_terminated" in interesting_data:  
                output.write("Terminated prcesses: \n\n")
                for TProcess in interesting_data["processes_terminated"]:
                    output.write(TProcess+"\n")

def main (API_KEY, InputFile, OutputFolder):
    File_ID = calc_id(InputFile)
    VirusTotla_Scan(InputFile, OutputFolder, API_KEY)
    Sandbox_result (File_ID , OutputFolder, API_KEY)
    

