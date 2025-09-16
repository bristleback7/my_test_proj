#Importing necessary libraries
import os
import json
import sys
import ast
import pprint
import socket
import argparse
from operator import mod
from typing import Final
from datetime import datetime

from os.path import join as path_join, dirname, realpath
project_root_dir = path_join(dirname(realpath(__file__)), '..', '..')
sys.path.append(project_root_dir)

try:    
    import pydnsbl
    from pydnsbl import providers as pr
    from dotenv import load_dotenv
    import requests
    import dns.resolver
except Exception as e:
    print("Module not installed:",e)

def Base_Domain_Provider_Check(domain_name):
    """
    Takes the domain name and returns the blacklisted or not and detected by list by using 
    the pydnsbl package. 
    Parameters:
        domain_name: The domain name to check blacklisted or not.
    Returns:
        dbl_val: Status of that domain name (blacklisted or not).
        dbl_det: List of the domain providers where this domain name is blacklisted.
    """
    dbl_val=False
    dbl_det=[]
    try:
        domain_checker=pydnsbl.DNSBLDomainChecker()
        result = domain_checker.check(domain_name)
        dbl_val = result.blacklisted
        dbl_det = list(result.detected_by.keys())
    except Exception as e:
        print(e)
    return dbl_val, dbl_det

def Base_IP_Provider_Check(IP):
    """
    Takes the IP and returns the blacklisted or not and detected by list by using 
    the pydnsbl package. 
    Parameters:
        IP: The IP to check blacklisted or not.
    Returns:
        ipbl_val: Status of that IP (blacklisted or not).
        ipbl_det: List of the IP providers where this IP is blacklisted.
    """
    ipbl_val = False
    ipbl_det = []
    try:
        if IP is not None:
            ip_checker = pydnsbl.DNSBLIpChecker()
            result = ip_checker.check(IP)
            ipbl_val = result.blacklisted
            ipbl_det = list(result.detected_by.keys())
    except Exception as e:
        print(e)
    return ipbl_val, ipbl_det

def DomainToIp(hostname):
    """
    Takes the domain and return the ip of that domain.
    Parameters:
        hostname: The domain name to get its IP.
    Returns:
        IP: IP of given domain name.
    """
    try:
        IP = socket.gethostbyname(hostname)
    except Exception as e:
        IP=None
    return IP

def Get_Mx_Records(domain):
    Mx_List=[]
    result = dns.resolver.resolve(domain, 'MX')

    for val in result:
        Mx_List.append(val.to_text().split(" ")[1][:-1])

    return Mx_List

def Get_Mx_Records_From_Hackertarget(domain):
    load_dotenv()
    apikey = os.getenv("HackerTargetAPIKEY")
    Mx_List=[]

    if len(apikey) == 0:
        r = requests.get("https://api.hackertarget.com/dnslookup/?q={}".format(domain))
    else:
        r = requests.get("https://api.hackertarget.com/dnslookup/?q={}&apikey={}".format(domain,apikey))

    p = r.text
    spli = p.split("\n")

    try:
        MX = [s for s in spli if s.startswith("MX :")]
        MX = [j[5:] for j in MX]
    except:
        pass

    for val in MX:
        Mx_List.append(val.split(" ")[1][:-1])
    return Mx_List

def Check_Blacklisted_And_Detected_By(domain):
    """
    Takes mail server as argument and gives the output as blacklisted or not
    and by which it is detected by.
    Parameters:
        domain_name: The domain name to check blacklisted or not.
    Returns:
        Final_Info: Status of the domain and list of providers where it is detected and 
        total length of these providers and len of detected providers.
        
    """
    BlacklistedMailServer=[]
    Mx_list=[]
    Total_Info=[]
    Final_Info={}
    ConfigCheckInfo=None
    ConfigCheckStatus=None
    ConfigCheckDescription=None
    bl_count_sum=0
    iterval=0
    bl_total = len(pr.BASE_DOMAIN_PROVIDERS)+ len(pr._BASE_PROVIDERS)
    try:
        Mx_list=Get_Mx_Records(domain)
        if(len(Mx_list)==0):
            Mx_list=Get_Mx_Records_From_Hackertarget(domain)
    except:
        pass
    
    try:
        for domain_name in Mx_list: 
            #Basse Domain Provider Check
            dbl_val1, dbl_det1=Base_Domain_Provider_Check(domain_name)

            #converting domain to ip
            IP = DomainToIp(domain_name)
            
            #Base IP Provider Check
            ipbl_val1,ipbl_det1 = Base_IP_Provider_Check(IP)
            Final_Info={}

            try:
                dbl_val_final = dbl_val1   or ipbl_val1 
                dbl_det_final = dbl_det1 +ipbl_det1 
                bl_total = len(pr.BASE_DOMAIN_PROVIDERS)  + len(pr._BASE_PROVIDERS) 
                bl_count= len(dbl_det_final) 
                bl_count_sum+=bl_count
                '''Info = {
                    "Blacklisted":dbl_val_final,
                    "Detected_By":dbl_det_final,
                    "Total_Reputed_Blacklists":bl_total,
                    "No_of_Blacklisted_Occurrences":bl_count
                }'''
            except Exception as e:
                print(e)

            Total_Info.append({"MX_Record":domain_name,"Blacklisted":dbl_val_final,
            "Detected_By":dbl_det_final,
            "Total_Reputed_Blacklists":bl_total,
            "No_Of_Blacklisted_Occurrences":bl_count})
            if bl_count>=1:
                BlacklistedMailServer.append(domain_name)

            iterval+=1
    except:
        pass

    ConfigCheckInfo="Mail servers checked in {} blacklists.".format(bl_total)

    if bl_count_sum!=0:
        ConfigCheckStatus="Warning"
        newstrofblacklistedmailserver=", ".join(BlacklistedMailServer)
        ConfigCheckDescription="Found mail servers that are blacklisted."
        ConfigCheckmoreInfo = [{"More Info":"Some of the mail servers are blacklisted as follows: {}.".format(newstrofblacklistedmailserver) +" Having one of the mail servers being blacklisted may affect email delivery and there are bright chances of email servers being hacked by spammers."}]
    else:
        ConfigCheckStatus="Ok"
        ConfigCheckDescription="No occurrences found."
        ConfigCheckmoreInfo =[{"More Info":"The test was performed against reputed blacklist providers to see if any of the mail servers are blacklisted. But, no occurrences are found."}]

    modifiedinfo={}

    if len(Mx_list)!=0:
        modifiedinfo['Mx_Records_Details']=Total_Info
        modifiedinfo['TestName']=ConfigCheckInfo
        modifiedinfo['Status']=ConfigCheckStatus
        modifiedinfo['Description']=ConfigCheckDescription
        modifiedinfo['moreInfo']=ConfigCheckmoreInfo
    else:
        modifiedinfo['Mx_Records_Details']=Total_Info
        modifiedinfo['TestName']=ConfigCheckInfo
        modifiedinfo['Status']="Skipped"
        modifiedinfo['Description']="No Mx Records Found."
        modifiedinfo['moreInfo']=ConfigCheckmoreInfo

    threats = []

    if modifiedinfo["Status"]== "Warning":
        threats.append(modifiedinfo)

    Final_Info={'Domain':domain,'Test_Results':modifiedinfo,"threats":threats, "extSource": "pydnsbl Python Module"}
    pprint.pprint(Final_Info)
    return Final_Info

def main(domain, scan_id):
    data = Check_Blacklisted_And_Detected_By(domain)

    if data is not None:
        pprint.pprint(data)
        print(f'[ + ] Task is completed for dnslookup for scan ID {scan_id} ({domain})!')
    else:
        print(
            'Error: Recieved `None` from the getData() function!',
            file=sys.stderr
        )
        sys.exit(1)

if __name__ == '__main__':
    domain, scan_id = 'abbvie.com', 17823
    main(domain, scan_id)
