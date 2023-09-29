import Get_R2_Analysis_info as R2
import Packing_Crypto_YARA as pc_yara
import VirusTotal as VT
import os


print("Welcome to Odissa....")

Binary_Path = input("Enter the binary path(Full path please): ")

directory_name = (os.path.basename(Binary_Path).split('/')[-1]).split('.')[0]+"_Analysis"
if (not os.path.exists(directory_name)):
    os.makedirs(directory_name)

directory_path = os.path.abspath(directory_name)

VT_Choise = input("Do you want to scan the file using VirusTotal ?(y/n): " )

if VT_Choise == 'y' or VT_Choise == 'Y':
    API_KEY = input("Enter your VirusTotla API key (you will find it in your account): ")
    if API_KEY is not None:
        VT.main(API_KEY, Binary_Path,  directory_name)

print("Analyzing Starting................")

pc_yara.Packing_Crypto_Detection(Binary_Path, directory_path)

R2.GetStaticAnalysisInformation(Binary_Path, directory_path)        

print("Analyzing finished................")
print("Check to folder contained files in the tool folder....")
