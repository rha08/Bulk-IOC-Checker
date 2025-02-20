import os
import pandas as pd
from API import Hash, IPAddress, Domain

path = input("Please enter the file path: ")

# file path check
if not os.path.exists(path):
    print("The file path is incorrect")
    quit()

df = pd.read_excel(path)

# check to see whether the file is empty
if df.empty:
    print("The file is empty.")
    quit()

# column heads check
if df.columns[0] != "IOC_Value":
    print("Column 1 not as per expected input 'IOC_Value'")
    quit()

elif df.columns[1] != "IOC_Type":
    print("Column 2 not as per expected input 'IOC_Type'")
    quit()

# IOC type values check
count = 1
error = ""
for i in df["IOC_Type"]:
    if i not in ["IP_Address_V4", "IP_Address_V6", "Email_Address", "Domain", "URL", "MD5_Hash", "SHA256_Hash"]:
        error = error + f"Row{count}:Column2 "
    count = count + 1

if error != "":
    print(f"Unexpected value present in {error}")
    quit()

# sort by IOC type
df = df.sort_values(by="IOC_Type")
df.reset_index(drop=True, inplace=True)

result = list(" " * len(df["IOC_Type"]))

# perform lookup
for index, IOC_type in enumerate(df["IOC_Type"]):

    if IOC_type == "MD5_Hash" or IOC_type == "SHA256_Hash":

        hash1 = Hash(df["IOC_Value"][index])
        response = hash1.virustotal()

    elif IOC_type == "IP_Address_V4" or IOC_type == "IP_Address_V6":

        ipaddress1 = IPAddress(df["IOC_Value"][index])
        response = ipaddress1.abuseipdb()

    elif IOC_type == "Domain":

        domain1 = Domain(df["IOC_Value"][index])
        response = domain1.alienvault()

    # valid response check
    if response in ["Malicious", "Clean"]:
        result[index] = response

    elif response == "API_Limit":
        print(f"Row{index+1}:Column1 --> API Limit Reached")

    else:
        print(f"Row{index+1}:Column1 --> {response}")

# updating the excel file
df["Result"] = result
df.to_excel(path, index=False)