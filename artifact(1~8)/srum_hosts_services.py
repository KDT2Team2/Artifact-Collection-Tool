import psutil
import csv
import subprocess
import pandas as pd
import os

def get_srum():
    srudb_path = r'C:\Windows\System32\sru\SRUDB.DAT'
    registy_path = r'C:\Windows\System32\config\SOFTWARE'
    cmd = f'srum_dump.exe -i {srudb_path} -r {registy_path} -o srum_report.xls'

    try:
        subprocess.run(args=cmd,text=True,stdout=subprocess.DEVNULL)
    except Exception as e:
        print(e)
    finally:
        if os.path.exists('srum_report.xls'):
            xlsx = pd.read_excel('srum_report.xls')
            xlsx.to_csv('srum_report.csv')
            os.remove('srum_report.xls')
 
def get_hosts():# Get information about hosts
    try:
        host_info = psutil.net_if_addrs()
        family_dict = {2:'AF_INET',23:'AF_INET6',-1:'AF_LINK'}
        hosts_csv = csv.writer(open("hosts_report.csv",'w',newline=""), dialect=csv.excel, quoting=1)
        hosts_csv.writerow(['Interface','Family','Netmask','Broadcast'])
        for interface, addresses in host_info.items():
            for address in addresses:
                hosts_csv.writerow([interface,family_dict[address.family],address.address,address.netmask,address.broadcast])
    except Exception as e:
        print(f"Error retrieving host information: {e}")
        print("\n")

def get_services():# Get information about services
    try:
        services_info = psutil.win_service_iter()
        services_csv = csv.writer(open("services_report.csv","w",newline=""), dialect=csv.excel, quoting=1)
        services_csv.writerow(['Service Name','Display Name','Status'])
        for service in services_info:
            services_csv.writerow([service.name(),service.display_name(),service.status()])
    except Exception as e:
        print(f"Error retrieving services information: {e}")
        print("\n")

# if __name__ == "__main__":
#     get_srum()
#     get_services()
#     get_hosts()
