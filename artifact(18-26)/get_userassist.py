import winreg
import codecs
import csv

def csv_writer(files):
    with open('userassist.csv', 'w', newline="") as f:
        csv_writer = csv.writer(f)
        csv_writer.writerow(['File Name'])
        
        for i in range(len(files)):
            csv_writer.writerow([files[i]])
    
def GetRegValue_userassist(key_path):
    userassist_list = []
    # try:
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
        f = open('userassist.csv', 'w')
        csv_writer = csv.writer(f)
        csv_writer.writerow(['File Name'])
        for i in range(0, winreg.QueryInfoKey(key)[0]):
            userassist = winreg.EnumKey(key, i)
            userassist_key_path = f"{key_path}\{userassist}\count"
            
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, userassist_key_path) as userassist_key:
                for j in range(0, winreg.QueryInfoKey(userassist_key)[1]):
                    userassist_key_name = winreg.EnumValue(userassist_key, j)
                    try:
                        decrypted_userassist = codecs.decode(userassist_key_name[0], 'rot_13')
                        userassist_list.append(decrypted_userassist)
                    except:
                        userassist_list.append(userassist_key_name[0])
                        continue
    return userassist_list

def GetUserAssist():
    userassist_list = GetRegValue_userassist(r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist")                    
    csv_writer(userassist_list)
