from datetime import datetime
import os
import pandas as pd

# 시간 수정 필요
def LinkFileParser(files):
    filename, createtime_list, modifiedtime_list, accesstime_list = [], [],[], []
    
    for j in files:
        createtime_list.append(datetime.fromtimestamp(os.path.getctime(j)))
        modifiedtime_list.append(datetime.fromtimestamp(os.path.getmtime(j)))
        accesstime_list.append(datetime.fromtimestamp(os.path.getatime(j)))
        filename.append(j)
    df = pd.DataFrame({
        'FileName': filename,
        'CreatedTime': createtime_list,
        'ModifiedTime': modifiedtime_list,
        'Accesstime': accesstime_list
    })
    df.to_csv('lnk.csv')
    
def GetLinkFile(user):
    # window 7~10 : C:\Users\%USERNAME%\AppData\Roaming\Microsoft\Windows\Recent
    # window xp : C:\Documents and Settings\%USERNAME%\Recent
    lnk_file_path = f"{user}\AppData\Roaming\Microsoft\Windows\Recent"
    lnk_file_list = []
    lnk_file_pull_list = []
    
    if os.path.exists(lnk_file_path):
        lnk_file_list = os.listdir(lnk_file_path)
        for i in lnk_file_list:
            lnk_file_pull_list.append(f"{lnk_file_path}\{i}")
    else:
        print("[-] Lnk 파일 경로가 올바르지 않음")
        
    LinkFileParser(lnk_file_pull_list)
    
    
