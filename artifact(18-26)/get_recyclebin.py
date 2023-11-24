import getpass
import winreg
import os
import csv
import chardet
import time

def GetRegValue_sid(user_name, key_path):
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
        sid_list = []
        i = 0
        while True:
            try:
                sid = winreg.EnumKey(key, i)
                sid_list.append(sid)
                sid_key_path = f"{key_path}\{sid}"
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sid_key_path) as sid_key:
                    profile_path, _= winreg.QueryValueEx(sid_key, "ProfileImagePath")
                    if user_name.lower() in profile_path.lower():
                        return sid
                i += 1
            except:
                break



def deleted_file_analysis(file, file_path):
    # 원본 파일
    origin_file = f"$R{file[2:]}"
    origin_file_path = f"{file_path}\\{origin_file}"
    
    # 삭제된 파일
    deleted_file_path = f"{file_path}\\{file}"
    print(deleted_file_path)

    with open(deleted_file_path, 'rb') as f:
        raw_data = f.read()
        # 인코딩 확인
        result = chardet.detect(raw_data)
        encoding = result['encoding']

        try:
            content = raw_data.decode(encoding)
            deleted_file_analysis_path = content[28:].replace('\x00', '')
            
            creation_time = os.path.getctime(deleted_file_path)
            creation_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(creation_time))

            modified_time = os.path.getmtime(deleted_file_path)
            modified_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(modified_time))

            access_time = os.path.getatime(deleted_file_path)
            access_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(access_time))
            
            print(f"{creation_time}, {access_time}, {modified_time}")
            
            file_size = str(os.path.getsize(origin_file_path))
            print(file_size)
        except UnicodeDecodeError as e:
            print(f"[-] 인코딩 오류 발생 : {e}")
        except Exception as e:
            print(f"다른 오류 발생 : {e}")

def GetRecycleBin():
        f = open('userassist.csv', 'w')
        csv_writer = csv.writer(f)
        csv_writer.writerow(['File Name'])
        
        # 사용자 이름
        user_name = getpass.getuser()
        join_user_name = f"C:\\Users\\{user_name}"
        print(join_user_name)
        # Recycle 경로
        recycle_path = 'C:\\$Recycle.Bin\\'
        
        # PC별 Sid 값 추출
        sid = GetRegValue_sid(join_user_name, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList")
        personal_recycle_path = f"{recycle_path}{sid}"
        
        # Sid 값에 알맞는 Recycle.Bin 경로 존재 시
        if os.path.exists(personal_recycle_path):
            recycle_files = os.listdir(personal_recycle_path)
            for deleted_file in recycle_files:
                if deleted_file == "desktop.ini":
                    continue
                else:
                    deleted_file_analysis(deleted_file, personal_recycle_path)
        else:
            print("[-] Recycle Bin 파싱 중 경로 문제 발생")

# $Action(Deleted File, Original File), Full Fath(원본 경로), File Size, File Created, ~ Source, Source File($~)
