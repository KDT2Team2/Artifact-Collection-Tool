import winreg
import csv

def get_reg_value_autorun(key_path):
    with open('autorun.csv', 'a', newline="") as f:
        csv_writer = csv.writer(f)

        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                for j in range(0, winreg.QueryInfoKey(key)[1]):
                    auto_run_info = winreg.EnumValue(key, j)
                    csv_writer.writerow([auto_run_info[0], auto_run_info[1], auto_run_info[2]])
        except Exception as e:
            print(f"[-] An error occurred: {e}")

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                for j in range(0, winreg.QueryInfoKey(key)[1]):
                    auto_run_info = winreg.EnumValue(key, j)
                    csv_writer.writerow([auto_run_info[0], auto_run_info[1], auto_run_info[2]])
        except Exception as e:
            print(f"[-] An error occurred: {e}")

def get_auto_run_list():
    auto_run_list = ['Software\Microsoft\Windows\CurrentVersion\Run', 'Software\Microsoft\Windows\CurrentVersion\RunOnce']
    # CSV 객체 생성
    with open('autorun.csv', 'w', newline="") as f:
        csv_writer = csv.writer(f)
        csv_writer.writerow(['Process Name', 'Process Path', 'Status'])
        
    for key_path in auto_run_list:
        get_reg_value_autorun(key_path)
