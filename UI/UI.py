import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import csv
import os
import tkinter
import socket
import psutil
import win32evtlog
import win32evtlogutil
import win32gui
import win32con
import win32service
import re
from scapy.all import *
import pythoncom
import win32com.client
import hashlib
import psutil
from datetime import datetime
import time
import winreg
import pandas as pd
from datetime import datetime
import codecs
import getpass
import chardet



global canvas
output_directory = ""
status_window = None
trees = {}

# 사용자 지정 경로 설정 함수
def browse_output_directory():
    global output_directory
    directory = filedialog.askdirectory()
    if directory:
        output_entry.delete(0, tk.END)
        output_entry.insert(0, directory)
        output_directory = directory

def set_default_output_directory():
    global output_directory
    default_directory = os.getcwd()
    output_entry.delete(0, tk.END)
    output_entry.insert(0, default_directory)
    output_directory = default_directory

def execute_and_save_artifacts():
    for artifact, var in variables.items():
        if var.get():
            func = artifact_functions.get(artifact)
            if func:
                func(output_directory)


# == 아티팩트 함수 ==========================================================================================================================
def memory_dump_func(output_directory):
    return 1

def prefetch_func(output_directory):
    return 1

def NTFS_func(output_directory):
    return 1

def sys_info_func(output_directory):
    return 1

def regi_hive(output_directory):
    return 1

def event_viewer_log_func(output_directory):
    return 1

def enviornment_func(output_directory):
    return 1

def patch_list_func(output_directory):
    update_session = win32com.client.Dispatch("Microsoft.Update.Session")
    update_searcher = update_session.CreateUpdateSearcher()

    history_count = update_searcher.GetTotalHistoryCount()
    updates = update_searcher.QueryHistory(0, history_count)

    with open(os.path.join(output_directory, '패치 리스트.csv'), 'w', newline='', encoding='utf-8-sig') as file:
        writer = csv.writer(file)
        writer.writerow(['Title', 'Update ID', 'Version', 'Date'])

        for update in updates:
            title = update.Title

            kb_pattern = r"KB\d+"
            version_pattern = r"\(버전\s([\d.]+)\)"

            kb_match = re.search(kb_pattern, title)
            version_match = re.search(version_pattern, title)

            kb_number = kb_match.group(0) if kb_match else "KB 정보 없음"
            version = version_match.group(1) if version_match else "버전 정보 없음"

            title_only = title.split(" - ")[0] if " - " in title else title

            writer.writerow([title_only, kb_number, version, str(update.Date)])

def process_list_info_func(output_directory):
    with open(os.path.join(output_directory, '실행 프로세스 목록 정보.csv'), 'w', newline='', encoding='utf-8-sig') as file:
        writer = csv.writer(file)
        writer.writerow(['Process ID', 'Process name', 'Process path', 'Process creat time', 'Process access time', 'Process modify time', 'Process size', 'hash value(sha-256)'])

        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            process_info = proc.info
            file_path = process_info.get("exe")
            if file_path and os.path.isfile(file_path):
                creation_time = os.path.getctime(file_path)
                access_time = os.path.getatime(file_path)
                modification_time = os.path.getmtime(file_path)
                
                file_size = os.path.getsize(file_path)

                hash_md5 = hashlib.sha256()
                with open(file_path, 'rb') as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        hash_md5.update(chunk)
                hash_value = hash_md5.hexdigest()

                writer.writerow([
                    process_info['pid'],
                    process_info['name'],
                    file_path,
                    datetime.fromtimestamp(creation_time).strftime('%Y-%m-%d %H:%M:%S'),
                    datetime.fromtimestamp(access_time).strftime('%Y-%m-%d %H:%M:%S'),
                    datetime.fromtimestamp(modification_time).strftime('%Y-%m-%d %H:%M:%S'),
                    file_size,
                    hash_value
                ])
            else:
                process = psutil.Process(process_info['pid'])
                writer.writerow([
                    process.pid,
                    process.name(),
                    'N/A',
                    datetime.fromtimestamp(process.create_time()).strftime('%Y-%m-%d %H:%M:%S'),
                    'N/A',
                    'N/A',
                    'N/A',
                    'N/A'
                ])

def connection_info_func(output_directory):
    host_name = socket.gethostname()

    with open(os.path.join(output_directory, '연결 정보 (열려진 포트).csv'), 'w', newline='', encoding='utf-8-sig') as file:
        writer = csv.writer(file)
        writer.writerow(['Port Number'])

        ports = range(1, 65535)
        
        packets = [IP(dst=host_name)/TCP(dport=port, flags="S") for port in ports]
        responses, _ = sr(packets, timeout=1, verbose=0)

        for sent, received in responses:
            if received.haslayer(TCP) and received[TCP].flags == 18:
                writer.writerow([sent[TCP].dport])

def ip_setting_info_func(output_directory):
    with open(os.path.join(output_directory, 'IP 설정 정보.csv'), 'w', newline='', encoding='utf-8-sig') as file:
        writer = csv.writer(file)
        writer.writerow(['Interface', 'IP Address', 'Netmask', 'Broadcast Address'])
        
        net_if_stats = psutil.net_if_stats()
        
        for interface, stats in net_if_stats.items():
            if stats.isup:
                addresses = psutil.net_if_addrs().get(interface, [])
                for address in addresses:
                    if address.family == socket.AF_INET:
                        writer.writerow([
                            interface, 
                            address.address, 
                            address.netmask, 
                            address.broadcast
                        ])

def ARP_info_func(output_directory):
    arp_table = os.popen('arp -a').read()

    with open(os.path.join(output_directory, 'ARP 정보.csv'), 'w', newline='', encoding='utf-8-sig') as file:
        writer = csv.writer(file)
        writer.writerow(['IP Address', 'Physical Address', 'Type'])

        lines = arp_table.split('\n')
        for line in lines:
            if line.strip() and 'internet address' not in line.lower():
                parts = line.split()
                if len(parts) == 3:
                    type_value = 'static' if parts[2] == '정적' else 'dynamic' if parts[2] == '동적' else parts[2]
                    writer.writerow([parts[0], parts[1], type_value])

def NetBIOS_info_func(output_directory):
    with open(os.path.join(output_directory, 'NetBIOS 정보.csv'), 'w', newline='', encoding='utf-8-sig') as file:
        writer = csv.writer(file)
        writer.writerow(['Network Name', 'IP Address', 'NetBIOS name', 'NetBIOS type', 'NetBIOS status'])

        result = os.popen('nbtstat -n').read()
        ethernet_tables = re.split(r'([^\n]*):\n노드', result, flags=re.DOTALL)[1:]
        ip_pattern = r'IpAddress: \[([\d.]+)\] 범위 ID: \[\]'
        netbios_pattern = r'(\S+)\s+([A-Z]+)\s+(\S+)'

        for i in range(0, len(ethernet_tables), 2):
            adapter_name = ethernet_tables[i].strip()
            ethernet_table = ethernet_tables[i + 1]

            ip_match = re.search(ip_pattern, ethernet_table, re.DOTALL)
            if ip_match:
                ip_address = ip_match.group(1)

            netbios_matches = re.findall(netbios_pattern, ethernet_table)
            if netbios_matches:
                for match in netbios_matches:
                    name, netbios_type, status = match
                    status = 'registration' if status == '등록됨' else 'collision' if status == '충돌' else status

                    writer.writerow([adapter_name, ip_address, name, netbios_type, status])
            else:
                    writer.writerow([adapter_name, ip_address, None, None, None])

def open_handle_info_func(output_directory):
    def callback(_hwnd, _result: list):
        title = win32gui.GetWindowText(_hwnd)
        if win32gui.IsWindowEnabled(_hwnd) and win32gui.IsWindowVisible(_hwnd) and title and len(title) > 0:
            _result.append(_hwnd)
        return True

    result = []
    win32gui.EnumWindows(callback, result)

    with open(os.path.join(output_directory, '열려있는 핸들 정보.csv'), 'w', newline='', encoding='utf-8-sig') as file:
        writer = csv.writer(file)
        writer.writerow(['Window Number', 'Window Title', 'Window Class', 'Visible'])

        for _hwnd in result:
            writer.writerow([
                _hwnd, 
                win32gui.GetWindowText(_hwnd),
                win32gui.GetClassName(_hwnd),
                win32gui.IsWindowVisible(_hwnd)
            ])

def work_schedule_info_func(output_directory):
    with open(os.path.join(output_directory, '작업 스케쥴 정보.csv'), 'w', newline='', encoding='utf-8-sig') as file:
        writer = csv.writer(file)
        writer.writerow(["Task name", "Last run Time", "Next run Time", "Enabled", "Trigger Count", "Action Count"])

        scheduler = win32com.client.Dispatch("Schedule.Service")
        scheduler.Connect()
        folders = [scheduler.GetFolder("\\")]

        while folders:
            folder = folders.pop(0)
            folders += list(folder.GetFolders(0))
            tasks = list(folder.GetTasks(0))

            for task in tasks:
                settings = task.Definition.Settings
                triggers = task.Definition.Triggers
                actions = task.Definition.Actions

                writer.writerow([task.Name, task.LastRunTime, task.NextRunTime, task.Enabled, triggers.Count, actions.Count])

def sys_logon_info_func(output_directory):
    server = 'localhost'
    log_type = ['Application', 'System', 'Security', 'Setup', 'Forwarded Events']
    query = 'logon'

    with open(os.path.join(output_directory, '시스템 로그온 정보.csv'), 'w', newline='', encoding='utf-8-sig') as file:
        writer = csv.writer(file)
        writer.writerow(['Log Type', 'Event ID', 'Source', 'Time Generated', 'Time Written', 'Event Category', 'Event Type'])

        for logtype in log_type:
            hand = win32evtlog.OpenEventLog(server, logtype)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            while events:
                for event in events:
                    if query in win32evtlogutil.SafeFormatMessage(event, logtype):
                        writer.writerow([
                            logtype,
                            event.EventID,
                            event.SourceName,
                            event.TimeGenerated,
                            event.TimeWritten,
                            event.EventCategory,
                            event.EventType
                        ])
                events = win32evtlog.ReadEventLog(hand, flags, 0)

def regi_service_info_func(output_directory):
    resume = 0
    accessSCM = win32con.GENERIC_READ
    accessSrv = win32service.SC_MANAGER_ALL_ACCESS

    hscm = win32service.OpenSCManager(None, None, accessSCM)

    typeFilter = win32service.SERVICE_WIN32
    stateFilter = win32service.SERVICE_STATE_ALL

    statuses = win32service.EnumServicesStatus(hscm, typeFilter, stateFilter)

    output_path = os.path.join(output_directory, '등록된 서비스 정보.csv')
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        csv_writer = csv.writer(f)
        csv_writer.writerow(['Short Name', 'Description', 'Status'])

        for (short_name, desc, status) in statuses:
            csv_writer.writerow([short_name, desc, status])

def recent_act_info_func(output_directory):
    return 1

def userassist_func(output_directory):
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
    userassist_list = []

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
            for i in range(0, winreg.QueryInfoKey(key)[0]):
                userassist = winreg.EnumKey(key, i)
                userassist_key_path = f"{key_path}\{userassist}\Count"

                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, userassist_key_path) as userassist_key:
                    for j in range(0, winreg.QueryInfoKey(userassist_key)[1]):
                        userassist_key_name = winreg.EnumValue(userassist_key, j)
                        try:
                            decrypted_userassist = codecs.decode(userassist_key_name[0], 'rot_13')
                            userassist_list.append(decrypted_userassist)
                        except:
                            userassist_list.append(userassist_key_name[0])
                            continue

        # 결과를 CSV 파일에 쓰기
        with open(os.path.join(output_directory, 'UserAssist.csv'), 'w', newline="") as f:
            csv_writer = csv.writer(f)
            csv_writer.writerow(['File Name'])
            for item in userassist_list:
                csv_writer.writerow([item])

    except Exception as e:
        print(f"[-] UserAssist 값 파싱 중 오류 발생: {e}")

def autorun_func(output_directory):
    auto_run_list = [
        'Software\Microsoft\Windows\CurrentVersion\Run', 
        'Software\Microsoft\Windows\CurrentVersion\RunOnce'
    ]

    # CSV 파일 생성
    with open(os.path.join(output_directory, 'AutoRun.csv'), 'w', newline="") as f:
        csv_writer = csv.writer(f)
        csv_writer.writerow(['Process Name', 'Process Path', 'Status'])

        # 레지스트리 키를 열고 정보 추출
        for key_path in auto_run_list:
            for hkey in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
                try:
                    with winreg.OpenKey(hkey, key_path) as key:
                        for j in range(winreg.QueryInfoKey(key)[1]):
                            auto_run_info = winreg.EnumValue(key, j)
                            csv_writer.writerow([auto_run_info[0], auto_run_info[1], auto_run_info[2]])
                except Exception as e:
                    print(f"[-] An error occurred: {e}")


def registry_func(output_directory):
    return 1

def browser_info_func(output_directory):
    return 1

def bin_func(output_directory):
    def get_reg_value_sid(user_name, key_path):
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            i = 0
            while True:
                try:
                    sid = winreg.EnumKey(key, i)
                    sid_key_path = f"{key_path}\{sid}"
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sid_key_path) as sid_key:
                        profile_path, _ = winreg.QueryValueEx(sid_key, "ProfileImagePath")
                        if user_name.lower() in profile_path.lower():
                            return sid
                    i += 1
                except:
                    break

    def analyze_deleted_file(file, file_path):
        origin_file = f"$R{file[2:]}"
        origin_file_path = f"{file_path}\\{origin_file}"
        deleted_file_path = f"{file_path}\\{file}"

        try:
            with open(deleted_file_path, 'rb') as f:
                raw_data = f.read()
                result = chardet.detect(raw_data)
                encoding = result['encoding'] if result['encoding'] is not None else 'utf-8'


                content = raw_data.decode(encoding)
                creation_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(os.path.getctime(deleted_file_path)))
                modified_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(os.path.getmtime(deleted_file_path)))
                access_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(os.path.getatime(deleted_file_path)))

                file_size = str(os.path.getsize(origin_file_path))
                return [deleted_file_path, creation_time, access_time, modified_time, file_size]
        except UnicodeDecodeError as e:
            print(f"[-] 인코딩 오류 발생 : {e}")
            return None
        except Exception as e:
            print(f"다른 오류 발생 : {e}")
            return None

    # 사용자 이름 가져오기
    user_name = getpass.getuser()
    join_user_name = f"C:\\Users\\{user_name}"
    recycle_path = 'C:\\$Recycle.Bin\\'
    sid = get_reg_value_sid(join_user_name, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList")
    personal_recycle_path = f"{recycle_path}{sid}"

    if os.path.exists(personal_recycle_path):
        recycle_files = os.listdir(personal_recycle_path)
        with open(os.path.join(output_directory, '휴지통.csv'), 'w', newline="") as f:
            csv_writer = csv.writer(f)
            csv_writer.writerow(['Deleted FilePath', 'Creation Time', 'Access Time', 'Modified Time', 'File Size'])

            for deleted_file in recycle_files:
                if deleted_file == "desktop.ini":
                    continue
                else:
                    file_info = analyze_deleted_file(deleted_file, personal_recycle_path)
                    if file_info:
                        csv_writer.writerow(file_info)
    else:
        print("[-] Recycle Bin 파싱 중 경로 문제 발생")

def powershell_log_func(output_directory):
    return 1


def lnk_files_func(output_directory):
    user = getpass.getuser()
    lnk_file_path = f"C:\\Users\\{user}\\AppData\\Roaming\\Microsoft\\Windows\\Recent"

    if os.path.exists(lnk_file_path):
        lnk_file_list = os.listdir(lnk_file_path)
        filename, createtime_list, modifiedtime_list, accesstime_list = [], [], [], []

        for file in lnk_file_list:
            full_path = os.path.join(lnk_file_path, file)
            createtime_list.append(datetime.fromtimestamp(os.path.getctime(full_path)))
            modifiedtime_list.append(datetime.fromtimestamp(os.path.getmtime(full_path)))
            accesstime_list.append(datetime.fromtimestamp(os.path.getatime(full_path)))
            filename.append(file)

        # 데이터프레임 생성 및 CSV 파일로 저장
        df = pd.DataFrame({
            'FileName': filename,
            'CreatedTime': createtime_list,
            'ModifiedTime': modifiedtime_list,
            'Accesstime': accesstime_list
        })
        output_file = os.path.join(output_directory, 'LNK 파일.csv')
        df.to_csv(output_file)
    else:
        print("[-] Lnk 파일 경로가 올바르지 않음")


# == 아티팩트 함수 ==========================================================================================================================


artifact_functions = {
    "메모리 덤프": memory_dump_func,
    "Prefetch" : prefetch_func,
    "NTFS 아티팩트" : NTFS_func,
    "시스템 정보" : sys_info_func,
    "레지스트리 하이브" : regi_hive,
    "이벤트 뷰어 로그" : event_viewer_log_func,
    "환경 변수" : enviornment_func,
    "패치 리스트" : patch_list_func,
    "실행 프로세스 목록 정보" : process_list_info_func,
    "연결 정보 (열려진 포트)" : connection_info_func,
    "IP 설정 정보" : ip_setting_info_func,
    "ARP 정보" : ARP_info_func,
    "NetBIOS 정보" : NetBIOS_info_func,
    "열려있는 핸들 정보" : open_handle_info_func,
    "작업 스케줄 정보" : work_schedule_info_func,
    "시스템 로그온 정보" : sys_logon_info_func,
    "등록된 서비스 정보" : regi_service_info_func,
    "최근 활동 정보" : recent_act_info_func,
    "UserAssist" : userassist_func,
    "AutoRun" : autorun_func,
    "레지스트리" : registry_func,
    "브라우저 기록" : browser_info_func,
    "휴지통" : bin_func,
    "파워쉘 로그" : powershell_log_func,
    "최근 LNK 파일" : lnk_files_func
}


# == 진행 상태 창 ============================================================================================================================
def open_status_window():
    global status_window
    status_window = tk.Toplevel(app)
    status_window.title("진행 상태")
    status_window.geometry("300x100")
    app.resizable(False, False)
    status_label = tk.Label(status_window, text="작업 시작", font=("Arial", 12))
    status_label.pack(pady=10)

    def on_exit():
        app.quit()

    # 결과보기 버튼 함수
    def show_results():
        for widget in app.winfo_children():
            widget.destroy()

        csv_files = [file for file in os.listdir(output_directory) if file.endswith(".csv")]
        selected_file_var = tk.StringVar()

        # 콤보박스
        file_combobox = ttk.Combobox(app, textvariable=selected_file_var, values=csv_files)
        file_combobox.grid(row=0, column=0, padx=10, pady=10, sticky='nw')

        # 프레임 생성
        scrollable_frame = create_scrollable_frame(app)
        scrollable_frame.grid(row=1, column=0, sticky='nsew')
        app.grid_columnconfigure(0, weight=1)
        app.grid_rowconfigure(1, weight=1)

        def on_file_selected(event):
            selected_file = selected_file_var.get()
            file_path = os.path.join(output_directory, selected_file)
            data = read_csv(file_path)

            for widget in scrollable_frame.winfo_children():
                widget.destroy()

            show_csv_in_treeview(scrollable_frame, data, selected_file)

        file_combobox.bind('<<ComboboxSelected>>', on_file_selected)

        if csv_files:
            selected_file_var.set(csv_files[0])
            on_file_selected(None)


    # 종료 버튼
    exit_button = tk.Button(status_window, text="종료", command=on_exit, state='disabled')
    exit_button.pack(side="left", padx=10, pady=10)

    # 결과보기 버튼
    result_button = tk.Button(status_window, text="결과보기", command=show_results, state='disabled')
    result_button.pack(side="right", padx=10, pady=10)

    def update_status(message):
        status_label.config(text=message)
        status_window.update()
        if message == "모든 작업 완료.":
            exit_button.config(state='normal')
            result_button.config(state='normal')

    return update_status




def read_csv(file_path):
    data = []
    with open(file_path, newline='', encoding='utf-8-sig') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            data.append(row)
    return data


def show_csv_in_treeview(parent, data, title):
    if not data:
        return

    frame = tk.Frame(parent)
    frame.pack(expand=True, fill='both')

    # 제목 라벨
    title_label = tk.Label(frame, text=title, bg="gray", fg="white")
    title_label.pack(side="top", fill="x")

    tree_frame = tk.Frame(frame)
    tree_frame.pack(expand=True, fill='both')

    tree = ttk.Treeview(tree_frame, columns=data[0], show="headings")
    tree.pack(side="left", expand=True, fill='both')

    # 스크롤바
    scrollbar = tk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
    scrollbar.pack(side="right", fill='y')
    tree.configure(yscrollcommand=scrollbar.set)

    for col in data[0]:
        tree.column(col, width=92, anchor="center")
        tree.heading(col, text=col)

    for row in data[1:]:
        tree.insert("", "end", values=row)

    # 검색 기능
    search_frame = tk.Frame(frame)
    search_frame.pack(side="top", fill="x")

    headers = ['전체'] + data[0]
    header_combobox = ttk.Combobox(search_frame, values=headers, state="readonly")
    header_combobox.pack(side="left")
    header_combobox.current(0)

    search_entry = tk.Entry(search_frame)
    search_entry.pack(side="left")

    def on_search():
        query = search_entry.get().lower() 
        selected_header = header_combobox.get()

        for item in tree.get_children():
            tree.item(item, tags=("normal",))

        matching_items = []
        non_matching_items = []

        if selected_header == "전체":
            for item in tree.get_children():
                if query in " ".join(map(str, tree.item(item, 'values'))).lower():
                    matching_items.append(item)
                else:
                    non_matching_items.append(item)
        else:
            col_index = data[0].index(selected_header)
            for item in tree.get_children():
                if query in str(tree.item(item, 'values')[col_index]).lower():
                    matching_items.append(item)
                else:
                    non_matching_items.append(item)

        for item in matching_items + non_matching_items:
            tree.move(item, '', 'end')

        for item in matching_items:
            tree.item(item, tags=("found",))

        tree.tag_configure('found', background='yellow')
        tree.tag_configure('normal', background='white')


    search_button = tk.Button(search_frame, text="검색", command=on_search)
    search_button.pack(side="left")




def on_frame_configure(event, canvas=None):
    if not canvas:
        canvas = event.widget
    canvas.configure(scrollregion=canvas.bbox("all"))

def create_scrollable_frame(parent):
    global canvas
    canvas = tk.Canvas(parent)
    canvas.grid(row=1, column=0, sticky='nsew')
    parent.grid_rowconfigure(1, weight=1)
    parent.grid_columnconfigure(0, weight=1)

    scrollable_frame = tk.Frame(canvas)
    canvas.create_window((0, 0), window=scrollable_frame, anchor='nw')

    scrollable_frame.bind("<Configure>", lambda event, canvas=canvas: on_frame_configure(event, canvas))

    return scrollable_frame



# == 메인 창 =================================================================================================================================
def execute_and_save_artifacts():
    global status_window
    update_status = open_status_window()
    for artifact, var in variables.items():
        if var.get():
            func = artifact_functions.get(artifact)
            if func:
                update_status(f"{artifact} 작업 시작")
                func(output_directory)
                update_status(f"{artifact} 작업 완료")

    update_status("모든 작업 완료.")



app = tk.Tk()
app.title('데이터 수집 도구')
app.geometry("800x600")
app['bg'] = '#f0f0f0'
app.resizable(False, False)

style = ttk.Style()
style.map("Treeview", 
          background=[("selected", "SystemWindow")],
          foreground=[("selected", "SystemWindowText")])
style.theme_use('clam')

# 사례 참조 섹션
case_ref_label = ttk.Label(app, text="케이스 번호 / 참조:", background='#f0f0f0')
case_ref_label.grid(row=0, column=0, padx=5, pady=5)
case_ref_entry = ttk.Entry(app)
case_ref_entry.grid(row=0, column=1, padx=5, pady=5, columnspan=2, sticky='ew')

artifact_label = ttk.Label(app, text="탐지할 아티팩트 선택", background='#f0f0f0', font=('Arial', 10))
artifact_label.grid(row=1, column=0, columnspan=1, padx=5, pady=5)

# 수집 옵션 섹션
options_frame = ttk.Frame(app, relief='solid', borderwidth=2)
options_frame.grid(row=2, column=0, columnspan=3, padx=10, pady=5, sticky='ew')

checkbuttons = {}
variables = {}
options = [
    "메모리 덤프",
    "Prefetch", 
    "NTFS 아티팩트", 
    "시스템 정보",
    "레지스트리 하이브",
    "이벤트 뷰어 로그",
    "SRUM, Hosts 및 서비스",
    "환경 변수",
    "패치 리스트",
    "실행 프로세스 목록 정보",
    "연결 정보 (열려진 포트)",
    "IP 설정 정보",
    "ARP 정보",
    "NetBIOS 정보",
    "열려있는 핸들 정보",
    "작업 스케줄 정보",
    "시스템 로그온 정보",
    "등록된 서비스 정보",
    "최근 활동 정보",
    "UserAssist",
    "AutoRun",
    "레지스트리",
    "브라우저 기록",
    "휴지통",
    "파워쉘 로그",
    "최근 LNK 파일"
    ]
for i, option in enumerate(options):
    variables[option] = tk.BooleanVar()
    checkbuttons[option] = ttk.Checkbutton(options_frame, text=option, variable=variables[option])
    checkbuttons[option].grid(row=i // 5, column=i % 5, padx=3, pady=2, sticky='w')

for i in range(5):
    options_frame.grid_columnconfigure(i, weight=1)

# 출력 섹션
output_label = ttk.Label(app, text="출력 저장 위치:", background='#f0f0f0')
output_label.grid(row=1000, column=0, padx=5, pady=5, sticky='e')
output_entry = ttk.Entry(app)
set_default_output_directory()
output_entry.grid(row=1000, column=1, padx=5, pady=5, sticky='ew')
browse_button = ttk.Button(app, text="찾아보기", command=browse_output_directory)
browse_button.grid(row=1000, column=2, padx=5, pady=5)

# 캡처 시작 버튼
start_button = ttk.Button(app, text="캡처 시작", command=execute_and_save_artifacts)
start_button.grid(row=1001, column=0, columnspan=3, padx=5, pady=20)

app.grid_columnconfigure(1, weight=1) 

app.mainloop()
