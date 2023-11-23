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
import re
from scapy.all import *
import pythoncom
import win32com.client
import hashlib
import psutil
from datetime import datetime

global canvas
output_directory = ""

# 사용자 지정 경로 설정 함수
def browse_output_directory():
    global output_directory
    directory = filedialog.askdirectory()
    if directory:
        output_entry.delete(0, tk.END)
        output_entry.insert(0, directory)
        output_directory = directory

# 체크된 아티팩트 실행 및 CSV 파일 저장 함수
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

    with open(os.path.join(output_directory, 'Patch_List.csv'), 'w', newline='', encoding='utf-8-sig') as file:
        writer = csv.writer(file)
        writer.writerow(['Title', 'Update ID', 'Version', 'Date'])

        for update in updates:
            title = update.Title

            # KB 번호와 버전을 추출하기 위한 정규 표현식
            kb_pattern = r"KB\d+"
            version_pattern = r"\(버전\s([\d.]+)\)"

            # 정규 표현식으로 KB 번호와 버전 찾기
            kb_match = re.search(kb_pattern, title)
            version_match = re.search(version_pattern, title)

            kb_number = kb_match.group(0) if kb_match else "KB 정보 없음"
            version = version_match.group(1) if version_match else "버전 정보 없음"

            # title에서 KB 정보 이전까지만 추출
            title_only = title.split(" - ")[0] if " - " in title else title

            writer.writerow([title_only, kb_number, version, str(update.Date)])

def process_list_info_func(output_directory):
    with open(os.path.join(output_directory, 'Processes_List.csv'), 'w', newline='', encoding='utf-8-sig') as file:
        writer = csv.writer(file)
        writer.writerow(['Process ID', 'Process name', 'Process path', 'Process creat time', 'Process access time', 'Process modify time', 'Process size', 'hash value(sha-256)'])

        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            process_info = proc.info
            file_path = process_info.get("exe")
            if file_path and os.path.isfile(file_path):
                # MAC 타임스탬프
                creation_time = os.path.getctime(file_path)
                access_time = os.path.getatime(file_path)
                modification_time = os.path.getmtime(file_path)
                
                # 파일 크기
                file_size = os.path.getsize(file_path)

                # 해시값 계산
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

    with open(os.path.join(output_directory, 'Open_Port_List.csv'), 'w', newline='', encoding='utf-8-sig') as file:
        writer = csv.writer(file)
        writer.writerow(['Port Number'])

        ports = range(1, 65535)
        
        packets = [IP(dst=host_name)/TCP(dport=port, flags="S") for port in ports]
        responses, _ = sr(packets, timeout=1, verbose=0)

        for sent, received in responses:
            if received.haslayer(TCP) and received[TCP].flags == 18:
                writer.writerow([sent[TCP].dport])

def ip_setting_info_func(output_directory):
    with open(os.path.join(output_directory, 'IP_configurations_info.csv'), 'w', newline='', encoding='utf-8-sig') as file:
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

    with open(os.path.join(output_directory, 'ARP_info.csv'), 'w', newline='', encoding='utf-8-sig') as file:
        writer = csv.writer(file)
        # CSV 헤더
        writer.writerow(['IP Address', 'Physical Address', 'Type'])

        # 활성화된 ARP 테이블에 대한 정보
        lines = arp_table.split('\n')
        for line in lines:
            if line.strip() and 'internet address' not in line.lower():
                parts = line.split()
                if len(parts) == 3:
                    type_value = 'static' if parts[2] == '정적' else 'dynamic' if parts[2] == '동적' else parts[2]
                    writer.writerow([parts[0], parts[1], type_value])

def NetBIOS_info_func(output_directory):
    with open(os.path.join(output_directory, 'NetBIOS_info.csv'), 'w', newline='', encoding='utf-8-sig') as file:
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

    with open(os.path.join(output_directory, 'Window(handler)_info.csv'), 'w', newline='', encoding='utf-8-sig') as file:
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
    with open(os.path.join(output_directory, 'Scheduled_Task_List.csv'), 'w', newline='', encoding='utf-8-sig') as file:
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

                writer.writerow({task.Name,task.LastRunTime,task.NextRunTime,task.Enabled,triggers.Count,actions.Count})

def sys_logon_info_func(query, output_directory):
    server = 'localhost'
    log_type = ['Application', 'System', 'Security', 'Setup', 'Forwarded Events']

    with open(os.path.join(output_directory, 'Event_log_List.csv'), 'w', newline='', encoding='utf-8-sig') as file:
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
    return 1

def recent_act_info_func(output_directory):
    return 1

def userassist_func(output_directory):
    return 1

def autorun_func(output_directory):
    return 1

def registry_func(output_directory):
    return 1

def browser_info_func(output_directory):
    return 1

def bin_func(output_directory):
    return 1

def powershell_log_func(output_directory):
    return 1

def lnk_files_func(output_directory):
    return 1


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

def execute_and_save_artifacts():
    for artifact, var in variables.items():
        if var.get():
            func = artifact_functions.get(artifact)
            if func:
                func(output_directory)

def browse_output_directory():
    global output_directory
    directory = filedialog.askdirectory()
    if directory:
        output_entry.delete(0, tk.END)
        output_entry.insert(0, directory)
        output_directory = directory

app = tk.Tk()
app.title('데이터 수집 도구')
app.geometry("800x600")
app['bg'] = '#f0f0f0'

style = ttk.Style()
style.theme_use('clam')

# 사례 참조 섹션
case_ref_label = ttk.Label(app, text="케이스 번호 / 참조:", background='#f0f0f0')
case_ref_label.grid(row=0, column=0, padx=5, pady=5)
case_ref_entry = ttk.Entry(app)
case_ref_entry.grid(row=0, column=1, padx=5, pady=5, columnspan=2, sticky='ew')  # 'ew'는 동서(east-west)를 의미하여 가로로 채워짐을 의미합니다.

# 탐지할 아티팩트 선택 라벨
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

# 프레임 내의 각 열에 가중치 설정
for i in range(5):
    options_frame.grid_columnconfigure(i, weight=1)

# 출력 섹션
output_label = ttk.Label(app, text="출력 저장 위치:", background='#f0f0f0')
output_label.grid(row=1000, column=0, padx=5, pady=5, sticky='e')
output_entry = ttk.Entry(app)
output_entry.grid(row=1000, column=1, padx=5, pady=5, sticky='ew')
browse_button = ttk.Button(app, text="찾아보기", command=browse_output_directory)
browse_button.grid(row=1000, column=2, padx=5, pady=5)

# 캡처 시작 버튼
start_button = ttk.Button(app, text="캡처 시작", command=execute_and_save_artifacts)
start_button.grid(row=1001, column=0, columnspan=3, padx=5, pady=20)

# Grid column configuration for resizing behavior
app.grid_columnconfigure(1, weight=1)  # 이것은 중간 열에 가중치를 주어 윈도우 크기가 변경될 때 가로로 늘어나게 합니다.

app.mainloop()
