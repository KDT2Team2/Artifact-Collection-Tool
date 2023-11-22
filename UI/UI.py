import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import csv
import os

global canvas

# == 아티팩트 함수 ==========================================================================================================================
def memory_dump_func():
    file_name = 'memory_dump.csv'

    with open(file_name, 'r') as file:
        reader = csv.reader(file)
        return list(reader)

def prefetch_func():
    file_name = 'prefetch.csv'

    with open(file_name, 'r') as file:
        reader = csv.reader(file)
        return list(reader)

def NTFS_func():
    return ["항목1", "항목2", "항목3"]


def sys_info_func():
    return []

def regi_hive():
    return ["1232"]

def event_viewer_log_func():
    return 1

def enviornment_func():
    return 1

def patch_list_func():
    return 1

def process_list_info_func():
    return 1

def connection_info_func():
    return 1

def ip_setting_info_func():
    return 1

def ARP_info_func():
    return 1

def NetBIOS_info_func():
    return 1

def open_handle_info_func():
    return 1

def work_schedule_info_func():
    return 1

def sys_logon_info_func():
    return 1

def regi_service_info_func():
    return 1

def recent_act_info_func():
    return 1

def userassist_func():
    return 1

def autorun_func():
    return 1

def registry_func():
    return 1

def browser_info_func():
    return 1

def bin_func():
    return 1

def powershell_log_func():
    return 1

def lnk_files_func():
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





# 결과 리스트 토글 기능
def toggle_items(frame):
    frame.pack_forget() if frame.winfo_viewable() else frame.pack(side='top', fill='x', padx=5, pady=5)

# 결과 프레임 출력
def create_result_frame(parent, title, items):
    frame = tk.Frame(parent, relief='solid', borderwidth=2, background='white')
    frame.pack(side='top', fill='x', padx=5, pady=5)

    title_frame = tk.Frame(frame, background='#D6D5CB')
    title_frame.pack(side='top', fill='x')
    title_label = tk.Label(title_frame, text=title, font=('Arial', 10), background='#D6D5CB', anchor='w')
    title_label.pack(side='left', padx=5, pady=5)

    items_frame = tk.Frame(frame, background='white')
    items_frame.pack(side='top', fill='x', padx=5, pady=5)

    if not isinstance(items, list):
        items = [items]

    # 리스트의 리스트인 경우 Treeview 사용
    if len(items) > 0 and all(isinstance(item, list) for item in items):
        # Treeview 위젯 생성 및 설정
        tree = ttk.Treeview(items_frame, columns=[str(i) for i in range(len(items[0]))], show='headings')
        tree.pack(side='left', fill='both', expand=True)

        # 컬럼 제목 및 너비 설정
        for i, title in enumerate(items[0]):
            tree.heading(str(i), text=title)
            tree.column(str(i), width=100, minwidth=50, anchor=tk.W)

        # 데이터 삽입
        for row in items[1:]:
            tree.insert('', 'end', values=row)

        # 스크롤바 추가
        scrollbar = ttk.Scrollbar(items_frame, orient='vertical', command=tree.yview)
        scrollbar.pack(side='right', fill='y')
        tree.configure(yscrollcommand=scrollbar.set)
    else:
        # 단일 항목 처리
        for item in items:
            item_label = tk.Label(items_frame, text=item, background='white')
            item_label.pack(side='top', anchor='w', padx=5, pady=2)

    title_frame.bind("<Button-1>", lambda e: toggle_items(items_frame))
    title_label.bind("<Button-1>", lambda e: toggle_items(items_frame))

    return frame










# 결과 창 스크롤 마우스 휠 연동
def on_mousewheel(event):
    global canvas
    canvas.yview_scroll(int(-1*(event.delta/120)), "units")






def start_capture():
    global case_ref_label, case_ref_entry, options_frame, output_label, output_entry, browse_button, start_button, artifact_label, canvas
    # 기존 위젯 숨기기
    case_label.grid_forget()
    case_ref_entry.grid_forget()
    options_frame.grid_forget()
    output_label.grid_forget()
    output_entry.grid_forget()
    browse_button.grid_forget()
    start_button.grid_forget()
    artifact_label.grid_forget()



    case_ref = case_ref_entry.get()

    # 스크롤 가능한 프레임
    canvas = tk.Canvas(app, borderwidth=0, background="#ffffff", height=600, width=780)
    scrollbar = tk.Scrollbar(app, orient="vertical", command=canvas.yview)
    canvas.configure(yscrollcommand=scrollbar.set)
    scrollbar.grid(row=0, column=1, sticky='ns')
    canvas.grid(row=0, column=0, sticky="nsew")
    canvas.bind_all("<MouseWheel>", on_mousewheel)


    # 캔버스 안에 결과 프레임 배치
    result_container = tk.Frame(canvas, background='white')
    canvas.create_window((0, 0), window=result_container, anchor="nw")
    result_container.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))


    case_ref_label = tk.Label(result_container, text="케이스 참조: {}".format(case_ref), font=('Arial', 12), background='white', anchor='w', width=85)
    case_ref_label.pack(side='top', fill='x', padx=5, pady=5)

    # 체크된 아티팩트에 대응하는 함수 호출
    for option in options:
        if variables[option].get() and option in artifact_functions:
            function = artifact_functions[option]
            result_items = function()
            frame = create_result_frame(result_container, option, result_items)
            frame.pack(side='top', fill='x', padx=5, pady=5)






# == 시작 페이지 ==================================================================================================================================


# 파일 위치 찾아보기 함수
def browse_output_directory():
    directory = filedialog.askdirectory()
    if directory:
        output_entry.delete(0, tk.END)
        output_entry.insert(0, directory)


# UI 창 구성 / 스타일
app = tk.Tk()
app.title('데이터 수집 도구')
app.geometry("800x600")
app.resizable(False, False)
app['bg'] = '#f0f0f0'
style = ttk.Style()
style.theme_use('clam')



# 사례 참조 섹션
case_label = ttk.Label(app, text="케이스 번호 / 참조:", background='#f0f0f0')
case_label.grid(row=0, column=0, padx=5, pady=10)
case_ref_entry = ttk.Entry(app)
case_ref_entry.grid(row=0, column=1, padx=5, pady=10, columnspan=2, sticky='ew')


# 수집 옵션 섹션
artifact_label = ttk.Label(app, text="탐지할 아티팩트 선택", background='#f0f0f0', font=('Arial', 10))
artifact_label.grid(row=1, column=0, columnspan=1, padx=5, pady=(50, 1))
options_frame = ttk.Frame(app, relief='solid', borderwidth=2)
options_frame.grid(row=2, column=0, columnspan=3, padx=10, pady=1, sticky='ew')


# 모두 선택 함수
def select_all():
    for option in options:
        variables[option].set(select_all_var.get())

# 각 체크박스와 변수 초기화
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

# 모두 선택 기능
select_all_var = tk.BooleanVar()
select_all_checkbox = ttk.Checkbutton(options_frame, text="모두 선택", variable=select_all_var, command=select_all)
select_all_checkbox.grid(row=100, column=4, padx=3, pady=2, sticky='e')



# 출력 저장 위치 설정
output_label = ttk.Label(app, text="출력 저장 위치:", background='#f0f0f0')
output_label.grid(row=1000, column=0, padx=5, pady=100, sticky='e')
output_entry = ttk.Entry(app)
output_entry.grid(row=1000, column=1, padx=5, pady=100, sticky='ew')
browse_button = ttk.Button(app, text="찾아보기", command=browse_output_directory)
browse_button.grid(row=1000, column=2, padx=(5, 30), pady=100)



# 캡처 시작 버튼
start_button = ttk.Button(app, text="캡처 시작", command=start_capture)
start_button.grid(row=1001, column=0, columnspan=3, padx=5, pady=20)



result_label = tk.Label(app, justify=tk.LEFT, anchor='w')
result_label.grid(row=1002, column=0, columnspan=3, padx=5, pady=20)


app.grid_rowconfigure(1, weight=1)
app.grid_columnconfigure(1, weight=1)
app.mainloop()

