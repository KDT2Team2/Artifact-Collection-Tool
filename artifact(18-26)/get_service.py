import win32con
import win32service

def GetServiceList():
    resume = 0
    # 엑세스 권한 명시
    accessSCM = win32con.GENERIC_READ
    accessSrv = win32service.SC_MANAGER_ALL_ACCESS

    # 
    hscm = win32service.OpenSCManager(None, None, accessSCM)

    #Enumerate Service Control Manager DB
    typeFilter = win32service.SERVICE_WIN32
    stateFilter = win32service.SERVICE_STATE_ALL

    statuses = win32service.EnumServicesStatus(hscm, typeFilter, stateFilter)

    # Status(서비스 유형, 서비스 상태, 허용하는 엑세스, win32오류코드, 서비스별 오류코드, 서비스에서 보고한 체크포인다, 대기)
    for (short_name, desc, status) in statuses:
        print(short_name, desc, status) 
