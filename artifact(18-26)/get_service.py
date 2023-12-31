import win32con
import win32service

def GetServiceList():
    resume = 0
    # 엑세스 권한 명시
    accessSCM = win32con.GENERIC_READ
    accessSrv = win32service.SC_MANAGER_ALL_ACCESS

    hscm = win32service.OpenSCManager(None, None, accessSCM)

    typeFilter = win32service.SERVICE_WIN32
    stateFilter = win32service.SERVICE_STATE_ALL

    statuses = win32service.EnumServicesStatus(hscm, typeFilter, stateFilter)

    for (short_name, desc, status) in statuses:
        print(short_name, desc, status) 
