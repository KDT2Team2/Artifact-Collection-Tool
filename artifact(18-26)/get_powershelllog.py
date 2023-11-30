import win32evtlog
import csv

def collect_powershell_logs(server, logtype):
    handle = win32evtlog.OpenEventLog(server, logtype)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ
    total = 0

    try:
        with open('powershell_log.csv', 'a', newline='') as f:
            csv_writer = csv.writer(f)
            while True:
                events = win32evtlog.ReadEventLog(handle, flags, 0)
                if not events:
                    break

                for event in events:
                    if event.EventCategory is None:
                        continue
                    else:
                        csv_writer.writerow([event.EventCategory, event.TimeGenerated, event.SourceName, event.EventID, event.EventType, event.StringInserts]) # Message 부분을 출력
                        total += 1

    finally:
        win32evtlog.CloseEventLog(handle)

    return total

def powershell_log_extract_start():
    with open('powershell_log.csv', 'w', newline='') as f:
        csv_writer = csv.writer(f)
        csv_writer.writerow(['Event Category', 'Generated Time', 'Source Name', 'Event ID', 'Event Type', 'Message'])
        server = ''  # 로컬 컴퓨터
        logtype = 'Windows PowerShell'
        total_events = collect_powershell_logs(server, logtype)
        print(f'Total PowerShell events collected: {total_events}')
