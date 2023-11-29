import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET
import csv

def parse_tag(element):
    if element.tag.index('}') > 0:
        return element[element.tag.index('}')+1:]

def parse_log(log_file, output_csv_file):
    with evtx.Evtx(log_file) as log:
        title_row = [
            'Provider name',
            'Provider guid',
            'EventID',
            'Version',
            'Level',
            'Task',
            'Opcode',
            'Keywords',
            'TimeCreadted',
            'EventRecordID',
            'ActivityID',
            'RelatedActivityID',
            'ProcessID',
            'ThreadID',
            'Channel',
            'Computer',
            'Security'
        ]
        csv_file = csv.writer(open(output_csv_file, 'w', newline=''), dialect=csv.excel, quoting=1)
        csv_file.writerow(title_row)

        for record in log.records():
            csv_record=[]
            root = ET.fromstring(record.xml())
            for child in root[0]:
                if child.attrib.items(): # attribute가 있는 경우
                    for key, value in child.attrib.items():
                        if key == "Qualifiers":
                            csv_record.append(child.text)
                        else:
                            csv_record.append(value)
                else: # attribute가 없는 경우
                    csv_record.append(child.text)
            csv_file.writerow(csv_record)

if __name__ == "__main__":
    parse_log('C:\\Windows\\System32\\winevt\\Logs\\Security.evtx', "eventlog_security.csv")
    # parse_log('C:\\Windows\\System32\\winevt\\Logs\\Application.evtx', "eventlog_application.csv")
    # parse_log('C:\\Windows\\System32\\winevt\\Logs\\System.evtx', "eventlog_system.csv")


            

