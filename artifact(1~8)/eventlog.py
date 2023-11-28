from Evtx.Evtx import Evtx
from Evtx.Views import evtx_file_xml_view
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import parse

def get_event_log_info(evtx_file_path):
    try:
        # Open the Event Log file
        with Evtx(evtx_file_path) as evtx:
            # Parse the XML view of the Event Log
            records = evtx_file_xml_view(evtx.get_file_header())

            # Iterate through all records in the Event Log
            for record in records:
                # Access information from the record
                # event_id = record.find("EventID").text if record.find("EventID") is not None else "N/A"
                # timestamp = record.find("TimeCreated").get("SystemTime") if record.find("TimeCreated") is not None else "N/A"
                # level = record.find("Level").text if record.find("Level") is not None else "N/A"
                # message = record.find("Data").text if record.find("Data") is not None else "N/A"

                # print(f"Event ID: {event_id}")
                # print(f"Timestamp: {timestamp}")
                # print(f"Level: {level}")
                # print(f"Message: {message}")
                # print("-" * 50)
                parse_event_xml(record)

    except FileNotFoundError:
        print(f"Event Log file {evtx_file_path} not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

def parse_event_xml(evt):
    # Extract the XML string from the tuple
    print(evt[0])
    xml_string = evt[0]

    # Parse the XML string
    root = parse(ET.fromstring(xml_string))
    
    # Extract information from the parsed XML
    event_id = root.find(".//EventID")
    time_created = root.find(".//TimeCreated")
    level = root.find(".//Level")
    message = root.find(".//Data[@Name='ObjectName']")

    # Print extracted information
    print(f"Event ID: {event_id}")
    print(f"Time Created: {time_created}")
    print(f"Level: {level}")
    print(f"Object Name: {message}")

# Example usage
get_event_log_info("C:\\Windows\\System32\\winevt\\Logs\\Security.evtx")
