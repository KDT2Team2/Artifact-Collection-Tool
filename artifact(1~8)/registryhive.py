import subprocess
from Registry import Registry
import csv
import os

output_csv = 'registry_export_'
key_paths = [
    'HKEY_CURRENT_USER',
    r'HKLM\sam',
    r'HKLM\security',
    r'HKLM\software',
    r'HKLM\system',
    r'HKEY_USERS\.DEFAULT',
    'HKEY_CURRENT_CONFIG',
]
extract_files = []

def recursive_search(key,csv_writer):
    subkeys = key.subkeys()
    if len(subkeys) == 0:
        for v in key.values():
            try:
                csv_writer.writerow([key.path(),v.name(),v.value()])
            except Registry.RegistryParse.UnknownTypeException:
                pass
            except UnicodeDecodeError:
                pass
    else:
        for subkey in subkeys:
            recursive_search(subkey,csv_writer)
      
def export_registry_key_to_csv(hive_path,output_csv):
        reg = Registry.Registry(hive_path)
        key = reg.root()
        with open(output_csv, 'w', newline='', encoding='utf-8') as csv_file:
            csv_writer = csv.writer(csv_file,dialect=csv.excel, quoting=1)
            csv_writer.writerow(['Path','Name','Value'])
            recursive_search(key,csv_writer)

def extract_registry_file():
    try:
        for key_path in key_paths:
            output_file = key_path.replace('\\','')
            if subprocess.run(['reg', 'save', key_path, output_file], check=True).returncode == 0:
                extract_files.append(output_file)
    except subprocess.CalledProcessError as e:
        print(f"Error exporting registry hive: {e}")

if __name__ == "__main__":
    extract_registry_file()
    for key_path in extract_files:
        export_registry_key_to_csv(key_path,key_path+'.csv')
            
    for key_path in extract_files:
        try:
            os.remove(key_path)
            print(f"{key_path} file removed")
        except Exception as e:
            print(e)
