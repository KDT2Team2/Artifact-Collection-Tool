import winreg

def get_registry_hive_info(hive):
    try:
        # Open the registry key
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, hive) as key:
            # Get information about the key
            info = winreg.QueryInfoKey(key)

            # Display information
            print(f"Registry Hive: {hive}")
            print(f"Number of Subkeys: {info[0]}")
            print(f"Number of Values: {info[1]}")
            print(f"Last Modification Time: {info[2]}")
            print(f"Title Index: {info[3]}")
            print(f"Class Index: {info[4]}")

    except FileNotFoundError:
        print(f"Registry hive {hive} not found.")
    except PermissionError:
        print(f"Permission error accessing registry hive {hive}. Make sure to run the script with appropriate permissions.")

# Example usage
get_registry_hive_info("SOFTWARE\\Microsoft\\Windows\\CurrentVersion")


import winreg

def read_registry_hive_file(hive_file_path, hive_name):
    try:
        # Load the hive file
        winreg.LoadHive(None, hive_file_path)

        # Open the registry key
        with winreg.OpenKey(winreg.HKEY_USERS, hive_name) as key:
            # Enumerate and display values
            num_values = winreg.QueryInfoKey(key)[1]
            for i in range(num_values):
                name, value, _ = winreg.EnumValue(key, i)
                print(f"Value Name: {name}, Value Data: {value}")

    except FileNotFoundError:
        print(f"Registry hive file {hive_file_path} or hive {hive_name} not found.")
    except PermissionError:
        print(f"Permission error accessing registry hive file {hive_file_path} or hive {hive_name}. Make sure to run the script with appropriate permissions.")
    finally:
        # Unload the hive file
        winreg.UnloadKey(None, hive_name)

# Example usage
read_registry_hive_file(r"C:\Windows\System32\config", "MyHive")
