# 시스템 정보, 시스템 감사 정보, 그룹 정책 정보 파싱
import platform
import subprocess

def get_group_policy_info():
    try:
        # Run gpresult command and capture the output
        result = subprocess.run(['gpresult', '/r'], capture_output=True, text=True)

        # Check if the command was successful
        if result.returncode == 0:
            # Print the group policy information
            print(result.stdout)
        else:
            # Print an error message
            print(f"Error: {result.stderr}")
    
    except Exception as e:
        print(f"An error occurred: {e}")

def get_system_info():
    # Get general system information using the platform module
    system_info = {
        'System': platform.system(),
        'Node Name': platform.node(),
        'Release': platform.release(),
        'Version': platform.version(),
        'Architecture': platform.architecture(),
        'Machine': platform.machine(),
        'Processor': platform.processor()
    }

    return system_info

def get_system_audit_info():
    try:
        # Run system audit command and capture the output
        result = subprocess.run(['auditpol', '/get', '/category:*'], capture_output=True, text=True)

        # Check if the command was successful
        if result.returncode == 0:
            # Return the audit information
            return result.stdout
        else:
            # Print an error message
            return f"Error: {result.stderr}"
    
    except Exception as e:
        return f"An error occurred: {e}"

if __name__ == "__main__":
    # Get group policy  information
    get_group_policy_info()

    # Get and print general system information
    system_info = get_system_info()
    print("System Information:")
    for key, value in system_info.items():
        print(f"{key}: {value}")

    # Get and print system audit information
    print("\nSystem Audit Information:")
    audit_info = get_system_audit_info()
    print(audit_info)
