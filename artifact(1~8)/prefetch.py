import os, time, csv, operator
# Prefetch 파싱
def get_prefetch():
    timeline_csv = open("timeline.csv","a")

    prefetch_directory = r"C:\Windows\Prefetch\\"
    subject_line = "Artifact timestamp,Filename,First executed,Last executed,Action,Source\n"
    timeline_csv.write(subject_line)

    prefetch_files = os.listdir(prefetch_directory)
    for pf_file in prefetch_files:
        if pf_file[-2:] == "pf":
            full_path = prefetch_directory + pf_file
            app_name = pf_file[:-12]
            first_executed = os.path.getctime(full_path)
            first_executed = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(first_executed))
            last_executed = os.path.getmtime(full_path)
            last_executed = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_executed))
            first_executed_line = first_executed + "," + app_name + "," + first_executed + "," + last_executed + "," + "Program first executed" + "," + "Prefetch - " + pf_file + "\n"
            last_executed_line = last_executed + "," + app_name + "," + first_executed + "," + last_executed + "," + "Program last executed" + "," + "Prefetch - " + pf_file + "\n"
            timeline_csv.write(first_executed_line)
            timeline_csv.write(last_executed_line)

    timeline_csv.close()

