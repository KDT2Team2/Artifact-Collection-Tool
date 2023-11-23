import win32com.client
import csv

def get_scheduled_tasks():
    with open('Scheduled_Task_List.csv', 'w', newline='', encoding='utf-8-sig') as file:
        writer = csv.writer(file)
        writer.writerow(["Task name", "Last run Time", "Next run Time", "Enabled", "Trigger Count", "Action Count"])

        scheduler = win32com.client.Dispatch("Schedule.Service")
        scheduler.Connect()
        folders = [scheduler.GetFolder("\\")]

        while folders:
            folder = folders.pop(0)
            folders += list(folder.GetFolders(0))
            tasks = list(folder.GetTasks(0))

            for task in tasks:
                settings = task.Definition.Settings
                triggers = task.Definition.Triggers
                actions = task.Definition.Actions

                writer.writerow([task.Name, task.LastRunTime, task.NextRunTime, task.Enabled, triggers.Count, actions.Count])
