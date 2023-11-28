import os
import csv

# Get all environment variables
env_vars = os.environ

csv_string = ['Key','Value']
csv_file = csv.writer(open("environ.csv", 'w', newline=""), dialect=csv.excel, quoting=1)
csv_file.writerow(csv_string)

# Print the list of environment variables]
for key, value in env_vars.items():
    csv_file.writerow([key,value])
