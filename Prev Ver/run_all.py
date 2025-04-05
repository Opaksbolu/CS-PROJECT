import subprocess

files = [
    "Name_and_Address_Removal.py",
    "DOB_and_Medical_Number_Removal.py",
    "Data_Anonymizer_GUI.py",
    "remove_sensitive_data.py",
    "Email_Removal.py",
    "Phone_Number_Removal.py"
]

for file in files:
    print(f"Running {file}...")
    subprocess.run(["python", file])
    print(f"{file} finished.\n")
