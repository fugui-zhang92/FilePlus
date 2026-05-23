import subprocess, os
os.chdir(r"d:\Filza\a")
result = subprocess.run(["git", "log", "--oneline", "-3"], capture_output=True, text=True)
print("STDOUT:", result.stdout)
print("STDERR:", result.stderr)
print("RC:", result.returncode)