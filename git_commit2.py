import subprocess, os, sys
os.chdir(r"d:\Filza\a")

def run(args):
    r = subprocess.run(args, capture_output=True, text=True)
    return f"$ {' '.join(args)}\nOUT:{r.stdout[:1000]}\nERR:{r.stderr[:1000]}\nRC:{r.returncode}\n"

result = ""
result += run(["git", "status", "--short"])
result += run(["git", "diff", "--stat"])
result += run(["git", "add", "-A"])
result += run(["git", "commit", "-m", "fix: add missing dirent.h include in Tweak.m"])
result += run(["git", "log", "--oneline", "-3"])

with open(r"d:\Filza\a\git_result.txt", "w") as f:
    f.write(result)
print("DONE", flush=True)