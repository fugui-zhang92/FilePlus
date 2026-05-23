import subprocess, os
os.chdir(r"d:\Filza\a")

def run(args):
    r = subprocess.run(args, capture_output=True, text=True)
    print("$", " ".join(args))
    if r.stdout: print("OUT:", r.stdout[:500])
    if r.stderr: print("ERR:", r.stderr[:500])
    print("RC:", r.returncode)
    return r

# Check current status
run(["git", "status", "--short"])

# Check diff
run(["git", "diff", "--stat"])

# Add and commit
run(["git", "add", "-A"])
run(["git", "commit", "-m", "fix: add missing dirent.h include in Tweak.m"])

# Verify
run(["git", "log", "--oneline", "-3"])