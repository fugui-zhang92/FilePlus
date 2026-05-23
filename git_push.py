import subprocess, os
os.chdir(r"d:\Filza\a")
try:
    r = subprocess.run(["git", "add", "-A"], capture_output=True, text=True, timeout=30)
    open(r"d:\Filza\a\git_out.txt","w").write(f"ADD: rc={r.returncode} out={r.stdout} err={r.stderr}")
    if r.returncode == 0:
        r = subprocess.run(["git", "commit", "-m", "fix: add missing dirent.h include in Tweak.m"], capture_output=True, text=True, timeout=30)
        open(r"d:\Filza\a\git_out.txt","a").write(f"\nCOMMIT: rc={r.returncode} out={r.stdout} err={r.stderr}")
        if r.returncode == 0:
            r = subprocess.run(["git", "push", "origin", "main"], capture_output=True, text=True, timeout=120)
            open(r"d:\Filza\a\git_out.txt","a").write(f"\nPUSH: rc={r.returncode} out={r.stdout} err={r.stderr}")
    open(r"d:\Filza\a\git_out.txt","a").write("\nDONE")
except Exception as e:
    open(r"d:\Filza\a\git_out.txt","w").write(f"EXCEPTION: {e}")