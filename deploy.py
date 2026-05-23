import subprocess, os
os.chdir(r"d:\Filza\a")
LOG = r"d:\Filza\a\deploy_log.txt"
def log(m):
    open(LOG, "a").write(m + "\n")
log("=== START ===")
try:
    r = subprocess.run(["git", "status", "--porcelain"], capture_output=True, text=True, timeout=30)
    log(f"STATUS: rc={r.returncode}")
    log(f"STDOUT: {r.stdout[:500]}")
    log(f"STDERR: {r.stderr[:500]}")
    
    r = subprocess.run(["git", "add", "-A"], capture_output=True, text=True, timeout=30)
    log(f"ADD: rc={r.returncode} {r.stdout[:200]} {r.stderr[:200]}")
    
    r = subprocess.run(["git", "commit", "-m", "fix: add missing dirent.h"], capture_output=True, text=True, timeout=30)
    log(f"COMMIT: rc={r.returncode} {r.stdout[:500]} {r.stderr[:500]}")
    
    r = subprocess.run(["git", "push", "origin", "main"], capture_output=True, text=True, timeout=120)
    log(f"PUSH: rc={r.returncode} {r.stdout[:500]} {r.stderr[:500]}")
    
    r = subprocess.run(["git", "log", "--oneline", "-1"], capture_output=True, text=True, timeout=30)
    log(f"HEAD: {r.stdout[:200]}")
except Exception as e:
    log(f"EXCEPTION: {e}")
log("=== END ===")