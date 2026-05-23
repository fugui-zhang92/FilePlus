import urllib.request, json, ssl, sys, time

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

BASE = "https://api.github.com/repos/fugui-zhang92/FilePlus"

def api(path):
    url = f"{BASE}{path}"
    for retry in range(3):
        try:
            r = urllib.request.urlopen(url, context=ctx, timeout=30)
            return json.loads(r.read())
        except Exception as e:
            print(f"  API error (retry {retry}): {e}", flush=True)
            time.sleep(2)
    return None

def main():
    run_id = sys.argv[1] if len(sys.argv) > 1 else "26334262145"
    
    # Get run info
    print(f"Fetching run {run_id}...", flush=True)
    run = api(f"/actions/runs/{run_id}")
    if not run:
        print("FAILED to get run info", flush=True)
        return
    print(f"Run: status={run.get('status')} conclusion={run.get('conclusion')}", flush=True)
    
    # Get jobs
    print(f"Fetching jobs...", flush=True)
    jobs_url = run.get('jobs_url')
    if not jobs_url:
        print("No jobs_url", flush=True)
        return
    
    # jobs_url is full URL, we need to extract path
    path = jobs_url.replace(BASE, "")
    jobs_data = api(path)
    if not jobs_data:
        print("FAILED to get jobs", flush=True)
        return
    
    for job in jobs_data.get('jobs', []):
        print(f"\nJob: {job['name']} ({job['status']}/{job.get('conclusion','')})", flush=True)
        print(f"  ID: {job['id']}", flush=True)
        for step in job.get('steps', []):
            conclusion = step.get('conclusion', '')
            print(f"  Step {step['number']}: {step['name']} -> {conclusion}", flush=True)
        
        # Try to download log
        job_id = job['id']
        log_url = f"/actions/jobs/{job_id}/logs"
        print(f"  Log URL: {log_url}", flush=True)
        
        for retry in range(3):
            try:
                full_url = f"{BASE}{log_url}"
                req = urllib.request.Request(full_url)
                resp = urllib.request.urlopen(req, context=ctx, timeout=60)
                log_data = resp.read().decode('utf-8', errors='replace')
                # Print last 100 lines
                lines = log_data.split('\n')
                print(f"  Log lines: {len(lines)}", flush=True)
                # Print all lines
                print("  === LOG START ===", flush=True)
                for line in lines:
                    print(f"  {line}", flush=True)
                print("  === LOG END ===", flush=True)
                break
            except urllib.error.HTTPError as e:
                print(f"  Log HTTP error: {e.code} {e.reason}", flush=True)
                if e.code == 410:
                    print("  Logs expired (410 Gone)", flush=True)
                    break
                time.sleep(2)
            except Exception as e:
                print(f"  Log error: {e}", flush=True)
                time.sleep(2)

if __name__ == "__main__":
    main()