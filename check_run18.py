import urllib.request, json, ssl
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

run_id = "26334262145"
r = urllib.request.urlopen(f"https://api.github.com/repos/fugui-zhang92/FilePlus/actions/runs/{run_id}", context=ctx)
run = json.loads(r.read())
print("Run status:", run.get("status"), run.get("conclusion"))
print("Jobs URL:", run.get("jobs_url"))

j = urllib.request.urlopen(run["jobs_url"], context=ctx)
jobs = json.loads(j.read())
for job in jobs.get("jobs", []):
    print("Job:", job["name"], job["status"], job["conclusion"])
    print("Steps:")
    for step in job.get("steps", []):
        print(f"  {step['number']}. {step['name']}: {step['status']} {step.get('conclusion','')}")
    # Try to get the log for step 4
    if job.get("steps"):
        for step in job["steps"]:
            if step["name"] == "Build Tweak (.deb)":
                print("  Build Tweak step log URL:", step.get("log"))