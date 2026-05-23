import urllib.request, json, sys, time, ssl

ctx = ssl._create_unverified_context()
run_id = sys.argv[1] if len(sys.argv) > 1 else None
poll = len(sys.argv) > 2 and sys.argv[2] == "poll"

def fetch(url):
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github.v3+json"})
    return json.loads(urllib.request.urlopen(req, context=ctx).read())

while True:
    if run_id:
        r = fetch(f"https://api.github.com/repos/fugui-zhang92/FilePlus/actions/runs/{run_id}")
    else:
        runs = fetch("https://api.github.com/repos/fugui-zhang92/FilePlus/actions/runs?per_page=1").get("workflow_runs", [])
        if not runs:
            print("No runs found")
            sys.exit(1)
        r = runs[0]

    msg = r.get("head_commit", {}).get("message", "?")[:60] if r.get("head_commit") else "?"
    print(f"Run #{r['run_number']}: status={r['status']} conclusion={r['conclusion']} msg={msg}")

    if not poll:
        break

    if r["status"] == "completed":
        print(f"\nBuild #{r['run_number']} completed! Conclusion: {r['conclusion']}")
        if r["conclusion"] == "success":
            print("SUCCESS: IPA should be available in artifacts!")
        else:
            print("FAILED: Check the build logs.")

        artifacts = fetch(f"https://api.github.com/repos/fugui-zhang92/FilePlus/actions/runs/{r['id']}/artifacts").get("artifacts", [])
        for a in artifacts:
            size_mb = a["size_in_bytes"] / 1024 / 1024
            print(f"  Artifact: {a['name']} ({size_mb:.1f} MB)")
        break

    time.sleep(60)