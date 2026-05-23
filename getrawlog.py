import urllib.request, gzip, io, os, sys, time

ctx = urllib.request.ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = urllib.request.ssl.CERT_NONE

run_id = sys.argv[1] if len(sys.argv) > 1 else "26334262145"
url = f"https://github.com/fugui-zhang92/FilePlus/actions/runs/{run_id}/logs"

print(f"Downloading logs from {url}...", flush=True)
for retry in range(5):
    try:
        req = urllib.request.Request(url)
        req.add_header('Accept', 'application/json')
        resp = urllib.request.urlopen(req, context=ctx, timeout=60)
        data = resp.read()
        print(f"Downloaded {len(data)} bytes", flush=True)
        
        # Try to extract zip
        import zipfile
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for name in z.namelist():
                print(f"\n=== File: {name} ===", flush=True)
                content = z.read(name).decode('utf-8', errors='replace')
                print(content[-2000:], flush=True)  # Last 2000 chars
        break
    except urllib.request.HTTPError as e:
        print(f"HTTP Error: {e.code} {e.reason}", flush=True)
        if e.code == 502 or e.code == 500:
            time.sleep(10)
            continue
        break
    except Exception as e:
        print(f"Error: {e}", flush=True)
        time.sleep(10)
        continue