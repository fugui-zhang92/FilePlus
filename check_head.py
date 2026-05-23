import urllib.request, json, ssl
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

url = "https://api.github.com/repos/fugui-zhang92/FilePlus/branches/main"
try:
    r = urllib.request.urlopen(url, context=ctx, timeout=15)
    data = json.loads(r.read())
    print("Latest commit:", data['commit']['sha'])
    print("Message:", data['commit']['commit']['message'])
except Exception as e:
    # Try web-based fallback  
    import urllib.request
    try:
        r2 = urllib.request.urlopen("https://github.com/fugui-zhang92/FilePlus/commits/main", context=ctx, timeout=15)
        html = r2.read().decode('utf-8', errors='replace')
        print("Page length:", len(html))
        # Find the latest commit SHA
        import re
        # Look for the first commit in the page
        lines = html.split('\n')
        for line in lines:
            if 'commit/' in line and 'sha' in line.lower():
                print(line[:200])
                break
    except Exception as e2:
        print(f"Both attempts failed: {e} / {e2}")