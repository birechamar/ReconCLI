import subprocess
import os
import re
from concurrent.futures import ThreadPoolExecutor

TARGET = input("Enter target domain: ").strip()
OUTPUT_DIR = f"results_{TARGET}"

os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(f"{OUTPUT_DIR}/subs", exist_ok=True)
os.makedirs(f"{OUTPUT_DIR}/urls", exist_ok=True)
os.makedirs(f"{OUTPUT_DIR}/classified", exist_ok=True)
os.makedirs(f"{OUTPUT_DIR}/tech", exist_ok=True)


def run(cmd):
    print(f"[+] {cmd}")
    subprocess.run(cmd, shell=True, check=False)


def dedup_file(path):
    if not os.path.exists(path):
        return
    with open(path, "r") as f:
        lines = sorted(set(line.strip() for line in f if line.strip()))
    with open(path, "w") as f:
        f.write("\n".join(lines))


# =========================
# 1. SUBDOMAIN ENUMERATION
# =========================
subs_raw = f"{OUTPUT_DIR}/subs/raw.txt"
run(f"subfinder -d {TARGET} -silent -o {subs_raw}")
run(f"assetfinder --subs-only {TARGET} >> {subs_raw}")
dedup_file(subs_raw)

# =========================
# 2. DNS RESOLUTION
# =========================
subs_resolved = f"{OUTPUT_DIR}/subs/resolved.txt"
run(f"dnsx -l {subs_raw} -silent -o {subs_resolved}")

# =========================
# 3. ALIVE + TECH DETECTION
# =========================
alive = f"{OUTPUT_DIR}/subs/alive.txt"
tech = f"{OUTPUT_DIR}/tech/technologies.txt"
run(f"httpx -l {subs_resolved} -silent -threads 100 -tech-detect -title -status-code -o {tech}")
run(f"cat {tech} | awk '{{print $1}}' > {alive}")

# =========================
# 4. URL COLLECTION
# =========================
katana_urls = f"{OUTPUT_DIR}/urls/katana.txt"
gau_urls = f"{OUTPUT_DIR}/urls/gau.txt"
wayback_urls = f"{OUTPUT_DIR}/urls/wayback.txt"
merged_urls = f"{OUTPUT_DIR}/urls/merged.txt"

run(f"katana -list {alive} -silent -c 50 -o {katana_urls}")
run(f"gau {TARGET} > {gau_urls}")
run(f"waybackurls {TARGET} > {wayback_urls}")
run(f"cat {katana_urls} {gau_urls} {wayback_urls} > {merged_urls}")
dedup_file(merged_urls)

# =========================
# 5. CLASSIFICATION
# =========================
files = {
    'js': [],
    'params': [],
    'endpoints': [],
    'login': [],
    'admin': [],
    'api': [],
    'sensitive': [],
    'uploads': [],
    'graphql': []
}

with open(merged_urls, 'r') as f:
    for line in f:
        url = line.strip().lower()
        if not url:
            continue

        clean = url.split('?')[0]

        if clean.endswith('.js'):
            files['js'].append(url)
            continue

        if '?' in url and '=' in url:
            files['params'].append(url)
        else:
            files['endpoints'].append(url)

        if any(x in url for x in ['login', 'signin', 'auth', 'register', 'password']):
            files['login'].append(url)

        if any(x in url for x in ['admin', 'dashboard', 'panel', 'backend']):
            files['admin'].append(url)

        if any(x in url for x in ['/api/', 'graphql', '/v1/', '/v2/', 'rest']):
            files['api'].append(url)

        if any(x in url for x in ['payment', 'billing', 'checkout', 'order', 'account']):
            files['sensitive'].append(url)

        if any(x in url for x in ['upload', 'avatar', 'profile-picture', 'attachment']):
            files['uploads'].append(url)

        if 'graphql' in url:
            files['graphql'].append(url)

for name, data in files.items():
    with open(f"{OUTPUT_DIR}/classified/{name}.txt", 'w') as f:
        f.write('\n'.join(sorted(set(data))))

# =========================
# 6. LIGHT JS ENDPOINT HINTS
# =========================
js_endpoints = f"{OUTPUT_DIR}/classified/js_endpoints.txt"
patterns = [r'/api/[A-Za-z0-9_\-/]+', r'/v[0-9]+/[A-Za-z0-9_\-/]+']
results = []


def analyze_js(js_url):
    found = []
    try:
        content = subprocess.check_output(f"curl -s {js_url}", shell=True, text=True)
        for p in patterns:
            found.extend(re.findall(p, content))
    except:
        pass
    return found

js_list = files['js']
with ThreadPoolExecutor(max_workers=20) as executor:
    futures = [executor.submit(analyze_js, js) for js in js_list]
    for future in futures:
        results.extend(future.result())

with open(js_endpoints, 'w') as f:
    f.write('\n'.join(sorted(set(results))))

# =========================
# 7. SCREENSHOTS (OPTIONAL)
# =========================
shots_dir = f"{OUTPUT_DIR}/screenshots"
os.makedirs(shots_dir, exist_ok=True)
run(f"gowitness file -f {alive} --screenshot-path {shots_dir} >/dev/null 2>&1")

# =========================
# 8. REPORT SUMMARY JSON
# =========================
import json
summary = {
    'target': TARGET,
    'subdomains_found': sum(1 for _ in open(subs_raw)) if os.path.exists(subs_raw) else 0,
    'resolved_subdomains': sum(1 for _ in open(subs_resolved)) if os.path.exists(subs_resolved) else 0,
    'alive_hosts': sum(1 for _ in open(alive)) if os.path.exists(alive) else 0,
    'urls_collected': sum(1 for _ in open(merged_urls)) if os.path.exists(merged_urls) else 0,
    'js_files': len(files['js']),
    'params': len(files['params']),
    'api_endpoints': len(files['api']),
    'admin_panels': len(files['admin'])
}

with open(f"{OUTPUT_DIR}/summary.json", "w") as f:
    json.dump(summary, f, indent=4)

print("🔥 ADVANCED RECON COMPLETE")
print(f"📁 Output Folder: {OUTPUT_DIR}")
print(f"📊 Summary saved: {OUTPUT_DIR}/summary.json")
