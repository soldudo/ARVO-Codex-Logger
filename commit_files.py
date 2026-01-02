import logging
import os
import requests
from urllib.parse import urlparse, quote_plus
from pathlib import Path

logger = logging.getLogger(__name__)

def download_commit_files(url, dest_path):
    parsed = urlparse(url)
    domain = parsed.netloc
    
    # 1. Detect Platform
    if "github.com" in domain:
        logger.info(f"Detected GitHub URL: {url}")
        handle_github(parsed, dest_path)
    elif "gitlab" in domain or "gnome.org" in domain:
        logger.info(f"Detected GitLab URL: {url}")
        handle_gitlab(parsed, dest_path)
    else:
        print(f"Unsupported domain: {domain}")

def handle_github(parsed, dest_path):
    path_parts = parsed.path.strip('/').split('/')
    if len(path_parts) < 4: 
        logger.error("Could not parse GitHub URL structure.")
        return
    
    owner, repo, sha = path_parts[0], path_parts[1], path_parts[3]
    api_url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
    logger.info(f'Downloading {api_url} commit files...')
    process_download(api_url, "github", sha, dest_path)

def handle_gitlab(parsed, dest_path):
    # GitLab URLs often look like: /Namespace/Project/-/commit/SHA
    path = parsed.path.strip('/')
    
    # Remove the '/-/commit/' or '/commit/' part to find the split
    if "/-/commit/" in path:
        project_part, sha = path.split("/-/commit/")
    elif "/commit/" in path:
        project_part, sha = path.split("/commit/")
    else:
        logger.error("Could not parse GitLab URL structure.")
        return

    # GitLab API requires the project path to be URL Encoded (slash -> %2F)
    project_id = quote_plus(project_part)
    
    # Construct API URL for the diff
    # Base URL uses the domain from the input (e.g., gitlab.gnome.org)
    api_url = f"https://{parsed.netloc}/api/v4/projects/{project_id}/repository/commits/{sha}/diff"
    
    # Pass extra context needed to construct raw URLs later
    context = {
        "base_domain": parsed.netloc,
        "project_part": project_part,
        "sha": sha
    }
    process_download(api_url, "gitlab", sha, context, dest_path)

def process_download(api_url, platform, sha, context=None, dest_path="."):
    logger.info(f'Downloading {api_url} commit files...')
    response = requests.get(api_url)
    
    if response.status_code != 200:
        logger.error(f"API Error: {response.status_code} - {response.text}")
        return

    data = response.json()
    
    # Create directory
    output_dir = Path(dest_path) / f'grndtrth_{sha[:7]}'
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Normalize the list of files to download
    files_to_download = []
    
    if platform == "github":
        # GitHub returns a 'files' list inside the commit object
        files_list = data.get('files', [])
        for f in files_list:
            files_to_download.append({
                "path": f['filename'],
                "url": f['raw_url']
            })
            
    elif platform == "gitlab":
        # GitLab returns a list of diff objects directly
        for diff in data:
            file_path = diff['new_path']
            # We must construct the raw URL manually for GitLab
            # Format: https://domain/project/-/raw/sha/path
            raw_url = f"https://{context['base_domain']}/{context['project_part']}/-/raw/{context['sha']}/{file_path}"
            files_to_download.append({
                "path": file_path,
                "url": raw_url
            })

    logger.info(f"Found {len(files_to_download)} file(s). Downloading...")

    # Execute Downloads
    for item in files_to_download:
        local_path = output_dir / item['path']
        local_path.parent.mkdir(parents=True, exist_ok=True)
        logger.info(f"Downloading {item['path']} to {local_path}...")
                
        r = requests.get(item['url'])
        if r.status_code == 200:
            local_path.write_bytes(r.content)
        else:
            logger.error(f"Failed to download {item['url']}: Status {r.status_code}")

# TEST 1: GitHub
# print("--- Test 1: GitHub ---")
# download_commit_files("https://github.com/ntop/nDPI/commit/759910ffe524460e9dad31d61ffafae8f5429f35")

# print("\n--- Test 2: GitLab (GNOME) ---")
# # TEST 2: GitLab
# download_commit_files("https://gitlab.gnome.org/GNOME/libxml2/-/commit/a3992815b3d4caa4a6709406ca085c9f93856809")

# Test 3: GitHub - multiple files
# print("\n--- Test 3: GitHub (Multiple Files) ---")
# download_commit_files("https://github.com/wolfssl/wolfssl/commit/4364700c01bb55bc664106e6c8b997849ec69228")