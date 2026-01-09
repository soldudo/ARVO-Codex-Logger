import logging
import os
import sys
import requests
import re
from urllib.parse import urlparse, quote_plus
from pathlib import Path

logger = logging.getLogger(__name__)

def setup_logger():
    # logger for development debugging. This does not capture LLM info
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler("commit_files.log"),
            logging.StreamHandler(sys.stdout)
        ]
    )

def download_commit_files(url, dest_path):
    parsed = urlparse(url)
    domain = parsed.netloc
    
    # 1. Detect Platform
    if "github.com" in domain:
        logger.info(f"Detected GitHub URL: {url}")
        gt_files = handle_github(parsed, dest_path)
    elif "gitlab" in domain or "gnome.org" in domain:
        logger.info(f"Detected GitLab URL: {url}")
        gt_files = handle_gitlab(parsed, dest_path)
    elif "ffmpeg.org" in domain:
        logger.debug(f"Detected FFmpeg URL: {url}")
        handle_ffmpeg(parsed, dest_path)
    else:
        logger.warning(f"Unsupported domain: {domain}")
        gt_files = []   
    return gt_files

def handle_github(parsed, dest_path):
    path_parts = parsed.path.strip('/').split('/')
    if len(path_parts) < 4: 
        logger.error("Could not parse GitHub URL structure.")
        return []
    
    owner, repo, sha = path_parts[0], path_parts[1], path_parts[3]
    api_url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
    gt_files = process_download(api_url, "github", sha, dest_path=dest_path)
    return gt_files

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
        return []

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
    gt_files = process_download(api_url, "gitlab", sha, context, dest_path)
    return gt_files

def handle_ffmpeg(parsed, dest_path):
    path = parsed.path.strip('/')

    parts = path.split('/')
    if 'commitdiff' in parts:
        sha_index = parts.index('commitdiff') + 1
    elif 'commit' in parts:
        sha_index = parts.index('commit') + 1
    else:
        logger.error("Could not parse FFmpeg URL structure.")
        return []
    
    if sha_index >= len(parts):
        logger.error("Could not find SHA in FFmpeg URL.")
        return []
    
    sha = parts[sha_index]

    base_path_parts = parts[:sha_index - 1]
    base_path = '/'.join(base_path_parts)

    api_url = f"https://{parsed.netloc}/{base_path}/patch/{sha}"

    context = {
        "base_domain": parsed.netloc,
        "base_path": base_path,
        "sha": sha
    }

    gt_files = process_download(api_url, "ffmpeg", sha, context, dest_path)

def process_download(api_url, platform, sha, context=None, dest_path="."):
    logger.info(f'Downloading {api_url} commit files...')
    response = requests.get(api_url)
    
    if response.status_code != 200:
        logger.error(f"API Error: {response.status_code} - {response.text}")
        return []
        
    # Create directory
    output_dir = Path(dest_path) / f'grndtrth'
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Normalize the list of files to download
    files_to_download = []
    
    if platform == "github":

        data = response.json()

        # GitHub returns a 'files' list inside the commit object
        files_list = data.get('files', [])
        for f in files_list:
            files_to_download.append({
                "path": f['filename'],
                "url": f['raw_url']
            })
            
    elif platform == "gitlab":
        data = response.json()

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

    elif platform == "ffmpeg":
        patch_text = response.text
        
        # Regex to find modified files in the diff: "diff --git a/path b/path"
        # We capture the 'b' path (the new version)
        # Note: This regex assumes standard filenames without spaces/quotes. 
        diff_pattern = re.compile(r'^diff --git a/.* b/(.*)$', re.MULTILINE)
        found_paths = diff_pattern.findall(patch_text)

        found_paths = list(set(found_paths))

        for file_path in found_paths:
            # Construct GitWeb blob_plain URL:
            # https://git.ffmpeg.org/gitweb/ffmpeg.git/blob_plain/SHA:/path/to/file
            raw_url = f"https://{context['base_domain']}/{context['base_path']}/blob_plain/{context['sha']}:/{file_path}"
            files_to_download.append({
                "path": file_path,
                "url": raw_url
            })

    logger.info(f"Found {len(files_to_download)} file(s). Downloading...")

    # Execute Downloads
    gt_files = []
    for item in files_to_download:
        local_path = output_dir / item['path']
        local_path.parent.mkdir(parents=True, exist_ok=True)
        logger.info(f"Downloading {item['path']} to {local_path}...")
                
        r = requests.get(item['url'])
        if r.status_code == 200:
            local_path.write_bytes(r.content)
            gt_files.append(str(local_path))
        else:
            logger.error(f"Failed to download {item['url']}: Status {r.status_code}")
    
    return gt_files

# # TEST 1: GitHub
# print("--- Test 1: GitHub ---")
# download_commit_files("https://github.com/ntop/nDPI/commit/759910ffe524460e9dad31d61ffafae8f5429f35", './dev/gtest')
download_commit_files('https://github.com/php/php-src/commit/dd3a098a9bf967831e889d2e19e873d09c71c9b9', './runs')
# setup_logger()
# print("\n--- Test 2: GitLab (GNOME) ---")
# # TEST 2: GitLab
# download_commit_files("https://gitlab.gnome.org/GNOME/libxml2/-/commit/a3992815b3d4caa4a6709406ca085c9f93856809", './dev/gtest')

# Test 3: GitHub - multiple files
# print("\n--- Test 3: GitHub (Multiple Files) ---")
# download_commit_files("https://github.com/wolfssl/wolfssl/commit/4364700c01bb55bc664106e6c8b997849ec69228", './dev/gtest')

# # Debug 1: GitHub
# setup_logger()
# print('--- Debug 1: GitHub ---')
# download_commit_files('https://github.com/OpenSC/OpenSC/commit/eab4d17866bb457dd86d067b304294e9f6671d52', '/home/ngibson/repos/ARVO-Codex-Logger/runs/arvo-421520684-vul-1767405264/')