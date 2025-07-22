import psutil
import requests
import hashlib
import os
import time
import json

CACHE_FILE = 'cache.json'

class ProcessScanner:
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key):
        self.api_key = api_key
        self.headers = {"x-apikey": self.api_key}
        self.safe_cache = self.load_cache()

    def load_cache(self):
        """Loads known-safe hashes from the cache file."""
        try:
            with open(CACHE_FILE, 'r') as f:
                return set(json.load(f))
        except (FileNotFoundError, json.JSONDecodeError):
            return set()

    def save_cache(self):
        """Saves the current set of known-safe hashes to the file."""
        with open(CACHE_FILE, 'w') as f:
            json.dump(list(self.safe_cache), f, indent=2)

    def _get_file_hash(self, file_path):
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
                return sha256_hash.hexdigest()
        except (IOError, PermissionError):
            return None

    def scan_processes(self):
        """A generator that yields live updates, prioritizing the local cache for speed."""
        try:
            all_procs = list(psutil.process_iter(['pid', 'name', 'exe']))
            total_procs = len(all_procs)
        except Exception:
            all_procs = []
            total_procs = 0

        for i, proc in enumerate(all_procs):
            pid, name, path = proc.info.get('pid'), proc.info.get('name', 'N/A'), proc.info.get('exe')

            yield {"type": "new_process", "pid": pid, "name": name, "path": path}
            yield {"type": "progress", "current": i + 1, "total": total_procs}
            
            verdict = {"type": "result", "pid": pid, "status": "Safe", "details": "Not scanned."}

            try:
                if not path or not os.path.exists(path):
                    verdict["details"] = "Skipped (inaccessible path)."
                    yield verdict
                    continue

                file_hash = self._get_file_hash(path)
                if not file_hash:
                    verdict["details"] = "Skipped (hashing error)."
                    yield verdict
                    continue

                # --- FAST PATH: CHECK CACHE FIRST ---
                if file_hash in self.safe_cache:
                    verdict.update({"status": "Cached Safe", "details": "Verified locally."})
                    yield verdict
                    continue

                # --- SLOW PATH: API CALL (ONLY IF NOT IN CACHE) ---
                time.sleep(16) # Respect API rate limit
                report_url = f"{self.BASE_URL}/files/{file_hash}"
                response = requests.get(report_url, headers=self.headers, timeout=10)

                if response.status_code == 200:
                    data = response.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    positives = stats.get("malicious", 0)

                    if positives > 0:
                        verdict.update({"status": "Harmful", "details": f"{positives}/{sum(stats.values())} engines flagged."})
                    else:
                        verdict.update({"status": "Safe", "details": "Clean (via VirusTotal)"})
                        self.safe_cache.add(file_hash) # Add to cache for next time
                else:
                    verdict.update({"status": "Safe", "details": "Not found in VirusTotal."})
                    self.safe_cache.add(file_hash) # Also cache files VT doesn't know about
            
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                verdict.update({"status": "Safe", "details": "Skipped (process disappeared)."})
            except requests.RequestException:
                verdict.update({"status": "Error", "details": "Network error."})

            yield verdict