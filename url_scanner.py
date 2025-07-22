import requests
import time
import base64

class URLScanner:
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key):
        self.api_key = api_key
        self.headers = {"x-apikey": self.api_key}

    def _get_url_report(self, url_id):
        report_url = f"{self.BASE_URL}/urls/{url_id}"
        response = requests.get(report_url, headers=self.headers)
        if response.status_code == 200:
            attributes = response.json().get('data', {}).get('attributes', {})
            if attributes.get('last_analysis_stats'):
                return {"stats": attributes['last_analysis_stats']}
        return None

    def scan_url(self, url_to_scan):
        try:
            url_id = base64.urlsafe_b64encode(url_to_scan.encode()).decode().strip("=")

            existing_report = self._get_url_report(url_id)
            if existing_report:
                return existing_report

            scan_api_url = f"{self.BASE_URL}/urls"
            response = requests.post(scan_api_url, headers=self.headers, data={"url": url_to_scan})
            
            if response.status_code != 200:
                error_message = response.json().get('error', {}).get('message', 'Unknown error')
                return {"error": f"API Submission Error: {error_message}"}
            
            analysis_id = response.json().get("data", {}).get("id")
            if not analysis_id:
                return {"error": "Failed to retrieve analysis ID from response."}
            
            return self._poll_for_results(analysis_id)
        except requests.RequestException as e:
            return {"error": f"Network error: {e}"}
        except Exception as e:
            return {"error": f"An unexpected error occurred: {e}"}

    def _poll_for_results(self, analysis_id):
        result_url = f"{self.BASE_URL}/analyses/{analysis_id}"
        # Shorter wait time for faster GUI feedback
        for _ in range(8):
            time.sleep(5)
            try:
                response = requests.get(result_url, headers=self.headers)
                if response.status_code == 200:
                    data = response.json().get("data", {}).get("attributes", {})
                    if data.get("status") == "completed":
                        # THE FIX IS HERE: The backslash has been removed from the next line.
                        return {"stats": data.get("stats", {})}
            except requests.RequestException:
                continue
        return {"error": "Scan timed out."}