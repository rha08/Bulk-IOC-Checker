import requests

class Hash():
    def __init__(self, hash):
        self.hash = hash  # Store the provided hash value

    def virustotal(self):
        API_KEY = "b25c1c92505a65c7e763e4e6d1e47bcf2226b5f5ec5493d85705b708762363ba"
        VT_URL = "https://www.virustotal.com/api/v3/files/"

        headers = {
            "x-apikey": API_KEY
        }

        url = VT_URL + self.hash  # Construct API URL
        response = requests.get(url, headers=headers)  # Make GET request

        if response.status_code == 200:
            result = response.json()
            analysis = result['data']['attributes']['last_analysis_results']

            flag = any(details['result'] is not None for details in analysis.values())

            return "Malicious" if flag else "Clean"

        elif response.status_code == 429:  # API rate limit exceeded
            return "API_Limit"

        else:
            return f"{response.status_code}: {response.reason}"  # Return error details


class IPAddress():
    def __init__(self, ip):
        self.ip = ip  # Store the provided IP address

    def abuseipdb(self):
        API_KEY = "082e1328eb21c0802c38cd9502592ad9fcd81aa8dfbb19452bb5a3796810352f56466265638226b4"
        url = "https://api.abuseipdb.com/api/v2/check"

        params = {"ipAddress": self.ip}

        headers = {
            "Accept": "application/json",
            "Key": API_KEY
        }

        response = requests.get(url, headers=headers, params=params)

        if response.status_code == 200:
            data = response.json()
            abuse_confidence_score = data['data']['abuseConfidenceScore']

            return "Malicious" if abuse_confidence_score > 0 else "Clean"

        elif response.status_code == 429:  # API rate limit exceeded
            return "API_Limit"

        else:
            return f"{response.status_code}: {response.reason}"  # Return error details


class Domain():
    def __init__(self, domain):
        self.domain = domain  # Store the provided domain name

    def alienvault(self):  # Domain should not include 'www.'
        API_KEY = "6fc1902347a503769c257ec4649f7ba2db0a16e2a70411f1588d0682b6097256"
        HEADERS = {'X-OTX-API-KEY': API_KEY}

        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}"
        response = requests.get(url, headers=HEADERS)

        if response.status_code == 200:
            data = response.json()
            pulse_count = data.get("pulse_info", {}).get("count", 0)

            return "Malicious" if pulse_count > 0 else "Clean"

        elif response.status_code == 429:  # API rate limit exceeded
            return "API_Limit"

        else:
            return f"{response.status_code}: {response.reason}"  # Return error details