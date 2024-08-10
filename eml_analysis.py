## import modules
import os
import re
import socket
import hashlib
import requests
import base64
from email import policy
from email.parser import BytesParser
from dotenv import load_dotenv
from datetime import datetime

## load environment variables from .env file
load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')

class EmailAnalyzer:
    def __init__(self, eml_content):
        self.eml_content = eml_content
        self.metadata = {}
        self.output = []

    ## function to check URL on Virus Total
    def check_virustotal_url(self, url):
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": response.json().get('error', 'Unable to check URL')}

    ## function to extract authentication results from email content
    def extract_auth_results(self):
        pattern = r'^Authentication-Results: ([\s\S]*?(?=\n\S|\Z))'
        match = re.search(pattern, self.eml_content, re.DOTALL | re.MULTILINE)
        return match.group(1) if match else "No Authentication Results Found."

    ## function to extract IP address and reverse DNS from email content
    def extract_ip_address(self):
        pattern = r'ip.*?\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
        match = re.search(pattern, self.eml_content, re.IGNORECASE)
        if match:
            ip_address = match.group(1)
            try:
                domain_name = socket.gethostbyaddr(ip_address)[0]
            except socket.herror:
                domain_name = "Reverse DNS Failed"
            return ip_address, domain_name
        return "No IP Addresses Found", None

    ## function to extract email address from pattern
    def extract_email_address(self, pattern):
        match = re.search(pattern, self.eml_content, re.DOTALL | re.MULTILINE)
        return match.group(1) if match else "No address found"

    ## functions to extract subject from email content
    def extract_subject(self):
        pattern = r'^Subject: ([\s\S]*?(?=\n\S|\Z))'
        match = re.search(pattern, self.eml_content, re.DOTALL | re.MULTILINE)
        return match.group(1) if match else "No Subject Found"

    ## function to extract addresses (To/Cc) from email content
    def extract_addresses(self, field_pattern, address_pattern):
        field_match = re.search(field_pattern, self.eml_content, re.DOTALL | re.MULTILINE)
        if field_match:
            field_content = re.split(r'\n\S', field_match.group(1))[0]
            addresses = set(re.findall(address_pattern, field_content))
            return addresses if addresses else "No addresses found"
        return "No field found"

    ## functions to extract date from email content
    def extract_date(self):
        pattern = r'^Date: ([\s\S]*?(?=\n\S|\Z))'
        match = re.search(pattern, self.eml_content, re.DOTALL | re.MULTILINE)
        return match.group(1) if match else "No Date Found"

    ## function to extract URLs from email content
    def extract_urls(self):
        pattern = r'https?://[^\s<>"\']+'
        urls = re.findall(pattern, self.eml_content)
        return urls if urls else ["No URLs Found"]

    ## function to sanitize URL
    def sanitize_url(self, url):
        return url.replace(".", "[.]")

    ## function to extract attachments from email content
    def extract_attachments(self):
        parser = BytesParser(policy=policy.default).parsebytes(self.eml_content.encode())
        attachments = []
        for part in parser.walk():
            content_disposition = part.get("Content-Disposition", None)
            if content_disposition and ("attachment" in content_disposition or "inline" in content_disposition):
                filename = part.get_filename()
                if filename:
                    file_content = part.get_payload(decode=True)
                    attachments.append((filename, file_content))
                    print(f"Attachment found: {filename}")
            else:
                print(f"No attachment found in part with Content-Disposition: {content_disposition}")
        return attachments

    ## function to hash file content
    def hash_file(self, content, hash_func):
        hasher = hash_func()
        hasher.update(content)
        return hasher.hexdigest()

    ## function to check file hash on VirusTotal
    def check_virustotal_file(self, hash_value):
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}
        response = requests.get(f'https://www.virustotal.com/api/v3/files/{hash_value}', headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": response.json().get('error', 'Unable to check file hash')}

    ## function to format VirusTotal URL result
    def format_vt_url_result(self, url, vt_result, url_index):
        if 'error' in vt_result:
            return f"<p>Error: {vt_result['error']}</p>", 0, 0
        
        data = vt_result.get('data', {}).get('attributes', {})
        total_votes = data.get('total_votes', {})
        reputation = data.get('reputation', 0)
        analysis_results = data.get('last_analysis_results', {})
        analysis_stats = data.get('last_analysis_stats', {})

        # Community Score
        harmless_votes = total_votes.get('harmless', 0)
        malicious_votes = total_votes.get('malicious', 0)
        community_score = reputation
        
        community_score_text = (
            "Neutral" if community_score == 0 else
            "Good" if community_score > 0 else
            "Bad"
        )
        
        # Malicious and Suspicious counts
        malicious_count = analysis_stats.get('malicious', 0)
        suspicious_count = analysis_stats.get('suspicious', 0)
        total_count = sum(analysis_stats.values())
        
        formatted_result = (
            f"<h3>VirusTotal URL Check for {url}</h3>"
            f"<p style='color: red;'>Malicious: {malicious_count} / {total_count}</p>"
            f"<p style='color: red;'>Suspicious: {suspicious_count} / {total_count}</p>"
            f"<p>Community Score: {community_score} ({community_score_text})</p>"
            f"<button class='table-toggle btn btn-secondary'>Toggle Security Vendors Analysis</button>"
            f"<div class='table-container'>"
            "<table class='table table-dark'>"
            "<thead><tr><th>Engine Name</th><th>Category</th><th>Result</th></tr></thead><tbody>"
        )
        
        ## sort analysis results: Malicious and Suspicious first
        sorted_results = sorted(
            analysis_results.items(),
            key=lambda item: (item[1]['category'] in ['malicious', 'suspicious'], item[1]['category']),
            reverse=True
        )
        
        for engine, result in sorted_results:
            engine_name = result.get('engine_name', 'Unknown')
            category = result.get('category', 'Unknown')
            analysis_result = result.get('result', 'Unknown')
            color = 'red' if category in ['malicious', 'suspicious'] else 'black'
            formatted_result += f"<tr style='color: {color};'><td>{engine_name}</td><td>{category}</td><td>{analysis_result}</td></tr>"
        
        formatted_result += "</tbody></table></div>"
        
        return formatted_result, malicious_count, suspicious_count

    ## function to format VirusTotal file result
    def format_vt_file_result(self, filename, vt_result):
        if 'error' in vt_result:
            return f"<p style='color: green;'>File not found on VirusTotal</p>"
        
        data = vt_result.get('data', {}).get('attributes', {})
        total_votes = data.get('total_votes', {})
        analysis_results = data.get('last_analysis_results', {})
        analysis_stats = data.get('last_analysis_stats', {})

        # Check if file is malicious or clean
        malicious_count = analysis_stats.get('malicious', 0)
        if malicious_count > 0:
            color = 'red'
            message = f"<p style='color: red;'>Malicious file detected: {filename}</p>"
        else:
            color = 'green'
            message = f"<p style='color: green;'>File is clean: {filename}</p>"

        formatted_result = (
            f"{message}"
            f"<button class='table-toggle btn btn-secondary'>Toggle Security Vendors Analysis</button>"
            f"<div class='table-container'>"
            f"<table class='table table-dark'>"
            f"<thead><tr><th>Engine Name</th><th>Category</th><th>Result</th></tr></thead><tbody>"
        )
        
        for engine, result in analysis_results.items():
            engine_name = result.get('engine_name', 'Unknown')
            category = result.get('category', 'Unknown')
            analysis_result = result.get('result', 'Unknown')
            formatted_result += f"<tr style='color: {color};'><td>{engine_name}</td><td>{category}</td><td>{analysis_result}</td></tr>"
        
        formatted_result += "</tbody></table></div>"
        
        return formatted_result

    ## function to analyze EML file
    def analyze(self):
        auth_results = self.extract_auth_results()
        self.metadata['auth_results'] = auth_results
        
        ip_address, domain_name = self.extract_ip_address()
        self.metadata['ip_address'] = ip_address
        self.metadata['domain_name'] = domain_name if domain_name else "N/A"
        
        from_address = self.extract_email_address(r'^From: .*?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})')
        self.metadata['from_address'] = from_address
        
        return_path = self.extract_email_address(r'^Return[-\s]*Path: .*?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})')
        self.metadata['return_path'] = return_path
        
        subject = self.extract_subject()
        self.metadata['subject'] = subject
        
        recipients = self.extract_addresses(r'^To:(.*(?:\n\s+.*)*)', r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        self.metadata['recipients'] = '<br>'.join(recipients) if isinstance(recipients, set) else recipients
        
        cc_addresses = self.extract_addresses(r'^Cc:(.*(?:\n\s+.*)*)', r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        self.metadata['cc_addresses'] = '<br>'.join(cc_addresses) if isinstance(cc_addresses, set) else cc_addresses
        
        date = self.extract_date()
        self.metadata['date'] = date
        
        reply_to = self.extract_email_address(r'^Reply[-\s]*To: .*?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})')
        self.metadata['reply_to'] = reply_to
        
        urls = self.extract_urls()
        sanitized_urls = [self.sanitize_url(url) for url in urls]
        self.metadata['urls'] = sanitized_urls
        
        total_malicious = 0
        total_suspicious = 0
        for idx, url in enumerate(urls):
            if url != "No URLs Found":
                vt_result = self.check_virustotal_url(url)
                formatted_vt_result, malicious_count, suspicious_count = self.format_vt_url_result(url, vt_result, idx)
                total_malicious += malicious_count
                total_suspicious += suspicious_count
                self.output.append(f"<div>{formatted_vt_result}</div>")
        
        self.metadata['total_malicious'] = total_malicious
        self.metadata['total_suspicious'] = total_suspicious
        self.metadata['total_urls'] = len(urls)

        attachments = self.extract_attachments()
        if attachments:
            for filename, file_content in attachments:
                self.output.append(f"<div class='attachment'><h2>Attachment Detected:</h2>")
                self.output.append(f"<p>{filename}</p>")
                save_path = os.path.join(os.getcwd(), 'uploads', filename)
                with open(save_path, 'wb') as f:
                    f.write(file_content)
                self.output.append(f"<p>Successfully Saved Attachment To: {save_path}</p>")
                sha256_hash = self.hash_file(file_content, hashlib.sha256)
                md5_hash = self.hash_file(file_content, hashlib.md5)
                self.output.append(f"<p>SHA256: {sha256_hash}</p>")
                self.output.append(f"<p>MD5: {md5_hash}</p>")
                vt_result = self.check_virustotal_file(sha256_hash)
                formatted_vt_result = self.format_vt_file_result(filename, vt_result)
                self.output.append(f"<div>VirusTotal File Check (SHA256):<br>{formatted_vt_result}</div></div>")
        else:
            self.output.append("<h2>No Attachments Found</h2>")
        
        self.metadata['analysis_time'] = datetime.now().strftime("%Y%m%d_%H%M%S")
        return ''.join(self.output), self.metadata
