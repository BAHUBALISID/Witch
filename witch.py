#!/usr/bin/env python3
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests, sys, re, json, os, time, argparse
from datetime import datetime
from colorama import Fore, Style, init
import signal

# Initialize colorama
init(autoreset=True)

# Advanced regex patterns with better organization
regex_patterns = {
    'google_api': r'AIza[0-9A-Za-z-_]{35}',
    'firebase': r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
    'google_captcha': r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$',
    'google_oauth': r'ya29\.[0-9A-Za-z\-_]+',
    'amazon_aws_access_key_id': r'A[SK]IA[0-9A-Z]{16}',
    'amazon_aws_secret_key': r'[A-Za-z0-9+/]{40}',
    'amazon_mws_auth_token': r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    'facebook_access_token': r'EAACEdEose0cBA[0-9A-Za-z]+',
    'authorization_basic': r'basic\s+[a-zA-Z0-9=:_\+\/-]{5,100}',
    'authorization_bearer': r'bearer\s+[a-zA-Z0-9_\-\.=:_\+\/]{5,100}',
    'mailgun_api_key': r'key-[0-9a-zA-Z]{32}',
    'twilio_api_key': r'SK[0-9a-fA-F]{32}',
    'twilio_account_sid': r'AC[a-zA-Z0-9_\-]{32}',
    'twilio_app_sid': r'AP[a-zA-Z0-9_\-]{32}',
    'paypal_braintree_access_token': r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
    'square_oauth_secret': r'sq0csp-[0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}',
    'square_access_token': r'sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}',
    'stripe_standard_api': r'sk_live_[0-9a-zA-Z]{24}',
    'stripe_restricted_api': r'rk_live_[0-9a-zA-Z]{24}',
    'stripe_public_key': r'pk_live_[0-9a-zA-Z]{24}',
    'github_access_token': r'gh[ps]_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82}',
    'github_oauth': r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*',
    'private_key': r'-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----',
    'json_web_token': r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$',
    'slack_token': r'xox[baprs]-[0-9a-zA-Z]{10,48}',
    'heroku_api_key': r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
    'ssh_private_key': r'-----BEGIN (?:OPENSSH|RSA|DSA|EC) PRIVATE KEY-----[A-Za-z0-9+\/\n=\s]+-----END (?:OPENSSH|RSA|DSA|EC) PRIVATE KEY-----',
    'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    'aws_s3_bucket': r'([a-zA-Z0-9.-]+\.)?s3(?:-website)?\.(?:[a-zA-Z0-9-]+\.)?amazonaws\.com',
    'digitalocean_token': r'dop_v1_[a-f0-9]{64}',
    'docker_registry': r'([a-zA-Z0-9-]+\.)?docker\.(?:io|com)',
    'mongodb_uri': r'mongodb(?:\+srv)?:\/\/[a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\/[a-zA-Z0-9._-]+',
    'postgres_uri': r'postgres(?:ql)?:\/\/[a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\/[a-zA-Z0-9._-]+',
    'mysql_uri': r'mysql:\/\/[a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\/[a-zA-Z0-9._-]+',
    'redis_uri': r'redis:\/\/[a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+:[0-9]+\/[0-9]+',
    'sql_connection': r'(?i)(jdbc:|odbc:|connection string)[a-zA-Z0-9=;:+/._-]+',
    'api_endpoint': r'(?i)(https?:\/\/[a-zA-Z0-9._-]+\/api\/[a-zA-Z0-9\/._-]+)',
    'internal_ip': r'\b(?:10\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)[0-9.]+',
    'password_in_text': r'(?i)(pass(?:word|wd)?|pwd)[=:\s]+[\'"`]?([a-zA-Z0-9!@#$%^&*()_+\-=\[\]{}|;:,.<>?~]+)[\'"`]?',
    'auth_header': r'(?i)(authorization|api[_-]?key|secret|token)[\s:]+[\'"`]?([a-zA-Z0-9_\-=+/.]{10,})[\'"`]?',
}

class SidSpy:
    def __init__(self, search_term, output_file=None, verbose=False, timeout=10, max_workers=25):
        self.search_term = search_term
        self.output_file = output_file
        self.verbose = verbose
        self.timeout = timeout
        self.max_workers = max_workers
        self.found_count = 0
        self.secrets_found = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json'
        })
        
    def display_banner(self):
        """Display ASCII art banner with SID branding"""
        sid_ascii = f"""
{Fore.MAGENTA}
                   88           
                   ""   ,d              88           
                        88              88           
{Fore.CYAN}8b      db      d8 88 MM88MMM ,adPPYba, 88,dPPYba,   
`8b    d88b    d8' 88   88   a8"     "" 88P'    "8a  
 `8b  d8'`8b  d8'  88   88   8b         88       88  
  `8bd8'  `8bd8'   88   88,  "8a,   ,aa 88       88  
    YP      YP     88   "Y888 `"Ybbd8"' 88       88
{Fore.GREEN}
    ╔══════════════════════════════════════════════════╗
    ║                 witch v1.0 - by sid7.py         ║
    ║        Advanced SwaggerHub OSINT Scanner         ║
    ╚══════════════════════════════════════════════════╝
{Style.RESET_ALL}
        """
        
        print(sid_ascii)
        print(f"{Fore.YELLOW}[*] Target: {self.search_term}")
        print(f"{Fore.YELLOW}[*] Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Fore.YELLOW}[*] Pattern Count: {len(regex_patterns)}")
        print(f"{Fore.YELLOW}[*] Workers: {self.max_workers}")
        print(f"{Fore.YELLOW}[*] Timeout: {self.timeout}s")
        print("="*70 + "\n")

    def check_regex(self, data):
        """Check data against all regex patterns"""
        matches = []
        for pattern_name, pattern in regex_patterns.items():
            try:
                found = re.findall(pattern, data, re.IGNORECASE)
                if found:
                    for match in found:
                        if isinstance(match, tuple):
                            match = match[1] if len(match) > 1 else match[0]
                        matches.append((pattern_name, match))
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.RED}[!] Regex error in {pattern_name}: {e}")
        return matches

    def process_url(self, url):
        """Process a single URL for secrets"""
        try:
            response = self.session.get(url, timeout=self.timeout)
            if response.status_code == 200:
                data = response.text
                matches = self.check_regex(data)
                
                if matches:
                    self.found_count += len(matches)
                    for pattern_name, content in matches:
                        self.secrets_found.append({
                            'url': url,
                            'type': pattern_name,
                            'secret': content,
                            'timestamp': datetime.now().isoformat(),
                            'status': 'valid'
                        })
                    
                    if self.verbose:
                        print(f"{Fore.GREEN}[✓] {url}")
                        for pattern_name, content in matches:
                            truncated = content[:80] + "..." if len(content) > 80 else content
                            print(f"    {Fore.CYAN}[*] {pattern_name}: {Fore.YELLOW}{truncated}")
                    return matches
                    
            elif response.status_code == 404:
                if self.verbose:
                    print(f"{Fore.BLUE}[.] {url} - Not Found (404)")
            elif response.status_code == 403:
                if self.verbose:
                    print(f"{Fore.YELLOW}[!] {url} - Forbidden (403)")
            elif response.status_code >= 500:
                if self.verbose:
                    print(f"{Fore.RED}[!] {url} - Server Error ({response.status_code})")
                    
        except requests.exceptions.Timeout:
            if self.verbose:
                print(f"{Fore.RED}[⏱] {url} - Timeout")
        except requests.exceptions.ConnectionError:
            if self.verbose:
                print(f"{Fore.RED}[✗] {url} - Connection Error")
        except requests.exceptions.RequestException as e:
            if self.verbose:
                print(f"{Fore.RED}[!] {url} - Request Error: {e}")
        except Exception as e:
            if self.verbose:
                print(f"{Fore.RED}[!] {url} - Unexpected Error: {e}")
        
        return []

    def get_swaggerhub_urls(self):
        """Fetch URLs from SwaggerHub API"""
        base_url = "https://app.swaggerhub.com/apiproxy/specs"
        urls = []
        
        try:
            print(f"{Fore.CYAN}[*] Querying SwaggerHub API for: '{self.search_term}'")
            
            # First request to get total count
            params = {
                'sort': 'BEST_MATCH',
                'order': 'DESC',
                'query': self.search_term,
                'page': 0,
                'limit': 100
            }
            
            response = self.session.get(base_url, params=params, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                total_count = data.get('totalCount', 0)
                urls.extend(self.extract_urls_from_response(data))
                
                if total_count == 0:
                    print(f"{Fore.YELLOW}[!] No APIs found for search term: {self.search_term}")
                    return []
                
                # Calculate pages needed
                total_pages = (total_count // 100) + 1
                print(f"{Fore.CYAN}[*] Found {total_count} total APIs")
                print(f"{Fore.CYAN}[*] Processing {total_pages} pages")
                
                # Process remaining pages in parallel
                with ThreadPoolExecutor(max_workers=min(10, self.max_workers)) as executor:
                    futures = []
                    for page in range(1, min(total_pages, 10)):  # Limit to 10 pages max
                        future = executor.submit(self.fetch_page, base_url, page)
                        futures.append(future)
                    
                    for future in as_completed(futures):
                        try:
                            page_data = future.result()
                            new_urls = self.extract_urls_from_response(page_data)
                            urls.extend(new_urls)
                            print(f"{Fore.GREEN}[+] Page processed, found {len(new_urls)} URLs")
                        except Exception as e:
                            print(f"{Fore.RED}[!] Error fetching page: {e}")
                
                urls = list(set(filter(None, urls)))  # Remove duplicates and None values
                print(f"{Fore.GREEN}[✓] Collected {len(urls)} unique URLs")
                
            else:
                print(f"{Fore.RED}[✗] API request failed: {response.status_code}")
                print(f"{Fore.RED}[!] Response: {response.text[:200]}")
                
        except Exception as e:
            print(f"{Fore.RED}[✗] Error fetching URLs: {e}")
        
        return urls

    def fetch_page(self, base_url, page):
        """Fetch a specific page from SwaggerHub"""
        params = {
            'sort': 'BEST_MATCH',
            'order': 'DESC',
            'query': self.search_term,
            'page': page,
            'limit': 100
        }
        response = self.session.get(base_url, params=params, timeout=self.timeout)
        response.raise_for_status()
        return response.json()

    def extract_urls_from_response(self, data):
        """Extract URLs from SwaggerHub API response"""
        urls = []
        try:
            for api in data.get('apis', []):
                # Check properties
                for prop in api.get('properties', []):
                    url = prop.get('url')
                    if url:
                        urls.append(url)
                
                # Check swagger object
                if 'swagger' in api:
                    swagger_obj = api['swagger']
                    if isinstance(swagger_obj, dict) and 'url' in swagger_obj:
                        urls.append(swagger_obj['url'])
                    elif isinstance(swagger_obj, str) and swagger_obj.startswith('http'):
                        urls.append(swagger_obj)
                        
        except Exception as e:
            if self.verbose:
                print(f"{Fore.YELLOW}[!] Error extracting URLs: {e}")
        
        return urls

    def save_results(self):
        """Save results to output file"""
        if not self.output_file or not self.secrets_found:
            return
        
        try:
            output_data = {
                'search_term': self.search_term,
                'timestamp': datetime.now().isoformat(),
                'total_found': len(self.secrets_found),
                'secrets': self.secrets_found,
                'scan_metadata': {
                    'pattern_count': len(regex_patterns),
                    'workers': self.max_workers,
                    'timeout': self.timeout
                }
            }
            
            with open(self.output_file, 'w') as f:
                json.dump(output_data, f, indent=2)
            
            print(f"{Fore.GREEN}[✓] Results saved to: {self.output_file}")
            
        except Exception as e:
            print(f"{Fore.RED}[✗] Error saving results: {e}")

    def generate_report(self):
        """Generate a summary report"""
        if not self.secrets_found:
            return
        
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════╗")
        print(f"{Fore.CYAN}║                    SECURITY FINDINGS                    ║")
        print(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════╝")
        
        # Group findings by type
        findings_by_type = {}
        for secret in self.secrets_found:
            secret_type = secret['type']
            if secret_type not in findings_by_type:
                findings_by_type[secret_type] = []
            findings_by_type[secret_type].append(secret)
        
        # Print findings by type
        for secret_type, secrets in findings_by_type.items():
            print(f"\n{Fore.YELLOW}【 {secret_type.upper()} 】")
            print(f"{Fore.WHITE}Count: {len(secrets)}")
            for i, secret in enumerate(secrets[:3], 1):  # Show first 3 of each type
                print(f"  {i}. {secret['secret'][:60]}...")
            if len(secrets) > 3:
                print(f"  ... and {len(secrets) - 3} more")

    def run(self):
        """Main execution method"""
        self.display_banner()
        
        print(f"{Fore.CYAN}[*] Fetching URLs from SwaggerHub...")
        urls = self.get_swaggerhub_urls()
        
        if not urls:
            print(f"{Fore.RED}[✗] No URLs found for search term: {self.search_term}")
            return
        
        print(f"\n{Fore.CYAN}[*] Scanning {len(urls)} URLs for secrets...")
        
        start_time = time.time()
        processed_count = 0
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_url = {executor.submit(self.process_url, url): url for url in urls}
            
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                processed_count += 1
                
                # Progress indicator
                if processed_count % 10 == 0:
                    progress = (processed_count / len(urls)) * 100
                    print(f"{Fore.BLUE}[~] Progress: {processed_count}/{len(urls)} ({progress:.1f}%)")
                
                try:
                    future.result(timeout=self.timeout + 5)
                except Exception as e:
                    if self.verbose:
                        print(f"{Fore.RED}[!] Processing error for {url}: {e}")
        
        elapsed_time = time.time() - start_time
        
        # Display summary
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════╗")
        print(f"{Fore.CYAN}║                      SCAN SUMMARY                       ║")
        print(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════╝")
        print(f"{Fore.YELLOW}[✓] URLs Scanned: {len(urls)}")
        print(f"{Fore.YELLOW}[✓] Secrets Found: {self.found_count}")
        print(f"{Fore.YELLOW}[✓] Time Elapsed: {elapsed_time:.2f} seconds")
        print(f"{Fore.YELLOW}[✓] Scan Rate: {len(urls)/elapsed_time:.2f} URLs/second")
        
        if self.secrets_found:
            self.generate_report()
            
            # Show most common types
            type_counts = {}
            for secret in self.secrets_found:
                secret_type = secret['type']
                type_counts[secret_type] = type_counts.get(secret_type, 0) + 1
            
            print(f"\n{Fore.GREEN}【 TOP FINDINGS BY TYPE 】")
            sorted_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            for secret_type, count in sorted_types:
                print(f"  {Fore.CYAN}{secret_type}: {Fore.YELLOW}{count} findings")
        
        # Save results if output file specified
        if self.output_file:
            self.save_results()
        
        print(f"\n{Fore.GREEN}[✓] Scan completed successfully!")
        print(f"{Fore.MAGENTA}     SIDSPY - Advanced API Security Scanner")
        print(f"{Fore.MAGENTA}     Created by sid7.py")

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print(f"\n{Fore.YELLOW}[!] Scan interrupted by user")
    sys.exit(0)

def main():
    """Main entry point"""
    signal.signal(signal.SIGINT, signal_handler)
    
    parser = argparse.ArgumentParser(
        description='SIDSPY - Advanced SwaggerHub OSINT Scanner by sid7.py',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com
  %(prog)s "api service" -o results.json
  %(prog)s target.org -v -w 50 -t 30
        """
    )
    
    parser.add_argument('search_term', help='Search term (domain, company name, API name, etc.)')
    parser.add_argument('-o', '--output', help='Output JSON file for results')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-t', '--timeout', type=int, default=10, 
                       help='Request timeout in seconds (default: 10)')
    parser.add_argument('-w', '--workers', type=int, default=25,
                       help='Number of concurrent workers (default: 25)')
    
    args = parser.parse_args()
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    
    try:
        spy = SidSpy(
            search_term=args.search_term,
            output_file=args.output,
            verbose=args.verbose,
            timeout=args.timeout,
            max_workers=args.workers
        )
        spy.run()
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[✗] Critical error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
