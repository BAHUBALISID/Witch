# WITCH – Advanced API Security & Secret Hunter  
#### Created by sid7.py (ProxyNation)

Witch is a powerful OSINT-based security scanner designed to hunt **exposed secrets, API keys, tokens, and misconfigurations** inside APIs listed on SwaggerHub.  
It performs deep regex analysis, multi-threaded scanning, metadata extraction, and auto-report generation.

The goal: **Slay vulnerabilities like monsters before attackers find them**.

---

## Key Features

| Feature | Description |
|--------|-------------|
| Multi-Threaded Scanner | High-speed scanning using up to 25 concurrent workers |
| 40+ Secret Detection Rules | Google, AWS, GitHub, Stripe, JWT, DB creds & more |
| OSINT-Focused | Queries SwaggerHub for APIs based on keyword |
| Detailed Output Report | JSON export with metadata |
| Intelligent Regex Engine | Safely extracts sensitive keys from responses |
| Real-time Progress Tracking | Color-coded stdout indicators |
| Request Handling | Smart retry, timeout & status diagnostics |
| Internal Asset Discovery | Detects API endpoints, private IPs, and internal URLs |

---

## Installation 
```
git clone https://github.com/BAHUBALISID/Witch.git
cd Witch
pip install -r requirements.txt
```
---

## Output Example

After a scan you will see:
- Summary of vulnerabilities found
- Top secret types
- URLs affected
- JSON report (if `-o` flag used)

JSON structure:
```json
{
  "search_term": "example",
  "timestamp": "2025-12-03T20:21:00",
  "total_found": 18,
  "secrets": [
    {
      "url": "https://api.example.com",
      "type": "github_access_token",
      "secret": "ghp_xxxxxxxxxxxxxxxxxxxxx",
      "timestamp": "...",
      "status": "valid"
    }
  ]
}
```

## ⚠️Legal and Ethical Disclaimer
```
This tool is intended ONLY for:

Security researchers

Authorized penetration testers

Organizations assessing their own risk


Unauthorized scanning of systems you do not own or have explicit permission for is illegal and punishable under cybercrime laws.

The developer assumes no responsibility
for any misuse or damages caused by this tool.
Use responsibly and ethically.
