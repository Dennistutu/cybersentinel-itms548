# QUICK API SETUP GUIDE - 5 MINUTES

## STEP 1: Get Your API Keys (All FREE!)

### 1. AbuseIPDB (REQUIRED - 2 minutes)
1. Go to: https://www.abuseipdb.com/register
2. Sign up with your email
3. Verify email
4. Go to: https://www.abuseipdb.com/account/api
5. Copy your API key

### 2. VirusTotal (REQUIRED - 2 minutes)
1. Go to: https://www.virustotal.com/gui/join-us
2. Sign up with your email
3. Verify email
4. Go to: https://www.virustotal.com/gui/user/YOUR_USERNAME/apikey
5. Copy your API key

### 3. AlienVault OTX (REQUIRED - 2 minutes)
1. Go to: https://otx.alienvault.com/
2. Click "Sign Up"
3. Create account
4. Go to: https://otx.alienvault.com/api
5. Copy your OTX Key

### 4. NVD (OPTIONAL - works without key)
1. Go to: https://nvd.nist.gov/developers/request-an-api-key
2. Fill out form
3. Wait for email (may take a few hours)
4. OR just skip it - the app works without NVD key (just slower)

---

## STEP 2: Add Keys to Config File

1. Open: `cybersentinel/config/config.json`
2. Replace the placeholder values with your real keys:

```json
{
  "api_keys": {
    "nvd": "YOUR_NVD_KEY_HERE_OR_LEAVE_EMPTY",
    "abuseipdb": "YOUR_ABUSEIPDB_KEY_HERE",
    "virustotal": "YOUR_VIRUSTOTAL_KEY_HERE",
    "alienvault_otx": "YOUR_OTX_KEY_HERE"
  },
  "settings": {
    "cache_enabled": true,
    "cache_duration_hours": 24,
    "max_api_retries": 3,
    "request_timeout": 30,
    "log_level": "INFO"
  },
  "database": {
    "path": "data/cybersentinel.db"
  }
}
```

3. Save the file

---

## STEP 3: Run the App!

```cmd
cd cybersentinel
venv\Scripts\activate
python src\main.py
```

---

## TEST THE APIS:

### Test IP Reputation (AbuseIPDB):
- Go to "IP Reputation" tab
- Enter: 8.8.8.8
- Click "Check Reputation"
- Should see real Google DNS data

### Test Vulnerability Search (NVD):
- Go to "Vulnerabilities" tab
- Enter: Apache
- Click "Search"
- Should see real CVE data

### Test URL Scan (VirusTotal):
- Go to "Scan" tab
- Enter: https://www.google.com
- Click "Scan"
- Should see real scan results

### Test Threat Intel (AlienVault OTX):
- Go to "Threat Intel" tab
- Enter: ransomware
- Click "Search Pulses"
- Should see real threat intelligence

---

## IF YOU GET ERRORS:

**"API key not configured"**
- Make sure you saved config.json with your real keys
- Make sure the file is in: cybersentinel/config/config.json

**"Rate limit exceeded"**
- VirusTotal free tier = 4 requests/minute (wait 1 minute)
- AbuseIPDB free tier = 1000 requests/day

**"Invalid API key"**
- Double-check you copied the key correctly
- No extra spaces or quotes
- Make sure you verified your email

---

## DONE!

Your CyberSentinel now has REAL threat intelligence! 🎉

All 4 APIs are working and saving data to the database.
