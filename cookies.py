import os
import shutil
import sqlite3
import platform
import pandas as pd
import numpy as np
import getpass
import psutil
import subprocess
import json
import base64
import datetime as dt
from pathlib import Path
import logging

# Logging setup
logging.basicConfig(level=logging.INFO)

# Fixed boolean to string mapping and validation helpers
def safe_bool_to_string(df, bool_columns):
    """Safely convert boolean-like columns to string representations 'Yes'/'No'/'Unknown'."""
    if df is None or df.empty:
        return df
    for col in bool_columns:
        if col not in df.columns:
            continue
        try:
            def map_bool_value(val):
                if pd.isna(val) or val is None:
                    return 'Unknown'
                if val in [True, 1, '1', 'true', 'True', 'TRUE']:
                    return 'Yes'
                if val in [False, 0, '0', 'false', 'False', 'FALSE']:
                    return 'No'
                return 'Unknown'
            df[col + '_str'] = df[col].apply(map_bool_value)
        except Exception as e:
            logging.warning(f"Failed to create string mapping for column {col}: {e}")
            df[col + '_str'] = 'Unknown'
    return df

def validate_dataframe_completeness(df, df_name):
    """Log warnings about empty or problematic columns for export diagnostics."""
    if df is None or df.empty:
        logging.warning(f"{df_name} is empty or None")
        return
    empty_cols = []
    for col in df.columns:
        try:
            if df[col].isna().all() or (df[col] == '').all():
                empty_cols.append(col)
        except Exception:
            # Non-comparable column types; skip
            continue
    if empty_cols:
        logging.warning(f"{df_name} has empty columns: {empty_cols}")
    str_cols = [col for col in df.columns if col.endswith('_str')]
    for col in str_cols:
        try:
            unique_vals = df[col].dropna().unique()
            if len(unique_vals) == 0:
                logging.warning(f"String column {col} in {df_name} has no valid values")
            elif len(unique_vals) == 1 and unique_vals[0] == 'Unknown':
                logging.warning(f"String column {col} in {df_name} only contains 'Unknown' values")
        except Exception:
            continue

try:
    # Windows DPAPI
    import win32crypt  # type: ignore
except Exception:
    win32crypt = None  # type: ignore

try:
    # Prefer Cryptodome if available; fallback to Crypto
    from Cryptodome.Cipher import AES  # type: ignore
except Exception:
    try:
        from Crypto.Cipher import AES  # type: ignore
    except Exception:
        AES = None  # type: ignore

try:
    import tldextract  # type: ignore
except Exception:
    tldextract = None  # type: ignore

# Domain classification lists (extendable)
TRUSTED_DOMAINS = {
    'google.com', 'gstatic.com', 'googleapis.com', 'googleusercontent.com', 'gmail.com',
    'microsoft.com', 'office.com', 'outlook.com', 'microsoftonline.com', 'live.com',
    'apple.com', 'icloud.com', 'github.com', 'stackoverflow.com', 'slack.com', 'zoom.us',
    'amazon.com', 'amazonaws.com', 'cloudfront.net', 'paypal.com'
}
KNOWN_TRACKERS = {
    'doubleclick.net', 'googleadservices.com', 'googlesyndication.com', 'adservice.google.com',
    'facebook.com', 'facebook.net', 'connect.facebook.net', 'twitter.com', 'ads-twitter.com',
    'linkedin.com', 'adsystem.amazon.com', 'amazon-adsystem.com', 'criteo.com', 'taboola.com',
    'outbrain.com', 'pubmatic.com', 'quantserve.com', 'scorecardresearch.com'
}
SUSPICIOUS_KEYWORDS = ['push', 'click', 'trk', 'track', 'ad', 'ads', 'notif', 'notify', 'popup']


def classify_domain_enhanced(domain):
    """Classify domain reputation with tldextract and lists. Returns: trusted|suspicious|unknown"""
    try:
        d = (domain or '').lower()
        if not d:
            return 'unknown'
        if tldextract is not None:
            extracted = tldextract.extract(d)
            main_domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
        else:
            parts = d.lstrip('.').split('.')
            main_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else d
        if main_domain in TRUSTED_DOMAINS or any(main_domain.endswith(f'.{td}') for td in TRUSTED_DOMAINS):
            return 'trusted'
        if (main_domain in KNOWN_TRACKERS) or any(k in main_domain for k in SUSPICIOUS_KEYWORDS):
            return 'suspicious'
        return 'unknown'
    except Exception as e:
        logging.warning(f"Failed to classify domain {domain}: {e}")
        return 'unknown'

# Domain category mapping for Power BI visuals
DOMAIN_CATEGORY_KEYWORDS = {
    'Social Media': ['facebook.com', 'instagram.com', 'twitter.com', 'x.com', 'linkedin.com', 'tiktok.com', 'snapchat.com', 'pinterest.com'],
    'Search': ['google.com', 'bing.com', 'yahoo.com', 'duckduckgo.com'],
    'E-commerce': ['amazon.com', 'ebay.com', 'aliexpress.com', 'walmart.com', 'etsy.com'],
    'Video/Streaming': ['youtube.com', 'netflix.com', 'hulu.com', 'disneyplus.com', 'primevideo.com', 'twitch.tv'],
    'Productivity': ['microsoft.com', 'office.com', 'outlook.com', 'googleusercontent.com', 'slack.com', 'zoom.us'],
    'CDN/Infra': ['cloudfront.net', 'akamaihd.net', 'akamai.net', 'fastly.net', 'cloudflare.com', 'gstatic.com', 'googleapis.com'],
    'Advertising/Tracking': list(KNOWN_TRACKERS),
}

def categorize_domain(domain):
    try:
        d = (domain or '').lower()
        if not d:
            return 'Other'
        if tldextract is not None:
            ex = tldextract.extract(d)
            main = f"{ex.domain}.{ex.suffix}" if ex.suffix else ex.domain
        else:
            parts = d.lstrip('.').split('.')
            main = '.'.join(parts[-2:]) if len(parts) >= 2 else d
        for category, keywords in DOMAIN_CATEGORY_KEYWORDS.items():
            if any(main.endswith(k) or k in main for k in keywords):
                return category
        return 'Other'
    except Exception as e:
        logging.warning(f"Failed to categorize domain {domain}: {e}")
        return 'Other'


def get_cookies_path(browser):
    user = getpass.getuser()
    paths = {
        'Windows': {
            'chrome': f"C:\\Users\\{user}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies",
            'brave': f"C:\\Users\\{user}\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Network\\Cookies",
            'edge': f"C:\\Users\\{user}\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Network\\Cookies"
        },
        'Darwin': {
            'chrome': f"/Users/{user}/Library/Application Support/Google/Chrome/User Data/Default/Network/Cookies",
            'brave': f"/Users/{user}/Library/Application Support/BraveSoftware/Brave-Browser/User Data/Default/Network/Cookies",
            'edge': f"/Users/{user}/Library/Application Support/Microsoft Edge/User Data/Default/Network/Cookies"
        },
        'Linux': {
            'chrome': f"/home/{user}/.config/google-chrome/User Data/Default/Network/Cookies",
            'brave': f"/home/{user}/.config/BraveSoftware/Brave-Browser/User Data/Default/Network/Cookies",
            'edge': f"/home/{user}/.config/microsoft-edge/User Data/Default/Network/Cookies"
        }
    }
    return paths.get(platform.system(), {}).get(browser)


def get_profile_root(browser):
    user = getpass.getuser()
    if platform.system() == 'Windows':
        roots = {
            'chrome': f"C:\\Users\\{user}\\AppData\\Local\\Google\\Chrome\\User Data",
            'brave': f"C:\\Users\\{user}\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data",
            'edge': f"C:\\Users\\{user}\\AppData\\Local\\Microsoft\\Edge\\User Data",
        }
    elif platform.system() == 'Darwin':
        roots = {
            'chrome': f"/Users/{user}/Library/Application Support/Google/Chrome/User Data",
            'brave': f"/Users/{user}/Library/Application Support/BraveSoftware/Brave-Browser/User Data",
            'edge': f"/Users/{user}/Library/Application Support/Microsoft Edge/User Data",
        }
    else:
        roots = {
            'chrome': f"/home/{user}/.config/google-chrome/User Data",
            'brave': f"/home/{user}/.config/BraveSoftware/Brave-Browser/User Data",
            'edge': f"/home/{user}/.config/microsoft-edge/User Data",
        }
    return roots.get(browser)


def chrome_time_to_datetime(chrome_time_int):
    # Chrome/WebKit epoch: 1601-01-01 in microseconds
    try:
        if chrome_time_int is None:
            return None
        epoch_start = dt.datetime(1601, 1, 1)
        return epoch_start + dt.timedelta(microseconds=int(chrome_time_int))
    except Exception:
        return None


def list_profile_dirs(browser):
    root = get_profile_root(browser)
    if not root or not os.path.exists(root):
        return []
    try:
        candidates = []
        for name in os.listdir(root):
            if name == 'Default' or name.startswith('Profile '):
                p = os.path.join(root, name)
                if os.path.isdir(p):
                    candidates.append(p)
        return candidates
    except Exception:
        return []


def load_local_state_key(profile_root):
    """Return decrypted AES key for Chromium cookies (cross-platform)."""
    try:
        local_state_path = Path(profile_root) / 'Local State'
        if not local_state_path.exists():
            return None
        with open(local_state_path, 'r', encoding='utf-8') as f:
            state = json.load(f)
        enc_key_b64 = state.get('os_crypt', {}).get('encrypted_key')
        if not enc_key_b64:
            return None
        enc_key = base64.b64decode(enc_key_b64)

        system = platform.system()

        if system == 'Windows':
            if enc_key.startswith(b'DPAPI'):
                enc_key = enc_key[5:]
            if win32crypt is None:
                return None
            return win32crypt.CryptUnprotectData(enc_key, None, None, None, 0)[1]
        elif system == 'Darwin':
            try:
                import keyring  # type: ignore
                password = keyring.get_password("Chrome Safe Storage", "Chrome")
                if password:
                    return password.encode()[:16]
            except Exception:
                return None
        elif system == 'Linux':
            try:
                import secretstorage  # type: ignore
                connection = secretstorage.dbus_init()
                collection = secretstorage.get_default_collection(connection)
                for item in collection.get_all_items():
                    if item.get_label() == 'Chrome Safe Storage':
                        return item.get_secret()[:16]
            except Exception:
                return None
        return None
    except Exception:
        return None


def decrypt_cookie_value(encrypted_value_bytes, aes_key):
    """Decrypt Chrome cookie value. Supports AES-GCM (v10/v11) and legacy DPAPI."""
    if not encrypted_value_bytes:
        return ''
    try:
        # AES-GCM format: v10 or v11 | 12-byte nonce | ciphertext | 16-byte tag
        if encrypted_value_bytes.startswith((b'v10', b'v11')):
            if AES is None or aes_key is None:
                return ''
            nonce = encrypted_value_bytes[3:15]
            ct_and_tag = encrypted_value_bytes[15:]
            if len(ct_and_tag) < 16:
                return ''
            ciphertext, tag = ct_and_tag[:-16], ct_and_tag[-16:]
            cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
            return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8', errors='ignore')
        # Legacy DPAPI encryption
        if win32crypt is not None:
            try:
                return win32crypt.CryptUnprotectData(encrypted_value_bytes, None, None, None, 0)[1].decode('utf-8', errors='ignore')
            except Exception:
                return ''
        return ''
    except Exception:
        return ''


def is_browser_running(browser):
    process_names = {
        'chrome': ['chrome.exe', 'Google Chrome', 'chrome'],
        'brave': ['brave.exe', 'Brave Browser', 'brave-browser', 'brave'],
        'edge': ['msedge.exe', 'Microsoft Edge', 'msedge']
    }
    target_names = process_names.get(browser.lower(), [])
    for p in psutil.process_iter(attrs=['name', 'exe']):
        proc_name = (p.info.get('name') or '').lower()
        proc_exe = (p.info.get('exe') or '').lower()
        if any(name.lower() in proc_name or name.lower() in proc_exe for name in target_names):
            return True
    return False


def close_browser(browser):
    system = platform.system()
    for p in psutil.process_iter(attrs=['pid', 'name']):
        name = (p.info.get('name') or '')
        if browser.lower() in name.lower():
            try:
                if system == 'Windows':
                    subprocess.call(["taskkill", "/F", "/PID", str(p.info['pid'])], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                else:
                    os.kill(p.info['pid'], 15)
            except (ProcessLookupError, PermissionError):
                continue


def extract_cookies(browser):
    profile_root = get_profile_root(browser)
    if not profile_root or not os.path.exists(profile_root): 
        return None
    if is_browser_running(browser): 
        close_browser(browser)
    aes_key = load_local_state_key(profile_root)
    try:
        all_rows = []
        for prof_dir in list_profile_dirs(browser):
            cookies_db = os.path.join(prof_dir, 'Network', 'Cookies')
            if not os.path.exists(cookies_db):
                continue
            temp_db = "temp_cookies.db"
            if os.path.exists(temp_db):
                os.remove(temp_db)
            shutil.copy2(cookies_db, temp_db)
            conn = sqlite3.connect(temp_db)
            query = (
                "SELECT host_key, name, encrypted_value, value, path, is_secure, is_httponly,"
                " last_access_utc, has_expires, expires_utc, is_persistent, samesite,"
                " source_scheme, creation_utc, priority FROM cookies"
            )
            df = pd.read_sql_query(query, conn)
            conn.close()
            os.remove(temp_db)
            df['__profile_name'] = os.path.basename(prof_dir)
            all_rows.append(df)
        if not all_rows:
            return None
        df = pd.concat(all_rows, ignore_index=True)

        # Decrypt values and derive fields
        decrypted_values = []
        last_access_human = []
        cookie_age_days = []
        is_session_cookie = []
        expires_human = []
        days_until_expiry = []
        cookie_size_bytes = []
        has_non_ascii = []
        for _, row in df.iterrows():
            enc = row.get('encrypted_value')
            plain = ''
            if isinstance(enc, (bytes, bytearray)):
                plain = decrypt_cookie_value(enc, aes_key)
            if not plain:
                # Fallback to plaintext 'value' column if present
                v = row.get('value')
                if isinstance(v, str):
                    plain = v
            decrypted_values.append(plain)
            cookie_size_bytes.append(len(plain.encode('utf-8', errors='ignore')) if isinstance(plain, str) else 0)
            try:
                has_non_ascii.append(any(ord(ch) > 127 for ch in plain))
            except Exception:
                has_non_ascii.append(False)

            last_dt = chrome_time_to_datetime(row.get('last_access_utc'))
            last_access_human.append(last_dt.isoformat(sep=' ') if last_dt else None)

            creation_dt = chrome_time_to_datetime(row.get('creation_utc'))
            age_days = None
            if creation_dt:
                age_days = max(0, (dt.datetime.utcnow() - creation_dt).days)
            cookie_age_days.append(age_days)

            # Prefer Chromium's is_persistent flag when available
            if 'is_persistent' in row and row.get('is_persistent') is not None:
                sess = 0 if row.get('is_persistent') else 1
            else:
                sess = 1 if (not row.get('has_expires') or not row.get('expires_utc')) else 0
            is_session_cookie.append(sess)

            exp_dt = chrome_time_to_datetime(row.get('expires_utc')) if row.get('expires_utc') else None
            expires_human.append(exp_dt.isoformat(sep=' ') if exp_dt else None)
            if exp_dt:
                days_left = (exp_dt - dt.datetime.utcnow()).days
            else:
                days_left = None
            days_until_expiry.append(days_left)

        df['cookie_value'] = decrypted_values
        df['last_access_utc_readable'] = last_access_human
        df['cookie_age_days'] = cookie_age_days
        df['is_session_cookie'] = is_session_cookie
        df['expires_utc_readable'] = expires_human
        df['days_until_expiry'] = days_until_expiry
        df['cookie_size_bytes'] = cookie_size_bytes
        df['has_non_ascii'] = has_non_ascii

        # Third-party detection (advanced)
        def detect_third_party_relationships(df_in):
            first_party_relationships = {
                'google.com': ['googleapis.com', 'gstatic.com', 'googleusercontent.com'],
                'microsoft.com': ['office.com', 'outlook.com', 'microsoftonline.com'],
                'amazon.com': ['amazonaws.com', 'cloudfront.net'],
                'facebook.com': ['fbcdn.net', 'facebook.net'],
                'apple.com': ['icloud.com', 'apple-cloudkit.com']
            }
            known_trackers = {
                'doubleclick.net', 'googleadservices.com', 'googlesyndication.com',
                'facebook.com', 'connect.facebook.net', 'twitter.com', 'ads.twitter.com',
                'linkedin.com', 'adsystem.amazon.com', 'amazon-adsystem.com',
                'outbrain.com', 'taboola.com', 'criteo.com', 'pubmatic.com'
            }
            def is_third_party_enhanced(row_in):
                host = (row_in.get('host_key') or '').lstrip('.')
                tld = row_in.get('top_level_domain') or ''
                if any(tracker in host for tracker in known_trackers):
                    return True
                for main_domain, related_domains in first_party_relationships.items():
                    if host.endswith(main_domain):
                        return False
                    if any(host.endswith(related) for related in related_domains):
                        main_cookies = df_in[df_in['host_key'].str.contains(main_domain, na=False)]
                        return len(main_cookies) == 0
                return host != tld and not host.endswith(f'.{tld}')
            df_in['is_third_party'] = df_in.apply(is_third_party_enhanced, axis=1)
            return df_in
        df = detect_third_party_relationships(df)

        # Purpose heuristic based on name with lookup
        purpose_lookup = {
            # Analytics
            '_ga': 'Analytics', '_gid': 'Analytics', '_gat': 'Analytics', '_gcl_au': 'Analytics',
            '_uetsid': 'Analytics', '_uetvid': 'Analytics', '_hjSessionUser': 'Analytics',
            # Advertising/Tracking
            'muid': 'Advertising/Tracking', 'fbp': 'Advertising/Tracking', 'fbc': 'Advertising/Tracking',
            'sid': 'Authentication', 'sess': 'Authentication', 'sessionid': 'Authentication', 'auth': 'Authentication', 'token': 'Authentication',
        }

        def infer_purpose(name):
            n = (name or '').lower()
            for key, val in purpose_lookup.items():
                if key in n:
                    return val
            if any(k in n for k in ['ga', '_ga', 'gid', '_gid', 'utm', 'analytics']):
                return 'Analytics'
            if any(k in n for k in ['ad', 'ads', 'gclid', 'fbp', 'fbc', 'muid']):
                return 'Advertising/Tracking'
            if any(k in n for k in ['sess', 'session', 'sid', 'auth', 'token']):
                return 'Authentication'
            return 'Other'

        df['purpose'] = df['name'].apply(infer_purpose)

        # Sensitive name flag (expanded)
        df['has_sensitive_name'] = df['name'].str.lower().fillna('').str.contains('(auth|token|sid|session|password|secret|csrf|xsrf|bearer)', regex=True)

        # Map samesite enum
        def map_samesite(val):
            if val == -1:
                return 'Unspecified'
            if val == 0:
                return 'NoRestriction'
            if val == 1:
                return 'Lax'
            if val == 2:
                return 'Strict'
            return 'Unknown'
        df['samesite_str'] = df['samesite'].apply(map_samesite)

        # Host-only flag
        df['is_host_only'] = ~df['host_key'].fillna('').str.startswith('.')

        # Naive top-level domain (last two labels)
        def naive_tld(host):
            if not isinstance(host, str):
                return None
            parts = host.lstrip('.').split('.')
            return '.'.join(parts[-2:]) if len(parts) >= 2 else host
        df['top_level_domain'] = df['host_key'].apply(naive_tld)

        # Tracking flag based on known trackers and purpose (compute BEFORE scores)
        tracking_name_patterns = ['_ga', '_gid', '_gat', 'muid', 'fbp', 'fbc', 'gclid', 'trk', 'amplitude', 'segment', 'mixpanel']
        df['cookie_tracking_flag'] = (
            df['purpose'].isin(['Analytics', 'Advertising/Tracking']) |
            (df['name'].fillna('').str.lower().apply(lambda n: any(p in n for p in tracking_name_patterns)))
        )

        # Security score heuristic
        def compute_enhanced_security_score(row):
            """Comprehensive security risk scoring."""
            score = 0
            score += 15 if not row.get('is_secure') else 0
            score += 10 if not row.get('is_httponly') else 0
            score += 8 if row.get('samesite_str') == 'NoRestriction' else 0
            score += 5 if row.get('samesite_str') == 'Unspecified' else 0
            score += 10 if row.get('is_session_cookie') == 0 else 0
            age_days = row.get('cookie_age_days', 0) or 0
            if age_days > 365:
                score += 15
            elif age_days > 180:
                score += 8
            elif age_days > 90:
                score += 5
            size_bytes = row.get('cookie_size_bytes', 0) or 0
            if size_bytes > 4096:
                score += 10
            elif size_bytes > 1024:
                score += 5
            score += 8 if row.get('has_non_ascii') else 0
            score += 12 if row.get('has_sensitive_name') else 0
            score += 10 if row.get('is_third_party') else 0
            score += 15 if row.get('cookie_tracking_flag') else 0
            return min(score, 100)

        df['security_score'] = df.apply(compute_enhanced_security_score, axis=1)

        # Privacy-focused cookie risk score
        def compute_privacy_risk_score(row):
            risk_score = 0
            if row.get('is_third_party') and row.get('cookie_tracking_flag'):
                risk_score += 40
            elif row.get('is_third_party'):
                risk_score += 25
            if not row.get('is_session_cookie') and row.get('purpose') in ['Analytics', 'Advertising/Tracking']:
                risk_score += 20
            days_until_expiry = row.get('days_until_expiry', 0) or 0
            if isinstance(days_until_expiry, (int, float)) and days_until_expiry > 365:
                risk_score += 15
            if row.get('has_sensitive_name') and row.get('purpose') == 'Authentication':
                risk_score += 30
            return min(risk_score, 100)

        df['privacy_risk_score'] = df.apply(compute_privacy_risk_score, axis=1)

        # Granular cookie risk points per cookie
        def cookie_risk_points(row):
            points = 0
            points += 3 if row.get('is_third_party') else 0
            points += 2 if row.get('is_session_cookie') == 0 else 0
            points += 2 if row.get('cookie_tracking_flag') else 0
            points += 2 if not row.get('is_secure') else 0
            points += 2 if not row.get('is_httponly') else 0
            points += 1 if row.get('samesite_str') in ['Unspecified', 'NoRestriction'] else 0
            return points

        df['cookie_risk_points'] = df.apply(cookie_risk_points, axis=1)

        # Frequency-based cookie risk at domain level (kept for reference), but cookie-level privacy classification takes precedence
        def days_since_last_access(last_dt_str):
            if not last_dt_str:
                return None
            try:
                last_dt = dt.datetime.fromisoformat(last_dt_str)
                return (dt.datetime.utcnow() - last_dt).days
            except Exception:
                return None

        df['days_since_last_access'] = df['last_access_utc_readable'].apply(days_since_last_access)
        df['recent_access_flag'] = df['days_since_last_access'].apply(lambda d: 1 if (d is not None and d <= 7) else 0)

        host_usage = df.groupby('host_key').agg(
            total_cookies=('name', 'count'),
            recent_hits=('recent_access_flag', 'sum')
        ).reset_index()
        host_usage['freq_ratio'] = (host_usage['recent_hits'] / host_usage['total_cookies'].replace(0, np.nan)).fillna(0)
        conditions = [
            (host_usage['recent_hits'] >= 3) | (host_usage['freq_ratio'] >= 0.5),
            (host_usage['recent_hits'] >= 1) | (host_usage['freq_ratio'] >= 0.2)
        ]
        choices = ['High', 'Medium']
        host_usage['host_cookie_risk_level'] = np.select(conditions, choices, default='Low')

        # Add privacy and security risk perspectives
        def compute_privacy_risk_level(recent_hits, freq_ratio, total_count):
            if recent_hits >= 3 or freq_ratio >= 0.5:
                return 'High'
            if recent_hits >= 1 or freq_ratio >= 0.2:
                return 'Medium'
            return 'Low'

        def compute_security_risk_level(recent_hits, freq_ratio, reputation):
            if reputation == 'trusted':
                return 'Low'
            if recent_hits >= 3 or freq_ratio >= 0.5:
                return 'Medium'
            return 'High'

        # Use domain reputation derived from permissions later; absent here => 'unknown'
        host_usage['privacy_risk_level'] = host_usage.apply(
            lambda r: compute_privacy_risk_level(r['recent_hits'], r['freq_ratio'], r['total_cookies']), axis=1
        )
        host_usage['security_risk_level'] = host_usage.apply(
            lambda r: compute_security_risk_level(r['recent_hits'], r['freq_ratio'], 'unknown'), axis=1
        )

        df = df.merge(host_usage[['host_key', 'host_cookie_risk_level', 'privacy_risk_level', 'security_risk_level']], on='host_key', how='left')

        # Enhanced domain reputation for cookies
        df['domain_reputation'] = df['top_level_domain'].apply(classify_domain_enhanced)

        # Privacy-first cookie risk level per new approach (refined thresholds)
        def cookie_privacy_level(row):
            if row.get('is_third_party') and row.get('cookie_tracking_flag'):
                return 'High'
            if row.get('has_sensitive_name') and row.get('purpose') == 'Authentication':
                return 'High'
            if row.get('is_session_cookie') == 1 and row.get('domain_reputation') == 'trusted':
                return 'Low'
            days_until_expiry = row.get('days_until_expiry')
            # Long-lived persistent cookies are medium-high risk unless trusted
            if (row.get('is_session_cookie') == 0) and (isinstance(days_until_expiry, (int, float)) and days_until_expiry > 365):
                return 'High' if row.get('domain_reputation') != 'trusted' else 'Medium'
            if (row.get('is_session_cookie') == 0) and (isinstance(days_until_expiry, (int, float)) and days_until_expiry > 180):
                return 'Medium'
            return row.get('host_cookie_risk_level') or 'Low'

        df['cookie_risk_level'] = df.apply(cookie_privacy_level, axis=1)

        # Power BI friendly categorical fields (robust mapping)
        bool_cols = ['is_secure', 'is_httponly', 'is_session_cookie', 'is_third_party', 'has_non_ascii', 'is_host_only', 'cookie_tracking_flag', 'has_sensitive_name']
        df = safe_bool_to_string(df, bool_cols)
        # Risk buckets
        def score_bucket(x):
            try:
                v = float(x)
            except Exception:
                return 'Low'
            if v <= 25:
                return 'Low'
            if v <= 50:
                return 'Medium'
            return 'High'
        df['security_score_bucket'] = df['security_score'].apply(score_bucket)
        df['privacy_risk_bucket'] = df['privacy_risk_score'].apply(score_bucket)
        # Domain category
        df['domain_category'] = df['top_level_domain'].apply(categorize_domain)
        # Time-based analysis
        df['weeks_since_last_access'] = df['days_since_last_access'].apply(lambda d: (d // 7) if isinstance(d, (int, float)) else None)
        def age_bucket(days):
            if days is None:
                return 'Unknown'
            if days < 30:
                return 'New (<30d)'
            if days <= 90:
                return 'Recent (30-90d)'
            return 'Old (>90d)'
        df['cookie_age_bucket'] = df['cookie_age_days'].apply(age_bucket)

        # Select and rename columns per requirements
        # Stamp audit date
        audit_date = dt.datetime.utcnow().date().isoformat()

        columns = {
            'host_key': 'host_key',
            'name': 'name',
            'path': 'path',
            'last_access_utc_readable': 'last_access_utc_readable',
            'cookie_age_days': 'cookie_age_days',
            'is_secure': 'is_secure',
            'is_httponly': 'is_httponly',
            'is_session_cookie': 'is_session_cookie',
            'has_expires': 'has_expires',
            'expires_utc_readable': 'expires_utc_readable',
            'days_until_expiry': 'days_until_expiry',
            'is_third_party': 'is_third_party',
            'samesite_str': 'samesite',
            'priority': 'priority',
            'cookie_size_bytes': 'cookie_size_bytes',
            'has_non_ascii': 'has_non_ascii',
            'is_host_only': 'is_host_only',
            'top_level_domain': 'top_level_domain',
            'security_score': 'security_score',
            'source_scheme': 'source_scheme',
            'purpose': 'purpose',
            'has_sensitive_name': 'has_sensitive_name',
            'cookie_risk_level': 'cookie_risk_level',
            'privacy_risk_level': 'privacy_risk_level',
            'security_risk_level': 'security_risk_level',
            'cookie_tracking_flag': 'cookie_tracking_flag',
            'cookie_risk_points': 'cookie_risk_points',
            'privacy_risk_score': 'privacy_risk_score',
            'domain_reputation': 'domain_reputation',
            'domain_category': 'domain_category',
            'is_secure_str': 'is_secure_str',
            'is_httponly_str': 'is_httponly_str',
            'is_session_cookie_str': 'is_session_cookie_str',
            'is_third_party_str': 'is_third_party_str',
            'has_non_ascii_str': 'has_non_ascii_str',
            'is_host_only_str': 'is_host_only_str',
            'cookie_tracking_flag_str': 'cookie_tracking_flag_str',
            'has_sensitive_name_str': 'has_sensitive_name_str',
            'security_score_bucket': 'security_score_bucket',
            'privacy_risk_bucket': 'privacy_risk_bucket',
            'weeks_since_last_access': 'weeks_since_last_access',
            'cookie_age_bucket': 'cookie_age_bucket',
        }
        out_df = df[list(columns.keys())].copy()
        out_df.columns = list(columns.values())
        out_df['browser'] = browser
        out_df['profile'] = df['__profile_name']
        out_df['last_audit_date'] = audit_date
        return out_df
    except PermissionError as e:
        logging.warning(f"Permission error extracting cookies for {browser}: {e}")
        return None
    except Exception as e:
        logging.warning(f"Unexpected error extracting cookies for {browser}: {e}")
        return None


def extract_permissions(browser):
    profile_root = get_profile_root(browser)
    if not profile_root:
        return None
    records = []
    for prof_dir in list_profile_dirs(browser):
        preferences_path = Path(prof_dir) / 'Preferences'
        if not preferences_path.exists():
            continue
        try:
            with open(preferences_path, 'r', encoding='utf-8') as f:
                prefs = json.load(f)
        except Exception as e:
            logging.warning(f"Failed reading Preferences from {preferences_path}: {e}")
            continue

        # Permissions live under profile.content_settings.exceptions
        exceptions = prefs.get('profile', {}).get('content_settings', {}).get('exceptions', {})

        # Map of exception key to human-readable permission type
        permission_key_map = {
            'geolocation': 'geolocation',
            'media_stream_mic': 'microphone',
            'media_stream_camera': 'camera',
            'notifications': 'notifications',
            'clipboard': 'clipboard',
            'sensors': 'sensors',
            'midi_sysex': 'midi',
            'durable_storage': 'persistent-storage',
            'bluetooth_guard': 'bluetooth',
            'serial': 'serial',
            'hid': 'hid',
            'usb_guard': 'usb',
            'file_system_write_guard': 'fs-write',
            'payment_handler': 'payment-handler',
            'idle_detection': 'idle-detection',
            'background_sync': 'background-sync',
            'pointer_lock': 'pointer-lock',
            'ar': 'augmented-reality',
            'vr': 'virtual-reality',
        }

        def interpret_setting(setting_val):
            # Chromium typically uses 1 allow, 2 block, 3 ask
            if setting_val == 1:
                return 'granted'
            if setting_val == 2:
                return 'denied'
            return 'prompt'

        def parse_any_timestamp(value):
            """Return ISO string for multiple possible Chromium timestamp formats or None.
            Supports Chrome/WebKit microseconds since 1601, Unix seconds, Unix ms, and ISO strings.
            """
            if value is None:
                return None
            try:
                # If it's already string and parseable
                if isinstance(value, str):
                    # Some prefs store ISO strings
                    try:
                        return dt.datetime.fromisoformat(value.replace('Z', '+00:00')).replace(tzinfo=None).isoformat(sep=' ')
                    except Exception:
                        # Try as numeric contained in string
                        try:
                            value = int(value)
                        except Exception:
                            return None
                # If it's float, cast to int
                if isinstance(value, float):
                    value = int(value)
                if isinstance(value, int):
                    # Heuristics: Chrome/WebKit epoch are big numbers (~1e17)
                    if value > 10**16:
                        ts = chrome_time_to_datetime(value)
                        return ts.isoformat(sep=' ') if ts else None
                    # Unix ms
                    if value > 10**12:
                        ts = dt.datetime.utcfromtimestamp(value / 1000.0)
                        return ts.isoformat(sep=' ')
                    # Unix seconds
                    if value > 10**9:
                        ts = dt.datetime.utcfromtimestamp(value)
                        return ts.isoformat(sep=' ')
                return None
            except Exception:
                return None

        for key, friendly in permission_key_map.items():
            bucket = exceptions.get(key, {})
            for pattern, data in bucket.items():
                setting_val = data.get('setting')
                source = data.get('source') or (data.get('is_incognito') and 'incognito') or 'user'
                # Attempt multiple possible last-used fields
                last_used_raw = (
                    data.get('last_used')
                    or data.get('last_used_time')
                    or data.get('last_modified')
                    or data.get('last_modified_time')
                    or data.get('last_visited')
                    or data.get('last_visited_time')
                )
                last_used_iso = parse_any_timestamp(last_used_raw)
                incognito = data.get('incognito', False)
                # Request count across possible keys and shapes
                req_count = None
                possible_keys = [
                    'num_requests', 'numRequests', 'request_count', 'requests',
                    'ask_count', 'granted_count', 'count', 'num_prompts'
                ]
                for k in possible_keys:
                    if k in data and data.get(k) is not None:
                        req_count = data.get(k)
                        break
                # Sometimes nested under 'setting' dict
                if req_count is None and isinstance(data.get('setting'), dict):
                    for k in possible_keys:
                        if k in data['setting'] and data['setting'].get(k) is not None:
                            req_count = data['setting'].get(k)
                            break
                try:
                    req_count = int(req_count) if req_count is not None else 0
                except Exception:
                    req_count = 0
                records.append({
                    'pattern': pattern,
                    'permission_type': friendly,
                    'permission_state': interpret_setting(setting_val),
                    'permission_source': source,
                    'permission_scope': 'session-only' if incognito else 'persistent',
                    'permission_request_count': req_count,
                    'permission_last_used': last_used_iso,
                    'profile': os.path.basename(prof_dir),
                })

    if not records:
        return None
    df = pd.DataFrame.from_records(records)

    # Derive domain for reputation lookups
    def pattern_to_domain(pattern):
        p = (pattern or '').replace('[*.]', '').replace('*,', '').replace(',', ' ')
        for sep in ['://', '://www.', 'www.']:
            if sep in p:
                p = p.split(sep)[-1]
        p = p.split('/')[0]
        p = p.split(':')[0]
        return p.strip()

    df['domain'] = df['pattern'].apply(pattern_to_domain)

    # Domain-level aggregates
    domain_agg = df.groupby('domain').agg(
        total_permissions_granted=('permission_type', 'count'),
        sensitive_permission_count=(
            'permission_type',
            lambda s: sum(x in {'camera', 'microphone', 'geolocation'} for x in s)
        )
    ).reset_index()
    df = df.merge(domain_agg, on='domain', how='left')

    # Enhanced domain reputation
    df['reputation'] = df['domain'].apply(classify_domain_enhanced)
    # Numeric reputation score for downstream use
    rep_score_map = {'trusted': 1.0, 'unknown': 0.5, 'suspicious': 0.0}
    df['domain_reputation_score'] = df['reputation'].map(rep_score_map).fillna(0.5)
    df['granted_by_user'] = df['permission_source'].eq('user')

    # Risk heuristic incorporating sensitivity, reputation, and source transparency
    sensitive_types = {'camera', 'microphone', 'geolocation'}

    def permission_risk(row):
        ptype = (row.get('permission_type') or '').lower()
        state = row.get('permission_state')
        reputation = row.get('reputation')
        last_str = row.get('permission_last_used')
        if state != 'granted':
            return 'Low'
        # Notifications baseline
        if ptype == 'notifications':
            if reputation == 'trusted':
                return 'Low'
            if reputation == 'suspicious':
                return 'High'
            return 'Medium'
        # Sensitive baseline
        if ptype in sensitive_types:
            if reputation == 'trusted':
                return 'Low'
            if reputation == 'suspicious':
                return 'High'
            # Unknown domains: bump to High if recently used
            try:
                if last_str:
                    last_dt = dt.datetime.fromisoformat(last_str)
                    days = (dt.datetime.utcnow() - last_dt).days
                    return 'High' if days <= 30 else 'Medium'
            except Exception:
                return 'Medium'
            return 'Medium'
        # Other permission types
        if reputation == 'trusted':
            return 'Low'
        if reputation == 'suspicious':
            return 'Medium'
        return 'Medium'

    df['permission_risk_level'] = df.apply(permission_risk, axis=1)

    # Post-adjust risk based on counts and recency decay
    def adjust_level(level, total_count, unused_days):
        order = ['Low', 'Medium', 'High']
        idx = order.index(level)
        # Raise if too many permissions granted for a domain
        if (total_count or 0) > 2 and idx < 2:
            idx += 1
        # Downgrade if unused for a long time
        if unused_days is not None and unused_days > 180 and idx > 0:
            idx -= 1
        return order[idx]

    # Enrichment
    def days_since_last(last_str):
        if not last_str:
            return None
        try:
            last_dt = dt.datetime.fromisoformat(last_str)
            return (dt.datetime.utcnow() - last_dt).days
        except Exception:
            return None
    df['days_since_last_used'] = df['permission_last_used'].apply(days_since_last)
    df['permission_unused_days'] = df['days_since_last_used']
    df['is_sensitive_permission'] = df['permission_type'].isin(['camera', 'microphone', 'geolocation'])
    df['permission_risk_level'] = df.apply(
        lambda r: adjust_level(r['permission_risk_level'], r.get('total_permissions_granted'), r.get('permission_unused_days')),
        axis=1
    )
    # Power BI friendly categorical fields (robust mapping)
    bool_cols = ['granted_by_user', 'is_sensitive_permission']
    df = safe_bool_to_string(df, bool_cols)
    # Transparency/audit notes
    def build_audit_notes(row):
        notes = []
        src = row.get('permission_source')
        rep = row.get('reputation')
        if src in ('user', 'default', 'policy', 'incognito'):
            notes.append(f"granted by {src}")
        if rep and rep != 'unknown':
            notes.append(f"site {rep}")
        return '; '.join(notes) if notes else None

    df['audit_notes'] = df.apply(build_audit_notes, axis=1)
    df['browser'] = browser
    return df


def combined_risk_assessment(cookies_df, permissions_df):
    # Aggregate per site (host/pattern) and compute combined scores
    def map_level_to_score(level):
        if level == 'High':
            return 3
        if level == 'Medium':
            return 2
        return 1

    cookie_site = None
    if cookies_df is not None and not cookies_df.empty:
        # Aggregate cookie risk using granular points and levels
        c_agg = cookies_df.groupby('host_key').agg(
            cookie_risk_level=('cookie_risk_level', lambda s: max(s, key=lambda x: map_level_to_score(x))),
            cookie_points_sum=('cookie_risk_points', 'sum'),
            cookie_tracking_presence=('cookie_tracking_flag', 'any')
        ).reset_index()
        # Map a numeric cookie score from risk level and points
        c_agg['cookie_score'] = c_agg['cookie_risk_level'].map(map_level_to_score) + (c_agg['cookie_points_sum'] / 6.0).clip(0, 3)
        cookie_site = c_agg

    perm_site = None
    if permissions_df is not None and not permissions_df.empty:
        # Extract domain from pattern like [*.]example.com,* or https://example.com:443, *example*
        def pattern_to_domain(pattern):
            p = (pattern or '').replace('[*.]', '').replace('*,', '').replace(',', ' ')
            for sep in ['://', '://www.', 'www.']:
                if sep in p:
                    p = p.split(sep)[-1]
            p = p.split('/')[0]
            p = p.split(':')[0]
            return p.strip()
        tmp = permissions_df.copy()
        tmp['domain'] = tmp['pattern'].apply(pattern_to_domain)
        p_agg = tmp.groupby('domain').agg(
            permission_risk_level=('permission_risk_level', lambda s: max(s, key=lambda x: map_level_to_score(x))),
            total_permissions_granted=('total_permissions_granted', 'max'),
            sensitive_permission_count=('sensitive_permission_count', 'max'),
            domain_reputation_score=('domain_reputation_score', 'max')
        ).reset_index()
        # Numeric permission score: base on risk + counts, weighted by reputation
        base_score = p_agg['permission_risk_level'].map(map_level_to_score)
        count_bonus = (p_agg['total_permissions_granted'].fillna(0).clip(0, 5) * 0.2) + (p_agg['sensitive_permission_count'].fillna(0).clip(0, 3) * 0.4)
        rep_weight = p_agg['domain_reputation_score'].fillna(0.5)  # 0..1
        p_agg['permission_score'] = (base_score + count_bonus) * (0.75 + 0.5 * (1 - rep_weight))
        perm_site = p_agg

    if cookie_site is None and perm_site is None:
        return None

    if cookie_site is None:
        result = perm_site.copy()
        result.rename(columns={'domain': 'site'}, inplace=True)
        result['cookie_score'] = 0
        result['cookie_risk_level'] = 'Low'
    elif perm_site is None:
        result = cookie_site.copy()
        result.rename(columns={'host_key': 'site'}, inplace=True)
        result['permission_score'] = 0
        result['permission_risk_level'] = 'Low'
    else:
        result = pd.merge(cookie_site, perm_site, left_on='host_key', right_on='domain', how='outer')
        result['site'] = result['host_key'].fillna(result['domain'])
        result['cookie_score'] = result['cookie_score'].fillna(0)
        result['permission_score'] = result['permission_score'].fillna(0)
        result['cookie_risk_level'] = result['cookie_risk_level'].fillna('Low')
        result['permission_risk_level'] = result['permission_risk_level'].fillna('Low')
        result = result[['site', 'cookie_score', 'cookie_risk_level', 'permission_score', 'permission_risk_level']]

    # Weighted site trust score per request: cookie 40%, permission 60%
    result['site_trust_score'] = (result['cookie_score'] * 0.4 + result['permission_score'] * 0.6)

    def overall_level(row):
        score = row['site_trust_score']
        if score >= 2.5:
            return 'High'
        if score >= 1.75:
            return 'Medium'
        return 'Low'

    result['overall_risk_level'] = result.apply(overall_level, axis=1)

    # Cross-site tracking indicator: if same top-level owner across multiple domains with tracking presence
    if cookies_df is not None and not cookies_df.empty:
        def tld(host):
            if not isinstance(host, str):
                return host
            parts = host.lstrip('.').split('.')
            return '.'.join(parts[-2:]) if len(parts) >= 2 else host
        cookie_owner = cookies_df.groupby('host_key')['cookie_tracking_flag'].any().reset_index()
        cookie_owner['owner_tld'] = cookie_owner['host_key'].apply(tld)
        owner_agg = cookie_owner.groupby('owner_tld')['cookie_tracking_flag'].sum().reset_index(name='tracking_domains_count')
        owner_agg['cross_site_tracking_flag'] = owner_agg['tracking_domains_count'] > 1
        # Create column for merge key first to avoid Series-as-key errors
        result['owner_tld'] = result['site'].apply(tld)
        result = result.merge(owner_agg[['owner_tld', 'cross_site_tracking_flag']], on='owner_tld', how='left')
        # Clean up merge auxiliary column
        result['cross_site_tracking_flag'] = result['cross_site_tracking_flag'].fillna(False)

    # Stamp last audit date
    result['last_audit_date'] = dt.datetime.utcnow().date().isoformat()
    return result


def export_to_excel(cookies_df, permissions_df, combined_df, output_path):
    with pd.ExcelWriter(output_path, engine='xlsxwriter') as writer:
        # Validate completeness before writing
        validate_dataframe_completeness(cookies_df, 'Cookies')
        validate_dataframe_completeness(permissions_df, 'Permissions')
        validate_dataframe_completeness(combined_df, 'Risk Summary')
        if cookies_df is not None and not cookies_df.empty:
            cookies_df.to_excel(writer, index=False, sheet_name='Cookies')
        if permissions_df is not None and not permissions_df.empty:
            permissions_df.to_excel(writer, index=False, sheet_name='Permissions')
        if combined_df is not None and not combined_df.empty:
            combined_df.to_excel(writer, index=False, sheet_name='Risk Summary')

        # Summary metrics sheet for Power BI
        summary_rows = []
        try:
            if cookies_df is not None and not cookies_df.empty:
                risk_counts = cookies_df['cookie_risk_level'].value_counts(dropna=False)
                for level in ['Low', 'Medium', 'High']:
                    summary_rows.append({'metric': f'cookies_{level.lower()}', 'value': int(risk_counts.get(level, 0))})
                summary_rows.append({'metric': 'total_cookies', 'value': int(len(cookies_df))})
            if permissions_df is not None and not permissions_df.empty:
                perm_counts = permissions_df['permission_risk_level'].value_counts(dropna=False)
                for level in ['Low', 'Medium', 'High']:
                    summary_rows.append({'metric': f'permissions_{level.lower()}', 'value': int(perm_counts.get(level, 0))})
                summary_rows.append({'metric': 'total_permissions', 'value': int(len(permissions_df))})
            if combined_df is not None and not combined_df.empty:
                # Overall privacy score per site (mean)
                try:
                    summary_rows.append({'metric': 'avg_site_trust_score', 'value': float(combined_df['site_trust_score'].mean())})
                except Exception:
                    pass
                # Top 10 riskiest domains by site_trust_score
                try:
                    top = combined_df.sort_values('site_trust_score', ascending=False).head(10)
                    top[['site', 'site_trust_score']].to_excel(writer, index=False, sheet_name='Top Risks')
                except Exception:
                    pass
        except Exception as e:
            logging.warning(f"Failed building summary metrics: {e}")

        if summary_rows:
            pd.DataFrame(summary_rows).to_excel(writer, index=False, sheet_name='Summary Metrics')


def save_audit_results(cookies_df, permissions_df, combined_df):
    timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"browser_privacy_audit_{timestamp}.xlsx"
    output_path = os.path.join('output', filename)
    export_to_excel(cookies_df, permissions_df, combined_df, output_path)
    print(f"Analysis saved to: {output_path}")
    return output_path


def detect_available_browsers():
    candidates = ['chrome', 'brave', 'edge']
    available = []
    for b in candidates:
        cp = get_cookies_path(b)
        pr = get_profile_root(b)
        if (cp and os.path.exists(cp)) or (pr and os.path.exists(pr)):
            available.append(b)
    return available


def run_audit_all_available():
    os.makedirs('output', exist_ok=True)
    browsers = detect_available_browsers()
    if not browsers:
        print('No supported browsers detected.')
        return
    all_cookies = []
    all_perms = []
    for b in browsers:
        cdf = extract_cookies(b)
        if cdf is not None and not cdf.empty:
            all_cookies.append(cdf)
        pdf = extract_permissions(b)
        if pdf is not None and not pdf.empty:
            all_perms.append(pdf)
    cookies_df = pd.concat(all_cookies, ignore_index=True) if all_cookies else None
    permissions_df = pd.concat(all_perms, ignore_index=True) if all_perms else None
    combined_df = combined_risk_assessment(cookies_df, permissions_df)
    save_audit_results(cookies_df, permissions_df, combined_df)


# Run the audit for local Chrome profile
if __name__ == '__main__':
    run_audit_all_available()

 
