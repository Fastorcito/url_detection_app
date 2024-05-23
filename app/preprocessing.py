
from urllib.parse import urlparse, unquote
import re
import tldextract
import pandas as pd

def extract_domain(url):
    extracted = tldextract.extract(url)
    return f"{extracted.domain}.{extracted.suffix}"

def count_character_occurrences(url, character):
    return url.count(character)

def abnormal_url(url):
    hostname = urlparse(url).hostname
    hostname = str(hostname)
    match = re.search(hostname, url)
    return 1 if match else 0

def has_https(url):
    return int("https" in url)

def count_digits(string):
    return sum(1 for char in string if char.isdigit())

def count_letters(string):
    return sum(1 for char in string if char.isalpha())

shortening_pattern = r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|' \
                     r'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|' \
                     r'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|' \
                     r'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|' \
                     r'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|' \
                     r'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|' \
                     r'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|' \
                     r'tr\.im|link\.zip\.net'

def has_shortening_service(url):
    return int(re.search(shortening_pattern, url, flags=re.I) is not None)

ip_pattern = (
    r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.'
    r'([01]?\d\d?|2[0-4]\d|25[0-5])\/)|'
    r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.'
    r'([01]?\d\d?|2[0-4]\d|25[0-5])\/)|'
    r'((0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\/)'
    r'(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'
    r'([0-9]+(?:\.[0-9]+){3}:[0-9]+)|'
    r'((?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)(?:\/\d{1,2})?)'
)

def has_ip_address(url):
    return int(re.search(ip_pattern, url, flags=re.I) is not None)

def check_for_malicious_code(url):
    if re.search(r'javascript:', url):
        return 1
    if re.search(r'<\s*script', url, re.IGNORECASE) or re.search(r'on\w*=', url, re.IGNORECASE):
        return 1
    return 0

def check_text_encoding(url):
    parsed_url = urlparse(url)
    text_part = parsed_url.path
    decoded_text = unquote(text_part)
    return 0 if decoded_text == text_part else 1

def preprocess_url(url):
    features = {
        'URL_Length': len(url),
        'type_ratio': len(url) / 100, 
        '@': count_character_occurrences(url, '@'),
        '?': count_character_occurrences(url, '?'),
        '-': count_character_occurrences(url, '-'),
        '=': count_character_occurrences(url, '='),
        '.': count_character_occurrences(url, '.'),
        '#': count_character_occurrences(url, '#'),
        '%': count_character_occurrences(url, '%'),
        '+': count_character_occurrences(url, '+'),
        '$': count_character_occurrences(url, '$'),
        '!': count_character_occurrences(url, '!'),
        '*': count_character_occurrences(url, '*'),
        ',': count_character_occurrences(url, ','),
        '//': count_character_occurrences(url, '//'),
        'Abnormal_URL': abnormal_url(url),
        'Has_HTTPS': has_https(url),
        'Digit_Count': count_digits(url),
        'Letter_Count': count_letters(url),
        'Has_Shortening_Service': has_shortening_service(url),
        'Has_IP_Address': has_ip_address(url),
        'Has_javascript_Code': check_for_malicious_code(url),
        'Has_Text_Encoding': check_text_encoding(url)
    }
    return pd.DataFrame([features])
