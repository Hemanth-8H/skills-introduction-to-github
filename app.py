import re
import whois
from datetime import datetime 
from flask import Flask, render_template, request
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

app = Flask(__name__)

# ---------------- URL RULE CHECK (SCORING) ----------------

def url_risk_score(url):

    score = 0

    suspicious_keywords = [
        "login","verify","update","secure",
        "account","bank","free","win",
        "gift","bonus","password"
    ]

    suspicious_tlds = [
        ".ru",".tk",".ml",".ga",".cf",
        ".biz",".xyz",".info"
    ]

    parsed = urlparse(url)

    # @ symbol (strong phishing indicator)
    if '@' in url:
        score += 30

    # Long URL
    if len(url) > 75:
        score += 15

    # IP address instead of domain
    if re.search(r'(\d{1,3}\.){3}\d{1,3}', url):
        score += 30

    # Too many subdomains
    if parsed.netloc.count('.') > 3:
        score += 20

    # Too many hyphens
    if url.count('-') > 3:
        score += 15

    # Suspicious keywords (each adds points)
    keyword_hits = 0
    for word in suspicious_keywords:
        if word in url.lower():
            keyword_hits += 1
    score += keyword_hits * 10

    # Suspicious TLD
    for tld in suspicious_tlds:
        if parsed.netloc.endswith(tld):
            score += 20
            break

    # No HTTPS
    if not url.startswith("https"):
        score += 15

    return score


# ---------------- DOMAIN AGE CHECK ----------------

def domain_age_check(domain):

    try:
        info = whois.whois(domain)
        creation_date = info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            age = (datetime.now() - creation_date).days

            if age < 30:
                return 25  # Very new domain
            elif age < 180:
                return 10  # Relatively new

    except:
        pass

    return 0


# ---------------- ROOT DOMAIN ----------------

def get_root_domain(domain):

    parts = domain.split('.')

    # Handle two-part TLDs like .co.in, .co.uk, .com.au
    two_part_tlds = ["co.in", "co.uk", "com.au", "co.jp", "org.in", "ac.in"]

    if len(parts) >= 3:
        last_two = ".".join(parts[-2:])
        if last_two in two_part_tlds:
            return ".".join(parts[-3:])

    if len(parts) >= 2:
        return ".".join(parts[-2:])

    return domain


# ---------------- HYPERLINK ANALYSIS ----------------

def analyze_hyperlinks(html, base_url):

    soup = BeautifulSoup(html, "html.parser")

    links = [a.get("href") for a in soup.find_all("a") if a.get("href")]

    internal = 0
    external = 0
    suspicious_links = 0

    base_parsed = urlparse(base_url)
    base_root = get_root_domain(base_parsed.netloc)

    for link in links:

        # Suspicious hyperlinks
        if link.startswith("javascript") or link.startswith("#"):
            suspicious_links += 1

        parsed = urlparse(link)

        if parsed.netloc == "":
            internal += 1
            continue

        link_root = get_root_domain(parsed.netloc)

        if link_root == base_root:
            internal += 1
        else:
            external += 1

    return internal, external, suspicious_links


# ---------------- FORM DETECTION ----------------

def detect_login_form(html):

    soup = BeautifulSoup(html,"html.parser")

    password_inputs = soup.find_all("input", {"type":"password"})

    if len(password_inputs) > 0:
        return True

    return False


# ---------------- MAIN DETECTION (SCORING) ----------------

# Score Thresholds:
#   0  - 20  → SAFE
#   21+      → SUSPICIOUS

def detect_url(url):

    if not url.startswith(("http://","https://")):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.netloc

    score = 0

    # URL rule scoring
    score += url_risk_score(url)

    # Domain age scoring
    score += domain_age_check(domain)

    options = Options()
    options.add_argument("--headless")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")

    driver = webdriver.Chrome(options=options)

    try:

        driver.get(url)

        html = driver.page_source

        # Redirect detection
        if len(driver.window_handles) > 1:
            score += 25

        internal, external, suspicious = analyze_hyperlinks(html, url)

        total = internal + external

        # Hyperlink scoring
        if total > 0:
            if external > internal * 2:
                score += 20
            if internal < total * 0.1:
                score += 15

        # Suspicious link scoring
        if suspicious > 10:
            score += 20
        elif suspicious > 5:
            score += 10

        # Login form scoring
        if detect_login_form(html):
            score += 15

        # Final verdict
        print(f"[DEBUG] URL: {url} | Score: {score}")

        if score >= 21:
            return "SUSPICIOUS"
        else:
            return "SAFE"

    except Exception as e:

        print("Error:", e)

        return "SUSPICIOUS"

    finally:

        driver.quit()


# ---------------- ROUTES ----------------

@app.route("/", methods=["GET","POST"])

def home():

    result = None

    if request.method == "POST":

        url = request.form["url"]

        result = detect_url(url)

    return render_template("index.html", result=result)


if __name__ == "__main__":

    app.run(debug=True)
