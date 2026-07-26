from flask import Flask, render_template, request
import re
from urllib.parse import urlparse

app = Flask(__name__)

def analyze_url(url):

    score = 0
    reasons = []

    # HTTPS Check
    if url.startswith("https://"):
        score += 20
    else:
        reasons.append("URL is not using HTTPS")

    # URL Length
    if len(url) > 75:
        score -= 15
        reasons.append("Very long URL")
    else:
        score += 10

    # Number of dots
    dots = url.count(".")
    if dots > 3:
        score -= 15
        reasons.append("Too many dots")

    # Digits
    digits = sum(c.isdigit() for c in url)
    if digits > 5:
        score -= 10
        reasons.append("Contains many numbers")

    # @ Symbol
    if "@" in url:
        score -= 20
        reasons.append("@ symbol found")

    # Hyphens
    if url.count("-") > 3:
        score -= 10
        reasons.append("Too many hyphens")

    # Suspicious Keywords
    suspicious = [
        "login",
        "verify",
        "update",
        "secure",
        "bank",
        "account",
        "signin",
        "password"
    ]

    for word in suspicious:
        if word in url.lower():
            score -= 10
            reasons.append(f"Suspicious keyword: {word}")

    # IP Address
    ip_pattern = r"(\d{1,3}\.){3}\d{1,3}"
    if re.search(ip_pattern, url):
        score -= 20
        reasons.append("IP address detected")

    # Domain exists
    domain = urlparse(url).netloc

    if len(domain) > 0:
        score += 10

    score = max(0, min(100, score + 50))

    if score >= 70:
        result = "✅ SAFE"
        color = "green"
    elif score >= 40:
        result = "⚠ Suspicious"
        color = "orange"
    else:
        result = "❌ PHISHING"

        color = "red"

    return result, color, score, reasons


@app.route("/", methods=["GET", "POST"])
def home():

    if request.method == "POST":

        url = request.form["url"]

        result, color, score, reasons = analyze_url(url)

        return render_template(
            "index.html",
            result=result,
            color=color,
            score=score,
            reasons=reasons
        )

    return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=True)