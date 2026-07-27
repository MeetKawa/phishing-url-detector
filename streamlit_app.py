import streamlit as st
import re
from urllib.parse import urlparse

# ---------------- PAGE SETTINGS ---------------- #

st.set_page_config(
    page_title="AI Phishing URL Detector",
    page_icon="🔒",
    layout="centered"
)

# ---------------- CUSTOM CSS ---------------- #

st.markdown("""
<style>

.main{
    background-color:#f5f7fa;
}

.title{
    text-align:center;
    font-size:40px;
    font-weight:bold;
    color:#1f2937;
}

.subtitle{
    text-align:center;
    color:gray;
    margin-bottom:20px;
}

.footer{
    text-align:center;
    color:gray;
    margin-top:60px;
}

.safe{
    background:#d4edda;
    color:#155724;
    padding:18px;
    border-radius:10px;
    text-align:center;
    font-size:28px;
    font-weight:bold;
}

.warning{
    background:#fff3cd;
    color:#856404;
    padding:18px;
    border-radius:10px;
    text-align:center;
    font-size:28px;
    font-weight:bold;
}

.danger{
    background:#f8d7da;
    color:#721c24;
    padding:18px;
    border-radius:10px;
    text-align:center;
    font-size:28px;
    font-weight:bold;
}

</style>
""", unsafe_allow_html=True)

# ---------------- TITLE ---------------- #

st.markdown(
    "<div class='title'>🔒 AI Phishing URL Detector</div>",
    unsafe_allow_html=True
)

st.markdown(
    "<div class='subtitle'>Detect whether a URL is Safe or Phishing using intelligent URL analysis.</div>",
    unsafe_allow_html=True
)

# ---------------- INPUT ---------------- #

url = st.text_input("Paste URL")

# ---------------- URL ANALYSIS ---------------- #

def analyze_url(url):

    score = 50
    reasons = []

    # HTTPS
    if url.startswith("https://"):
        score += 20
    else:
        score -= 20
        reasons.append("URL does not use HTTPS")

    # Length
    if len(url) > 75:
        score -= 15
        reasons.append("URL is unusually long")

    # Dots
    if url.count(".") > 3:
        score -= 10
        reasons.append("Too many dots")

    # Numbers
    digits = sum(c.isdigit() for c in url)
    if digits > 5:
        score -= 10
        reasons.append("Contains many numbers")

    # Hyphens
    if url.count("-") > 3:
        score -= 10
        reasons.append("Too many hyphens")

    # @
    if "@" in url:
        score -= 20
        reasons.append("@ symbol detected")

    # IP Address
    if re.search(r"(\\d{1,3}\\.){3}\\d{1,3}", url):
        score -= 20
        reasons.append("IP Address detected")

    # Suspicious Words
    keywords = [
        "login",
        "verify",
        "secure",
        "update",
        "bank",
        "signin",
        "password",
        "account"
    ]

    for word in keywords:
        if word in url.lower():
            score -= 10
            reasons.append(f"Suspicious keyword: {word}")

    # Domain Exists
    domain = urlparse(url).netloc

    if domain:
        score += 5

    score = max(0, min(score,100))

    return score,reasons

# ---------------- BUTTON ---------------- #

if st.button("🔍 Analyze URL"):

    if url.strip()=="":

        st.warning("Please enter a URL.")

    else:

        score,reasons = analyze_url(url)

        if score>=70:

            st.markdown(
                "<div class='safe'>🟢 SAFE</div>",
                unsafe_allow_html=True
            )

        elif score>=40:

            st.markdown(
                "<div class='warning'>🟠 SUSPICIOUS</div>",
                unsafe_allow_html=True
            )

        else:

            st.markdown(
                "<div class='danger'>🔴 PHISHING</div>",
                unsafe_allow_html=True
            )

        st.write("## Risk Score")

        st.progress(score/100)

        st.metric("Overall Score",f"{score}%")

        st.write("## Analysis Report")

        if reasons:

            for r in reasons:

                st.write("•",r)

        else:

            st.success("No suspicious indicators found.")

# ---------------- FOOTER ---------------- #

st.markdown("---")

st.markdown("""
<div class="footer">

### AI Based Phishing URL Detector

Developed by **Meet & Tanvi**

</div>
""",unsafe_allow_html=True)