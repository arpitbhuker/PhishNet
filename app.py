# app.py
import streamlit as st
from phishnet_core import analyze_url
import pandas as pd

st.set_page_config(page_title="PhishNet", page_icon="🔒", layout="centered")
st.title("🔒 PhishNet — Suspicious Link Analyzer")

st.write("Enter a URL below and PhishNet will analyze it for common phishing signals (WHOIS, SSL, URL structure, content).")

url_input = st.text_input("URL", placeholder="https://example.com/login")

if st.button("Analyze") and url_input:
    with st.spinner("Analyzing..."):
        result = analyze_url(url_input.strip())
    st.subheader("Result")
    st.metric("Risk score", f"{result.get('risk_score')} / 100", delta=None)
    st.markdown(f"**Label:** {result.get('label')}")
    if result.get("error"):
        st.error(result.get("error"))

    st.write("### Key features")
    # show certain fields in a table
    features = {
        "Is valid URL": result.get("is_valid_url"),
        "HTTPS": result.get("https"),
        "Uses IP": result.get("uses_ip"),
        "Domain age (days)": result.get("domain_age_days"),
        "Redirects": result.get("redirects_count"),
        "Forms on page": result.get("forms"),
        "External favicon": result.get("external_favicon"),
        "SSL valid": result.get("ssl_valid")
    }
    df = pd.DataFrame(list(features.items()), columns=["Feature", "Value"])
    st.table(df)

    if result.get("reasons"):
        st.write("### Why this score?")
        for r in result["reasons"]:
            st.write("- " + r)

    st.write("### Full JSON output")
    st.json(result)

