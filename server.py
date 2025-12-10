# server.py
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from phishnet_core import analyze_url

app = Flask(__name__, static_folder="static", template_folder="templates")
CORS(app)  # allow requests from extension or localhost

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data = request.get_json() or {}
    url = data.get("url") or ""
    result = analyze_url(url)
    return jsonify(result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

