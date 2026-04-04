from flask import Flask, request, jsonify
import subprocess, tempfile, os, json

app = Flask(__name__)

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})

@app.route("/scan", methods=["POST"])
def scan():
    data = request.json or {}
    targets = data.get("targets", [])
    if not targets:
        return jsonify({"error": "no targets"}), 400

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
        tf.write("\n".join(targets))
        req_file = tf.name

    out_file = tempfile.mktemp(suffix=".txt")

    try:
        result = subprocess.run(
            ["python3", "/ssrfmap/ssrfmap.py", "-r", req_file, "-p", "url", "-m", "readfiles,portscan"],
            capture_output=True, text=True, timeout=120
        )
        output = result.stdout + result.stderr
    except Exception as e:
        output = str(e)
    finally:
        os.unlink(req_file)

    findings = []
    for line in output.splitlines():
        low = line.lower()
        if any(k in low for k in ("ssrf", "169.254", "metadata", "found", "vulnerable")):
            sev = "high" if ("169.254" in low or "metadata" in low) else "medium"
            findings.append({"tool": "ssrfmap", "line": line, "severity": sev})

    return jsonify({"findings": findings, "raw_output": output})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8081)
