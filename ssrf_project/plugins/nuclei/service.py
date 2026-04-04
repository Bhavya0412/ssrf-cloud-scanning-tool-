from flask import Flask, request, jsonify
import subprocess, tempfile, os, json

app = Flask(__name__)
TEMPLATES_DIR = os.environ.get("TEMPLATES_DIR", "/templates")

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
        targets_file = tf.name
    out_file = tempfile.mktemp(suffix=".jsonl")
    cmd = ["nuclei", "-l", targets_file, "-jsonl", "-o", out_file, "-silent"]
    if os.path.isdir(TEMPLATES_DIR) and os.listdir(TEMPLATES_DIR):
        cmd += ["-t", TEMPLATES_DIR]
    else:
        cmd += ["-tags", "ssrf"]
    try:
        subprocess.run(cmd, timeout=300, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.TimeoutExpired:
        return jsonify({"error": "nuclei timed out"}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        os.unlink(targets_file)
    findings = []
    if os.path.exists(out_file):
        with open(out_file, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line: continue
                try: findings.append(json.loads(line))
                except: pass
        os.unlink(out_file)
    return jsonify({"findings": findings})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
