import json
import random

OUTPUT_FILE = "ssrf_llm_dataset.jsonl"
NUM_SAMPLES = 350  # change to 500 if you want even more

methods = ["GET", "POST", "PUT", "DELETE"]
paths_vuln = ["/proxy", "/image-proxy", "/fetch", "/download", "/convert", "/api/request"]
paths_safe = ["/static/logo.png", "/css/main.css", "/health", "/status", "/home"]
internal_keywords = ["admin", "internal", "metadata", "k8s", "db", "config", "vault"]
metadata_hosts = [
    "http://169.254.169.254/latest/meta-data",
    "http://169.254.169.254/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
]
public_domains = [
    "https://google.com",
    "https://openai.com",
    "https://github.com",
    "https://example.com",
    "https://wikipedia.org",
]

def random_bool():
    return random.choice([0, 1])

def make_vulnerable_example():
    method = random.choice(methods)
    path = random.choice(paths_vuln)

    # Force a risky combination
    user_url = 1
    ip_literal = 1
    internal_kw = random.choice([0, 1])

    # Sometimes mention explicit target
    target = random.choice(
        ["127.0.0.1", "10.0.0.5", "192.168.1.10", "0.0.0.0"]
        + [h for h in metadata_hosts]
    )

    input_desc = (
        f"method={method}\n"
        f"path={path}\n"
        f"user_supplied_url={user_url}\n"
        f"contains_ip_literal={ip_literal}\n"
        f"contains_internal_keyword={internal_kw}\n"
        f"example_target={target}\n"
    )

    instruction = "Analyze this HTTP endpoint and decide if it is vulnerable to SSRF. Explain briefly."
    output = (
        "VULNERABLE: The endpoint accepts a user-controlled URL parameter and can reach internal or metadata "
        "endpoints (e.g. private IPs or cloud metadata). The backend server can be tricked into making internal "
        "requests on behalf of the attacker."
    )

    return {"instruction": instruction, "input": input_desc, "output": output}

def make_safe_example():
    method = random.choice(methods)
    path = random.choice(paths_safe)

    user_url = 0
    ip_literal = 0
    internal_kw = 0

    input_desc = (
        f"method={method}\n"
        f"path={path}\n"
        f"user_supplied_url={user_url}\n"
        f"contains_ip_literal={ip_literal}\n"
        f"contains_internal_keyword={internal_kw}\n"
        f"example_target=static_resource\n"
    )

    instruction = "Analyze this HTTP endpoint and decide if it is vulnerable to SSRF. Explain briefly."
    output = (
        "SAFE: The endpoint does not take a user-controlled URL and only serves static or internal application "
        "resources. There is no way for the attacker to force the server to fetch arbitrary external URLs."
    )

    return {"instruction": instruction, "input": input_desc, "output": output}

def make_explanation_example():
    q = random.choice([
        "What is SSRF?",
        "Why is SSRF dangerous?",
        "How does an SSRF attack usually work?",
        "How can a developer prevent SSRF?",
    ])

    if "prevent" in q.lower():
        a = (
            "To prevent SSRF, validate and restrict outgoing URLs using an allowlist of trusted domains, reject "
            "private IP ranges, disallow dangerous schemes like gopher/file, block access to cloud metadata "
            "IPs, and avoid directly proxying user-supplied URLs."
        )
    elif "dangerous" in q.lower():
        a = (
            "SSRF is dangerous because the attacker abuses the server's network position to access internal "
            "services, cloud metadata, or perform port scans that are not reachable from the public internet."
        )
    elif "how does" in q.lower():
        a = (
            "In a typical SSRF attack, the application offers a feature like URL fetching, image loading, or a "
            "proxy endpoint. The attacker supplies a crafted URL that points to internal or sensitive targets, "
            "and the backend server performs the request, leaking data or exposing services."
        )
    else:
        a = (
            "SSRF (Server-Side Request Forgery) is a vulnerability where an attacker tricks the server into "
            "making HTTP or network requests to arbitrary URLs, often including internal or metadata endpoints."
        )

    return {"instruction": q, "input": "", "output": a}

def make_payload_example():
    instruction = "Suggest some SSRF payloads that can be used to probe internal services and metadata endpoints."
    base = random.choice([
        "/proxy?url=",
        "/fetch?target=",
        "/image-proxy?url=",
        "/convert?source=",
    ])
    input_desc = f"Base vulnerable endpoint pattern: {base}<user_input>"

    output = (
        "Example SSRF payloads:\n"
        "- http://127.0.0.1:80/\n"
        "- http://127.0.0.1:22/\n"
        "- http://169.254.169.254/latest/meta-data/\n"
        "- http://10.0.0.1:8080/admin\n"
        "- gopher://127.0.0.1:6379/_info\n"
        "- http://metadata.google.internal/computeMetadata/v1/\n"
    )

    return {"instruction": instruction, "input": input_desc, "output": output}

generators = [make_vulnerable_example, make_safe_example, make_explanation_example, make_payload_example]
weights = [0.5, 0.3, 0.15, 0.05]  # mostly classify (vuln/safe)

def pick_generator():
    r = random.random()
    total = 0.0
    for gen, w in zip(generators, weights):
        total += w
        if r <= total:
            return gen
    return generators[0]

def main():
    random.seed(42)
    count = 0
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for _ in range(NUM_SAMPLES):
            gen = pick_generator()
            ex = gen()
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")
            count += 1
    print(f"Wrote {count} examples to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
