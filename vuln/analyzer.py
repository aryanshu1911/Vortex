import json

def load_rules(json_file="vuln/rules.json"):
    with open(json_file, "r") as f:
        return json.load(f)

def analyze(ip, open_ports, banners, rules_file="vuln/rules.json"):
    rules = load_rules(rules_file)
    findings = []

    for port in open_ports:
        banner = banners.get(port, "")
        for rule in rules:
            if port == rule.get("port"):
                if "banner_contains" in rule:
                    if banner and rule["banner_contains"] in banner:
                        findings.append({
                            "ip": ip,
                            "port": port,
                            "issue": rule["message"],
                            "severity": rule["severity"]
                        })
                else:
                    findings.append({
                        "ip": ip,
                        "port": port,
                        "issue": rule["message"],
                        "severity": rule["severity"]
                    })
    return findings