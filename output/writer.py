import json

def save_json_report(report, filename):
    """
    Save JSON report with open_ports inline
    """
    def custom_encoder(obj, level=0):
        indent = '    ' * level
        if isinstance(obj, dict):
            lines = []
            for k, v in obj.items():
                lines.append(f'{indent}    "{k}": {custom_encoder(v, level+1)}')
            return "{\n" + ",\n".join(lines) + f"\n{indent}}}"
        elif isinstance(obj, list):
            # Inline small lists
            if all(isinstance(i, (int, str)) for i in obj) and len(obj) <= 5:
                return "[" + ", ".join(map(str, obj)) + "]"
            else:
                lines = [f'{indent}    {custom_encoder(i, level+1)}' for i in obj]
                return "[\n" + ",\n".join(lines) + f"\n{indent}]"
        elif isinstance(obj, str):
            return json.dumps(obj, ensure_ascii=False)
        else:
            return str(obj)

    with open(filename, "w", encoding="utf-8") as f:
        f.write(custom_encoder(report))

def save_txt_report(report, filename):
    with open(filename, "w", encoding="utf-8") as f:
        for host in report["results"]:
            f.write(f"Host: {host['scan_target']}\n")
            f.write(f"Open Ports: {', '.join(map(str, host['open_ports']))}\n")
            f.write("Banners:\n")
            for port, banner in host['banners'].items():
                f.write(f"  {port}: {banner}\n")
            f.write("Findings:\n")
            for fnd in host['findings']:
                f.write(f"  {fnd['ip']}:{fnd['port']} → {fnd['issue']} ({fnd['severity']})\n")
            f.write("\n")