import json
import os
import urllib.request

def load_trivy_results():
    try:
        with open('trivy-results.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {"Results": []}

def extract_findings(trivy_data):
    findings = []
    results = trivy_data.get('Results', [])
    
    for result in results:
        vulnerabilities = result.get('Vulnerabilities', [])
        for vuln in vulnerabilities[:5]:
            findings.append({
                'id': vuln.get('VulnerabilityID', 'Unknown'),
                'package': vuln.get('PkgName', 'Unknown'),
                'severity': vuln.get('Severity', 'Unknown'),
                'description': vuln.get('Description', 'No description')[:200],
                'fixed_version': vuln.get('FixedVersion', 'No fix available')
            })
    return findings

def generate_ai_report(findings):
    if not findings:
        return "No vulnerabilities found in this scan."

    api_key = os.environ.get('GEMINI_API_KEY')
    findings_text = json.dumps(findings, indent=2)

    prompt = f"""You are a security engineer reviewing vulnerability scan results.

Here are the findings from a Trivy scan of a Python Flask application:

{findings_text}

For each finding provide:
1. What the vulnerability means in plain English
2. The actual risk to this application
3. Exactly how to fix it

Keep each explanation concise and actionable. Format as markdown."""

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={api_key}"
    
    payload = json.dumps({
        "contents": [{
            "parts": [{"text": prompt}]
        }]
    }).encode('utf-8')

    req = urllib.request.Request(
        url,
        data=payload,
        headers={'Content-Type': 'application/json'},
        method='POST'
    )

    with urllib.request.urlopen(req) as response:
        result = json.loads(response.read().decode('utf-8'))
        return result['candidates'][0]['content']['parts'][0]['text']

def main():
    print("Loading Trivy scan results...")
    trivy_data = load_trivy_results()
    
    print("Extracting findings...")
    findings = extract_findings(trivy_data)
    
    print(f"Found {len(findings)} vulnerabilities. Generating AI report...")
    report = generate_ai_report(findings)
    
    with open('ai_report.md', 'w') as f:
        f.write("# AI Security Report\n\n")
        f.write(f"**Vulnerabilities analysed:** {len(findings)}\n\n")
        f.write("---\n\n")
        f.write(report)
    
    print("AI report saved to ai_report.md")
    print("\n--- REPORT PREVIEW ---")
    print(report[:500])

if __name__ == '__main__':
    main()