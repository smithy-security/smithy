import json
import subprocess
import os

def scan_ebs(snap_name):
    try:
        # Run Trivy scan command for the specified ebs
        # trivy vm --scanners vuln ebs:snap-02f3d4e008898f8d0 --aws-region eu-west-1
        result = subprocess.run(
            ['trivy', 'vm', '--scanners', 'vuln', '--format', 'json', '--severity', os.GetEnv("SEVERITY"), f"ebs:{snap_name}"],
            capture_output=True,
            text=True,
            check=True
        )
        
        # Parse the JSON output
        vulnerabilities = json.loads(result.stdout)
        return vulnerabilities
        
    except subprocess.CalledProcessError as e:
        print(f"Error scanning ebs {snap_name}: {e.stderr}")
        return None
