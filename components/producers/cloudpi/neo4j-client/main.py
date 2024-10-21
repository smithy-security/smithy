from reachability import assessor
from trivy import run


def main():
    snaps = assessor.get_snapshosts_exposed()
    print(snaps)
    for snap in snaps:
        print(f"running scan on snap {snap}")
        vuln = run.scan_ebs(snap["snapshot_id"])
        print(vuln)

if __name__ == '__main__':
    main()