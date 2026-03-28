#!/usr/bin/env python3
import argparse
import json
from datetime import datetime
from statistics import mean, median
from urllib.request import Request, urlopen

BASE = "https://api.github.com/repos/wazuh/wazuh"
HEADERS = {
    "Accept": "application/vnd.github+json",
    "User-Agent": "wazuh-34915-metrics",
}


def get(url):
    req = Request(url, headers=HEADERS)
    with urlopen(req) as response:
        return json.loads(response.read().decode())


def minutes(start, end):
    if not start or not end:
        return None
    start_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
    end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))
    return round((end_dt - start_dt).total_seconds() / 60.0, 2)


def p95(values):
    ordered = sorted(values)
    if not ordered:
        return None
    index = max(0, int((0.95 * len(ordered)) + 0.999999) - 1)
    index = min(index, len(ordered) - 1)
    return ordered[index]


def collect_runs(workflow_file, limit=10, branch=None, only_success=True):
    runs = get(f"{BASE}/actions/workflows/{workflow_file}/runs?per_page=50").get("workflow_runs", [])
    output = []

    for run in runs:
        if run.get("status") != "completed":
            continue
        if only_success and run.get("conclusion") != "success":
            continue
        if branch and run.get("head_branch") != branch:
            continue

        total_min = minutes(run.get("run_started_at"), run.get("updated_at"))

        jobs = get(run["jobs_url"]).get("jobs", [])
        build_min = None
        run_test_min = None
        shard_0_min = None
        shard_1_min = None

        for job in jobs:
            job_name = (job.get("name") or "").lower()
            job_min = minutes(job.get("started_at"), job.get("completed_at"))

            if job_name == "build":
                build_min = job_min
            if job_name == "run-test":
                run_test_min = job_min
            if "tier-0" in job_name:
                shard_0_min = job_min
            if "tier-1" in job_name:
                shard_1_min = job_min

        output.append(
            {
                "id": run.get("id"),
                "event": run.get("event"),
                "branch": run.get("head_branch"),
                "conclusion": run.get("conclusion"),
                "build_min": build_min,
                "run_test_min": run_test_min,
                "shard_0_min": shard_0_min,
                "shard_1_min": shard_1_min,
                "total_min": total_min,
                "html_url": run.get("html_url"),
            }
        )

        if len(output) >= limit:
            break

    return output


def summarize(runs):
    totals = [r["total_min"] for r in runs if isinstance(r["total_min"], (int, float))]
    failures = [r for r in runs if r.get("conclusion") != "success"]

    if not totals:
        return {
            "count": 0,
            "mean": None,
            "median": None,
            "p95": None,
            "failure_rate": None,
        }

    return {
        "count": len(runs),
        "mean": round(mean(totals), 2),
        "median": round(median(totals), 2),
        "p95": p95(totals),
        "failure_rate": f"{round((len(failures) / len(runs)) * 100, 2)}%",
    }


def main():
    parser = argparse.ArgumentParser(description="Collect metrics for issue #34915")
    parser.add_argument("--workflow", required=True, help="Workflow file name")
    parser.add_argument("--limit", type=int, default=10, help="Number of runs to collect")
    parser.add_argument("--branch", default=None, help="Filter by branch name")
    parser.add_argument("--include-failures", action="store_true", help="Include failed runs")
    args = parser.parse_args()

    runs = collect_runs(
        workflow_file=args.workflow,
        limit=args.limit,
        branch=args.branch,
        only_success=not args.include_failures,
    )

    report = {
        "workflow": args.workflow,
        "branch": args.branch,
        "runs": runs,
        "summary": summarize(runs),
    }

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
