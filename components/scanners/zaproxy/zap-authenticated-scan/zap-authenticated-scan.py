#!/usr/bin/env python
import json
import yaml
import sys
import signal
import re
import subprocess
import argparse
import os
import time
import requests

from datetime import datetime, timedelta
from time import sleep
from urllib.parse import quote, urlparse

from zapv2 import ZAPv2


plan_template = """
{
    "env": {
        "contexts": [
            {
                "name": "Default Context",
                "urls": [
                    "${zap_target}"
                ],
                "includePaths": [
                    "*.${zap_target}.*"
                ],
                "authentication": {
                    "method": "browser",
                    "parameters": {
                        "browserId": "firefox-headless",
                        "loginPageUrl": "${zap_login_path}",
                        "loginPageWait": 5
                    },
                    "verification": {
                        "method": "autodetect"
                    }
                },
                "sessionManagement": {
                    "method": "autodetect"
                },
                "technology": {},
                "users": [
                    {
                        "name": "test-user",
                        "credentials": {
                            "username": "${zap_username}",
                            "password": "${zap_password}"
                        }
                    }
                ]
            }
        ],
        "parameters": {}
    },
    "jobs": [
        {
            "type": "activeScan-config",
            "rules": []
        },
        {
            "type": "passiveScan-config",
            "rules": []
        },
        {
            "parameters": {},
            "name": "spider",
            "type": "spider"
        },
        {
            "parameters": {
                "maxDuration": 5,
                "maxCrawlDepth": 10,
                "runOnlyIfModern": true,
                "inScopeOnly": true
            },
            "name": "spiderAjax",
            "type": "spiderAjax"
        },
        {
            "type": "requestor",
            "parameters": {
                "user": "test-user"
            },
            "requests": [
                {
                    "url": "${zap_target}"
                }
            ]
        },
         {
            "name": "activeScan",
            "type": "activeScan",
            "parameters": {
                "maxScanDurationInMins": 10
            }
        },
        {
            "type": "passiveScan-wait",
            "parameters": {},
            "name": "passiveScan-wait"
        },
        {
            "name": "${zap_report_name}",
            "type": "report",
            "parameters": {
                "template": "sarif-json",
                "theme": null,
                "reportDir": "${zap_report_dir}",
                "reportFile": "${zap_report_file}",
                "reportTitle": "${zap_report_title}"
            }
        }
    ]
}
"""

baseline_plan_template = """
{
  "env": {
    "contexts": [
      {
        "name": "Smithy Baseline Context",
        "urls": [
          "${zap_target}"
        ],
        "includePaths": [],
        "excludePaths": []
      }
    ],
    "parameters": {
      "failOnError": true,
      "failOnWarning": false,
      "progressToStdout": true
    },
    "vars": {}
  },
  "jobs": [
    {
      "parameters": {
        "scanOnlyInScope": true,
        "enableTags": false
      },
      "rules": [],
      "name": "passiveScan-config",
      "type": "passiveScan-config"
    },
    {
      "parameters": {
        "maxDuration": "${zap_spider_duration_mins}"
      },
      "name": "spider",
      "type": "spider"
    },
    {
      "parameters": {},
      "name": "passiveScan-wait-pre-ajax",
      "type": "passiveScan-wait"
    },
    {
      "parameters": {
        "maxDuration": "${zap_spider_duration_mins}",
        "runOnlyIfModern": true,
        "inScopeOnly": true
      },
      "name": "spiderAjax",
      "type": "spiderAjax"
    },
    {
      "parameters": {
        "maxScanDurationInMins": "${zap_active_scan_duration_mins}"
      },
      "policyDefinition": {},
      "name": "activeScan",
      "type": "activeScan"
    },
    {
      "parameters": {},
      "name": "passiveScan-wait-pre-report",
      "type": "passiveScan-wait"
    },
    {
            "name": "${zap_report_name}",
            "type": "report",
            "parameters": {
                "template": "sarif-json",
                "theme": null,
                "reportDir": "${zap_report_dir}",
                "reportFile": "${zap_report_file}",
                "reportTitle": "${zap_report_title}"
            }
        }
  ]
}
"""


class ZapInvalidTargetError(Exception):
    """Custom exception for invalid target URLs."""

    def __init__(self, target, message="Invalid target URL provided"):
        self.message = f"{message}: '{target}'"
        super().__init__(self.message)


class ZapInvalidAPIKeyError(Exception):
    """Custom exception for invalid api keys."""

    def __init__(self, api_key, message="Invalid api key provided"):
        self.message = f"{message}: '{api_key}'"
        super().__init__(self.message)


class ZapRunner:
    context_id: int = 1
    context_name: str = "Default Context"
    zap: ZAPv2
    zap_api_url: str
    zap_process: None

    def __init__(
        self: "ZapRunner",
        api_key: str,
        target_url: str,
        host: str = "localhost",
        port: int = 8090,
    ) -> None:
        if not target_url:
            raise ZapInvalidAPIKeyError(target="no target provided")

        parsed = urlparse(target_url)
        if not parsed.scheme and not parsed.netloc:
            raise ZapInvalidTargetError(target=target_url)

        print(f"zap target {target_url}, recorded")

        if not api_key:
            raise ZapInvalidAPIKeyError(api_key=api_key)
        self.api_key = api_key
        self.target_url = target_url
        self.host = host
        self.port = port
        self.zap_api_url = f"http://{host}:{port}"
        self.request_proxies = {"http": self.zap_api_url, "https": self.zap_api_url}
        self.zap = ZAPv2(apikey=api_key, proxies=self.request_proxies)

    def start_zap(
        self: "ZapRunner",
        wait: bool = True,
        interval: timedelta = timedelta(seconds=10),
        max_retries: int = 5,
    ) -> None:
        print(f"initializing zap, listening on {self.host}:{self.port}")
        self.zap_process = subprocess.Popen(
            [
                "/zap/zap.sh",
                "-daemon",
                "-silent",
                "-notel",
                "-config",
                f"api.key={self.api_key}",
                "-host",
                self.host,
                "-port",
                str(self.port),
            ],
            stdout=sys.stdout,
            stderr=sys.stderr,
        )
        print("zap subprocess started")

        if not wait:
            return

        for i in range(max_retries, -1, -1):
            try:
                self.check_connection()
                print("connection to ZAP daemon established")
            except Exception as e:
                print(f"there was an issue connecting to Zap: {e}")
                if i == 0:
                    print(
                        "not waiting any more for zap subprocess to finish bootstraping"
                    )
                    raise e

                exit_code = self.zap_process.poll()
                if exit_code:
                    print(f"zap subprocess exited with exit code: {exit_code}")
                    raise e

                print(
                    f"sleeping {interval.seconds}s until next retry, retries left: {i-1}/{max_retries}"
                )
                sleep(interval.seconds)

    def stop_zap(self: "ZapRunner") -> int:
        print(
            f"shutting down zap, {self.zap.core.shutdown(apikey=self.api_key)}"
        )  # stop zap
        self.zap_process.terminate()
        return self.zap_process.wait(timeout=10)

    def check_connection(self: "ZapRunner") -> None:
        version = self.zap.core.version

        if not version:
            raise RuntimeError(f"could not connect to remote zap at {self.zap_api_url}")
        print(f"connected to remote zap version {version}")

    def create_context(self: "ZapRunner") -> None:
        self.context_id = self.zap.context.new_context(self.context_name)
        if self.context_id == "already_exists":
            ctx = self.zap.context.context(self.context_name)
            self.context_id = ctx["id"]
        print(f"context is {self.zap.context.context(self.context_name)}")

    def run_automation_framework_scan(
        self: "ZapRunner",
        login_url: str = None,
        username: str = None,
        password: str = None,
        filename: str = "zap-report.json",
        report_name: str = "Smithy Zap Report",
        report_title: str = "Smithy Zap Report",
        report_dir: str = None,
        plan: str = None,
        scan_duration: int = 10,
        spider_duration: int = 5,
    ):
        automation_framework_script = json.loads(plan)
        for context in automation_framework_script["env"]["contexts"]:
            print(f"setting zap target for context {context['name']}")
            context["urls"] = [self.target_url]
            urlparsed = urlparse(self.target_url)
            without_scheme = re.escape(
                f"{urlparsed.netloc}{urlparsed.path.rstrip('/')}"
            )
            include_url = f".*{without_scheme}.*"

            context["includePaths"] = [f"{include_url}"]
            print(f"Configured include paths {context['includePaths']}")
            context["excludePaths"] = [f"^((?!{without_scheme}).)*$"]
            print(f"Configured exclude paths {context['excludePaths']}")

            if login_url and username and password:
                print(
                    f"setting authentication for context {context['name']} to login_url: {login_url}, username: {username}"
                )
                context["authentication"]["method"] = "browser"
                context["authentication"]["parameters"]["loginPageUrl"] = login_url
                for user in context["users"]:
                    user["credentials"]["username"] = username
                    user["credentials"]["password"] = password
        for job in automation_framework_script["jobs"]:
            if job["type"] == "requestor":
                for req in job["requests"]:
                    req["url"] = self.target_url
            elif job["type"] == "activeScan":
                if "parameters" not in job:
                    job["parameters"] = {}
                job["parameters"]["maxScanDurationInMins"] = scan_duration
            elif job["type"] == "spider":
                if "parameters" not in job:
                    job["parameters"] = {}
                job["parameters"]["maxDuration"] = spider_duration
            elif job["type"] == "spiderAjax":
                if "parameters" not in job:
                    job["parameters"] = {}
                job["parameters"]["maxDuration"] = spider_duration
            elif job["type"] == "report":
                job["name"] = report_name
                job["parameters"]["reportDir"] = report_dir
                job["parameters"]["reportFile"] = filename
                job["parameters"]["reportTitle"] = report_title

        with open("/tmp/zap_auth_automation.yaml", "w") as f:
            f.write("\n---\n")
            f.write(yaml.safe_dump(automation_framework_script, sort_keys=False))
            f.close()
        print(
            "running automation framework scipt located at /tmp/zap_auth_automation.yaml"
        )
        planID = self.zap.automation.run_plan("/tmp/zap_auth_automation.yaml")
        progress = self.zap.automation.plan_progress(planid=planID)
        while not progress["error"] and not progress["finished"]:
            progress = self.zap.automation.plan_progress(planid=planID)
            time.sleep(5)
            print(f"plan progress {progress}  {progress['info']}")
        if progress["finished"]:
            print(f"plan completed successfully at {progress['finished']}")
        if progress["error"]:
            print(f"plan had errors, check progress for hints")


def get_env_or_default(value, env_key, default=""):
    return value if value else os.getenv(env_key, default)


def main():
    parser = argparse.ArgumentParser(description="Parse input parameters")
    parser.add_argument(
        "--login-url",
        default=get_env_or_default("", "LOGIN_URL"),
        type=str,
        help="login url",
    )
    parser.add_argument(
        "--logout-url",
        default=get_env_or_default("", "LOGOUT_URL"),
        type=str,
        help="logout url",
    )
    parser.add_argument(
        "--username",
        default=get_env_or_default("", "USERNAME"),
        type=str,
        help="Username",
    )
    parser.add_argument(
        "--password",
        default=get_env_or_default("", "PASSWORD"),
        type=str,
        help="Password",
    )
    parser.add_argument(
        "--target",
        type=str,
        default=get_env_or_default("", "TARGET"),
        help="Target URL or address",
    )
    parser.add_argument(
        "--sub-targets",
        default=get_env_or_default("", "SUB_TARGETS"),
        type=str,
        help="Comma-separated list of sub-targets",
    )
    parser.add_argument(
        "--api-key",
        default=get_env_or_default("", "API_KEY"),
        type=str,
        help="Comma-separated list of sub-targets",
    )
    parser.add_argument(
        "--report-name",
        default=get_env_or_default("zap-report.json", "REPORT_FILENAME"),
        type=str,
        help="report filename",
    )
    parser.add_argument(
        "--report-dir",
        default=get_env_or_default("", "REPORT_DIR"),
        type=str,
        help="where to put the report",
    )
    parser.add_argument(
        "--max-scan-duration",
        default=get_env_or_default("", "SCAN_DURATION_MINS"),
        type=str,
        help="where to put the report",
    )
    parser.add_argument(
        "--max-spider-duration",
        default=get_env_or_default("", "SPIDER_DURATION_MINS"),
        type=str,
        help="where to put the report",
    )
    parser.add_argument(
        "--no-start-zap",
        default=False,
        action="store_true",
        help="(for local dev, do not attempt to start zap)",
    )
    parser.add_argument(
        "--startup-check-retries",
        default=get_env_or_default("", "STARTUP_CHECK_RETRIES", default=3),
        type=int,
        help="how many times to check if ZAP has started before leaving",
    )
    parser.add_argument(
        "--startup-check-interval",
        default=get_env_or_default("", "STARTUP_CHECK_INTERVAL", default=10),
        type=int,
        help="how many seconds to wait before successive ZAP liveness checks",
    )
    args = parser.parse_args()

    target_url = args.target.strip("/")
    print(f"starting zap scanning target: {target_url}")
    runner = ZapRunner(api_key=args.api_key, target_url=target_url)
    if not args.no_start_zap:
        runner.start_zap(
            max_retries=args.startup_check_retries,
            interval=timedelta(seconds=args.startup_check_interval),
        )

    runner.create_context()
    max_scan_duration = 10  # default
    if args.max_scan_duration and str(args.max_scan_duration).isdecimal():
        max_scan_duration = int(args.max_scan_duration)
    else:
        print(
            f"max scan duration had unsupported value '{args.max_scan_duration}' setting to default '{max_scan_duration}'"
        )

    max_spider_duration = 5  # default
    if args.max_spider_duration and str(args.max_spider_duration).isdecimal():
        max_spider_duration = int(args.max_spider_duration)
    else:
        print(
            f"max spider duration had unsupported value '{args.max_spider_duration}' setting to default '{max_spider_duration}'"
        )

    try:
        if args.username and args.password:
            print("running automation framework scan")
            return runner.run_automation_framework_scan(
                login_url=args.login_url,
                username=args.username,
                password=args.password,
                report_dir=args.report_dir,
                plan=plan_template,
            )
        print("running baseline scan using the the automation framework")
        return runner.run_automation_framework_scan(
            report_dir=args.report_dir,
            plan=baseline_plan_template,
            scan_duration=max_scan_duration,
            spider_duration=max_spider_duration,
        )
    finally:
        runner.stop_zap()


if __name__ == "__main__":
    main()
