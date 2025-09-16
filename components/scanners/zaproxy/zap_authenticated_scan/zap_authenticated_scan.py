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

global_exclude_paths = [
    "^data:.*",
    ".*\\.(jpg|jpeg|png|gif|bmp|tiff|svg|webp|ico|css|js|woff|woff2|ttf|pdf|zip|mp3|mp4)(\\?.*)?$",
    ".*/images/.*",
    ".*/img/.*",
    ".*/static/.*",
    ".*/assets/.*",
    ".*/media/.*",
    ".*/cdn/.*",
    ".*base64.*",
    ".*data:image.*",
    ".*googletagmanager.*",
    ".*googlesyndication.*",
    ".*facebook\\.com.*",
    ".*twitter\\.com.*",
]

baseline_plan_template = """
{
  "env": {
    "contexts": [
      {
        "name": "Smithy Baseline Context",
        "urls": [
          "${zap_target}"
        ],
        "includePaths": [
            ".*${zap_target}.*"
        ],
        "excludePaths": ["${global_exclude_paths}"]
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
        "enableTags": false,
        "threadsPerHost": 1,
        "maxBodySizeInBytes": 33554432
      },
      "rules": [],
      "name": "passiveScan-config",
      "type": "passiveScan-config"
    },
    {
      "parameters": {
        "maxDuration": "${zap_spider_duration_mins}",
        "maxCrawlDepth": "${zap_spider_max_crawl_depth}",
        "numberOfThreads": 1,
        "maxChildren": "${zap_spider_max_children}",
        "handleParameters": "USE_ALL",
        "maxParseTimeInSecs": 15,
        "parseComments": false,
        "parseRobotsTxt": false,
        "handleODataParametersVisited": false,
        "maxParseSizeBytes": 33554432
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
        "inScopeOnly": true,
        "maxCrawlDepth": "${zap_spider_max_crawl_depth}",
        "numberOfBrowsers": 1,
        "clickDefaultElems": true,
        "clickElemsOnce": true,
        "randomInputs": false,
        "reloadWait": 1000,
        "clickElemWait": 100,
        "eventWait": 1000,
        "maxCrawlStates": 50
      },
      "name": "spiderAjax",
      "type": "spiderAjax"
    },
    {
      "parameters": {
        "maxScanDurationInMins": "${zap_active_scan_duration_mins}",
        "maxRuleDurationInMins": 1,
        "threadPerHost": 1,
        "hostPerScan": 1,
        "scanOnlyInScope": true
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
        shutdown_timeout: int = 10,
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
        self.shutdown_timeout = shutdown_timeout

    def start_zap(
        self: "ZapRunner",
        wait: bool = True,
        interval: timedelta = timedelta(seconds=10),
        max_retries: int = 5,
    ) -> None:
        print(f"initializing zap, listening on {self.host}:{self.port}")
        env = os.environ.copy()

        # Build JAVA_OPTS string with performance/memory optimizations:
        java_opts = [
            "-Xmx1536m",  # -Xmx1536m: Allows ZAP to use up to ~1.5GB RAM per thread, preventing out-of-memory errors during large scans.
            "-Xms512m",  # -Xms512m: Starts JVM with 512MB RAM, reducing time spent resizing the heap during startup.
            "-XX:MaxMetaspaceSize=256m",  # -XX:MaxMetaspaceSize=256m: Limits class metadata memory usage, preventing excessive growth.
            "-XX:+UseStringDeduplication",  # -XX:+UseStringDeduplication: Saves memory by deduplicating identical strings in the heap.
            "-XX:+UseParallelGC",  # -XX:+UseParallelGC: Enables parallel garbage collection, improving performance on multi-core systems.
        ]
        env["JAVA_OPTS"] = " ".join(java_opts)

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
            env=env,
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
        return self.zap_process.wait(timeout=self.shutdown_timeout)

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

    def __add_authentication_to_scan(
        self: "ZapRunner",
        automation_framework_script: dict,
        login_url: str,
        username: str,
        password: str,
    ) -> dict:
        for ctx in automation_framework_script.get("env", {}).get("contexts", []):
            name_of_zap_user = "default-user"
            if "authentication" not in ctx:
                ctx["authentication"] = {}
            ctx["authentication"] = {
                "method": "browser",
                "parameters": {
                    "browserId": "chromium-headless",
                    "loginPageUrl": login_url,
                    "loginPageWait": 5,
                },
                "verification": {"method": "autodetect"},
            }
            if (
                "sessionManagement" not in ctx
                or not ctx["sessionManagement"]
                or not ctx["sessionManagement"].get("method")
            ):
                ctx["sessionManagement"] = {"method": "autodetect"}

            if "users" not in ctx or not ctx["users"]:
                ctx["users"] = [
                    {
                        "name": "default-user",
                        "credentials": {"username": username, "password": password},
                        "enabled": True,
                    }
                ]
            elif len(ctx["users"]) != 1:
                raise ValueError(
                    f"if users are provided in the context, there must be exactly one user, found {len(ctx['users'])} users"
                )
            else:
                for user in ctx["users"]:
                    name_of_zap_user = user.get("name", "default-user")
                    user["credentials"]["username"] = username
                    user["credentials"]["password"] = password
                    user["enabled"] = True
        activeScanIndex = -1
        for i, job in enumerate(automation_framework_script.get("jobs", [])):
            if job["type"] == "activeScan":
                activeScanIndex = i
                break

        # inject the requestor job before active scan to ensure active scan is logged in
        requestor_job = {
            "type": "requestor",
            "name": "Authenticated User Requestor",
            "context": self.context_name,
            "user": name_of_zap_user,
            "requests": [
                {
                    "url": self.target_url,
                }
            ],
            "parameters": {"user": name_of_zap_user},
        }
        insert_index = activeScanIndex if activeScanIndex >= 0 else 0
        automation_framework_script["jobs"].insert(insert_index, requestor_job)

        return automation_framework_script

    def run_automation_framework_scan(
        self: "ZapRunner",
        login_url: str = None,
        username: str = None,
        password: str = None,
        filename: str = "zap-report.json",
        report_name: str = "Smithy Zap Report",
        report_title: str = "Smithy Zap Report",
        report_dir: str = None,
        scan_duration: int = 10,
        spider_duration: int = 5,
        spider_crawl_depth: int = 5,
        spider_max_children: int = 50,
    ) -> dict:
        automation_framework_script = None

        print(f"preparing to load automation plan:\n```{baseline_plan_template}```")
        try:
            automation_framework_script = json.loads(baseline_plan_template)
        except json.JSONDecodeError as e:
            print(
                f"could not parse plan provided \n```{baseline_plan_template}```\nerror: {e}"
            )
            raise e

        # setup context
        #   * make the urls be our target url
        #   * setup include/exclude paths
        #   * setup context auth if credentials were provided
        # If loggedin scan the also setup requestor
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

            context["excludePaths"] = global_exclude_paths.copy()
            context["excludePaths"].extend([f"^((?!{without_scheme}).)*$"])
            print(f"Configured exclude paths {context['excludePaths']}")

            if login_url and username and password:
                print("adding authentication to scan")
                automation_framework_script = self.__add_authentication_to_scan(
                    automation_framework_script,
                    login_url,
                    username,
                    password,
                )

        # setup:
        #   activeScan scanDuration
        #   spider maxDuration, crawlDepth, children
        #   spiderAjax maxDuration, crawlDepth
        #   report dir, filename, title
        for job in automation_framework_script["jobs"]:
            if job["type"] == "activeScan":
                if "parameters" not in job:
                    job["parameters"] = {}
                job["parameters"]["maxScanDurationInMins"] = scan_duration
            elif job["type"] == "spider":
                if "parameters" not in job:
                    job["parameters"] = {}
                job["parameters"]["maxDuration"] = spider_duration
                job["parameters"]["maxCrawlDepth"] = spider_crawl_depth
                job["parameters"]["maxChildren"] = spider_max_children
            elif job["type"] == "spiderAjax":
                if "parameters" not in job:
                    job["parameters"] = {}
                job["parameters"]["maxDuration"] = spider_duration
                job["parameters"]["maxCrawlDepth"] = spider_crawl_depth
            elif job["type"] == "report":
                job["name"] = report_name
                job["parameters"]["reportDir"] = report_dir
                job["parameters"]["reportFile"] = filename
                job["parameters"]["reportTitle"] = report_title

        script = yaml.safe_dump(automation_framework_script, sort_keys=False)
        print(f"templated automation framework script:\n```{script}```")

        with open("/tmp/zap_auth_automation.yaml", "w") as f:
            f.write("\n---\n")
            f.write(script)
            f.close()
        print(
            "running automation framework script located at /tmp/zap_auth_automation.yaml"
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

        return automation_framework_script


def get_env_or_default(value, env_key, default=""):
    return value if value else os.getenv(env_key, default)


def main():
    parser = argparse.ArgumentParser(description="Parse input parameters")

    parser.add_argument(
        "--target",
        type=str,
        default=get_env_or_default("", "TARGET"),
        help="Target URL or address",
    )

    # auth
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

    # internal
    parser.add_argument(
        "--api-key",
        default=get_env_or_default("", "API_KEY"),
        type=str,
        help="API key for authentication",
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
    parser.add_argument(
        "--shutdown-timeout",
        default=get_env_or_default("", "SHUTDOWN_TIMEOUT", default=10),
        type=int,
        help="how many seconds to wait for ZAP to shutdown",
    )

    # performance
    parser.add_argument(
        "--max-scan-duration",
        default=get_env_or_default("", "SCAN_DURATION_MINS"),
        type=str,
        help="for how long does the active scanner run, this affects how many findings will be produced",
    )
    parser.add_argument(
        "--max-spider-duration",
        default=get_env_or_default("", "SPIDER_DURATION_MINS"),
        type=str,
        help="for how long does the spider run, this affects how many findings will be produced",
    )
    parser.add_argument(
        "--max-spider-crawl-depth",
        default=get_env_or_default("", "SPIDER_MAX_CRAWL_DEPTH"),
        type=str,
        help="for how deep the spider should crawl, this affects how many findings will be produced",
    )
    parser.add_argument(
        "--max-spider-children",
        default=get_env_or_default("", "SPIDER_MAX_CHILDREN"),
        type=str,
        help="how many children pages the spider should crawl, this affects how many findings will be produced",
    )

    # testing/dev/debugging
    parser.add_argument(
        "--no-start-zap",
        default=False,
        action="store_true",
        help="(for local dev, do not attempt to start zap)",
    )
    args = parser.parse_args()

    target_url = args.target.strip("/")
    print(f"starting zap scanning target: {target_url}")

    shutdown_timeout = None
    if args.shutdown_timeout and str(args.shutdown_timeout).isdecimal():
        shutdown_timeout = int(args.shutdown_timeout)

    if any([args.username, args.password, args.login_url]) and not all(
        [args.username, args.password, args.login_url]
    ):
        raise ValueError(
            "if any of username, password or login-url are provided, all must be provided in order to run an authenticated scan"
        )

    runner = ZapRunner(
        api_key=args.api_key, target_url=target_url, shutdown_timeout=shutdown_timeout
    )
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
            print("running authenticated automation framework scan")
            return runner.run_automation_framework_scan(
                login_url=args.login_url,
                username=args.username,
                password=args.password,
                report_dir=args.report_dir,
            )
        print("running baseline scan using the the automation framework")
        return runner.run_automation_framework_scan(
            report_dir=args.report_dir,
            scan_duration=max_scan_duration,
            spider_duration=max_spider_duration,
        )
    finally:
        runner.stop_zap()


if __name__ == "__main__":
    main()
