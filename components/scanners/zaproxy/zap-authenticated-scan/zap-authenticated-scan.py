#!/usr/bin/env python
import json
import yaml
import sys
import signal
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
                "runOnlyIfModern": true
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

    def set_include_in_context(self: "ZapRunner", target_url: str) -> None:
        urlparsed = urlparse(target_url)
        without_scheme = f"{urlparsed.netloc}{urlparsed.path.rstrip('/')}"
        include_url = f".*{without_scheme}.*"
        print(
            f"Configured include regexp {include_url}, response: {self.zap.context.include_in_context(self.context_name, include_url)}"
        )

    def set_browser_based_auth(self: "ZapRunner", login_url: str) -> None:
        browser_based_config = (
            f"loginPageUrl={quote(login_url)}&browserId=firefox-headless"
        )
        resp = self.zap.authentication.set_authentication_method(
            contextid=self.context_id,
            authmethodname="browserBasedAuthentication",
            authmethodconfigparams=browser_based_config,
        )

        if resp != "OK":
            raise RuntimeError(
                "could not setup authentication for login_url: {login_url}, response: {resp}"
            )
        resp = self.zap.sessionManagement.set_session_management_method(
            contextid=self.context_id, methodname="autoDetectSessionManagement"
        )
        print(
            f"Configured browser based authentication for login     url: {login_url}, response: {resp}"
        )

    def set_user_auth_config(
        self: "ZapRunner",
        user: str,
        username: str,
        password: str,
    ) -> None:
        if not user or not username or not password:
            raise ValueError(
                f"parameters 'user', 'username' and 'password' must be set, received: user:{user},username:{username},password:{password}"
            )

        self.user_id = self.zap.users.new_user(self.context_id, user)
        user_auth_config = f"username={quote(username)}&password={quote(password)}"
        self.zap.users.set_authentication_credentials(
            self.context_id, self.user_id, user_auth_config
        )
        self.zap.users.set_user_enabled(self.context_id, self.user_id, "true")
        self.zap.authentication.get_authentication_method
        print(f"User Auth Configured for user {user} with username {username}")
        return self.user_id

    def test_user_auth(
        self: "ZapRunner",
    ) -> None:
        print(
            f"authentication as user:"
            f" {self.zap.users.authenticate_as_user(userid=self.user_id,contextid=self.context_id)}"
        )

    def start_authenticated_spider(self: "ZapRunner", user_id):
        scan_id = self.zap.spider.scan_as_user(
            contextid=self.context_id,
            userid=user_id,
            url=self.target_url,
            recurse="true",
            maxchildren=500,
            subtreeonly=True,
        )
        print(f"Started Spidering with Authentication for zap userid: {user_id}")
        return scan_id

    def start_spider(self: "ZapRunner"):
        scan_id = self.zap.spider.scan(
            url=self.target_url, recurse=False, subtreeonly=True
        )
        print(f"Started Spidering")
        return scan_id

    def get_spider_status(self: "ZapRunner", scanID):
        return self.zap.spider.status(scanid=scanID)

    def active_authenticated_scan(self: "ZapRunner", scan_duration):
        self.zap.ascan.set_option_max_scan_duration_in_mins(scan_duration)
        return self.zap.ascan.scan_as_user(
            url=self.target_url,
            contextid=self.context_id,
            userid=self.user_id,
            recurse=False,
            apikey=self.api_key,
        )

    def active_scan(self: "ZapRunner", scan_duration: int = 0):
        print(f"setting scan max duration to {scan_duration} minutes")
        self.zap.ascan.set_option_max_scan_duration_in_mins(scan_duration)
        return self.zap.ascan.scan(
            url=self.target_url,
            contextid=self.context_id,
            recurse=False,
            apikey=self.api_key,
        )

    def get_active_scan_status(self: "ZapRunner", scanID):
        return self.zap.ascan.status(scanid=scanID)

    def get_passive_scan_status(self: "ZapRunner"):
        """Get the status of a passive scan.
        It returns -1 when there are no more record to scan so it is finished.
        """
        return self.zap.pscan.records_to_scan

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
    ):
        automation_framework_script = json.loads(plan)
        for context in automation_framework_script["env"]["contexts"]:
            print(f"setting zap target for context {context['name']}")
            context["urls"] = [self.target_url]
            context["includePaths"] = [f"{self.target_url}.*"]
            context["authentication"]["parameters"]["loginPageUrl"] = login_url
            for user in context["users"]:
                user["credentials"]["username"] = username
                user["credentials"]["password"] = password
        for job in automation_framework_script["jobs"]:
            if job["type"] == "requestor":
                for req in job["requests"]:
                    req["url"] = self.target_url
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

    def get_report(
        self: "ZapRunner",
        filename: str = "zap-report.json",
        title: str = "Smithy ZAP report",
        report_dir: str = None,
    ):
        print(f"generating report")
        response = requests.get(
            f"{self.zap.base}reports/action/generate/?apikey={self.api_key}&title={title}&template=sarif-json&theme=&description=&contexts=&sites=&sections=&includedConfidences=&includedRisks=&reportFileName={filename}&reportFileNamePattern=&reportDir={report_dir}&display=",
            proxies=self.request_proxies,
        )
        if response.status_code != 200:
            from pprint import pprint

            pprint(response.text)
            raise RuntimeError(
                f"the zap server replied with {response.status_code} while generating report"
            )
        return response.json()["generate"]


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
        "--use-automation-framework",
        action="store_true",
        help="use automation framework to execute the scan",
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

    try:
        if args.username and args.password:
            if args.use_automation_framework:
                print("running automation framework scan")
                return runner.run_automation_framework_scan(
                    login_url=args.login_url,
                    username=args.username,
                    password=args.password,
                    report_dir=args.report_dir,
                    plan=plan_template,
                )
            print("running scan using the rest api")
            return run_zap_authenticated_scan(args, runner)

        print("running baseline scan using the rest api")
        return run_zap_baseline_scan(args, runner)
    finally:
        runner.stop_zap()


def run_zap_authenticated_scan(args, runner: ZapRunner):
    print(
        f"received a username and a password, running an authenticated scan for target: '{args.target}'"
    )

    runner.set_browser_based_auth(login_url=args.login_url)
    user_id_response = runner.set_user_auth_config(
        user=args.username, username=args.username, password=args.password
    )
    runner.test_user_auth()

    runner.set_include_in_context(target_url=args.target)
    spider_id = runner.start_authenticated_spider(user_id=user_id_response)

    spider_status = runner.get_spider_status(spider_id)
    while "100" not in spider_status:
        if spider_status == "does_not_exist":
            raise RuntimeError("spider scan never started")
        print(f"spider scan status: {spider_status}%")
        time.sleep(10)
        spider_status = runner.get_spider_status(spider_id)

    scan_id = runner.active_authenticated_scan(args.max_scan_duration)
    scan_status = runner.get_active_scan_status(scanID=scan_id)
    while "100" not in scan_status:
        print(f"active scan status: {scan_status}%")
        time.sleep(10)
        scan_status = runner.get_active_scan_status(scanID=scan_id)

    print(
        f"report stored successfully at: {runner.get_report(report_dir=args.report_dir,filename=args.report_name)}"
    )


def run_zap_baseline_scan(args, runner: ZapRunner):
    print(
        f"did not receive a username and a password, running an unauthenticated baseline scan for target '{runner.target_url}'"
    )
    runner.set_include_in_context(target_url=runner.target_url)
    spider_id = runner.start_spider()
    spider_status = runner.get_spider_status(spider_id)
    while "100" not in spider_status:
        print(f"spider scan status: {spider_status}%")
        time.sleep(10)
        spider_status = runner.get_spider_status(spider_id)
    print("finished spidering")

    print("running active scan")
    scan_id = runner.active_scan(args.max_scan_duration)
    if scan_id == "url_not_in_context":
        raise RuntimeError("scan url is not in context")

    print(f"started scan with id {scan_id}")
    scan_status = runner.get_active_scan_status(scanID=scan_id)
    while "100" not in scan_status:
        if "DOES_NOT_EXIST" in scan_status:
            raise RuntimeError("scan was never started")
        print(f"active scan status: {scan_status}%")
        time.sleep(10)
        scan_status = runner.get_active_scan_status(scanID=scan_id)
    print("finished active scan")

    print("waiting for passive scan to finish")
    scan_status = runner.get_passive_scan_status()
    try:
        while int(scan_status) >= 1:
            if "DOES_NOT_EXIST" in scan_status:
                raise RuntimeError("scan was never started")
            print(f"records left for passive scan to finish: {scan_status}")
            time.sleep(10)
            scan_status = runner.get_passive_scan_status()
    except ValueError as ve:
        print(f"error while checking passive scan status: {ve}, continuing")

    print(f"finished passive scan, records left: {scan_status}")

    print(
        f"report stored successfully at: {runner.get_report(report_dir=args.report_dir,filename=args.report_name)}"
    )


if __name__ == "__main__":
    main()
