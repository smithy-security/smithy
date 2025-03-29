#!/usr/bin/env python

import argparse
import os
import time
import requests
import urllib.parse
from zapv2 import ZAPv2
from urllib.parse import urlparse


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

    def __init__(
        self, api_key: str, target_url: str, host: str = "localhost", port: int = 8090
    ):
        parsed = urlparse(target_url)
        if not bool(parsed.scheme and parsed.netloc):
            raise ZapInvalidTargetError(target=target_url)
        print(f"zap target {target_url}, recorded")

        if not api_key:
            raise ZapInvalidAPIKeyError(api_key=api_key)
        self.api_key = api_key
        self.target_url = target_url
        self.zap_api_url = f"http://{host}:{port}"
        self.request_proxies = {"http": self.zap_api_url, "https": self.zap_api_url}
        self.zap = ZAPv2(apikey=api_key, proxies=self.request_proxies)
        version = self.zap.core.version

        if not version:
            raise RuntimeError(f"could not connect to remote zap at {self.zap_api_url}")
        print(f"connected to remote zap version {version}")
        self.create_context()

    def create_context(self):
        self.context_id = self.zap.context.new_context(self.context_name)
        print(f"context is {self.zap.context.context(self.context_name)}")

    def set_include_in_context(self, target_url: str, logout_url: str = ""):
        exclude_url = logout_url
        include_url = f"{target_url}.*"
        self.zap.context.include_in_context(self.context_name, include_url)
        self.excluded_regexp = f"^(?=.*\b{include_url}\b)(?!.*\b{exclude_url}\b).*$"
        self.zap.context.exclude_from_context(self.context_name, self.excluded_regexp)
        print(
            f"Configured include regexp {include_url} and exclude regexp {exclude_url} in context"
        )

    def set_logged_in_indicator(self, logged_in_regexp: str):
        self.zap.authentication.set_logged_in_indicator(
            self.context_id, logged_in_regexp
        )
        print(f"Configured logged in indicator regex: {logged_in_regexp}")

    def set_form_based_auth(
        self, login_url: str, login_request_data_override: str = None
    ):
        login_request_data = "username={%username%}&password={%password%}"
        if login_request_data_override:
            login_request_data = login_request_data_override
        form_based_config = f"loginUrl={urllib.parse.quote(login_url)}&loginRequestData={urllib.parse.quote(login_request_data)}"
        self.zap.authentication.set_authentication_method(
            self.context_id, "formBasedAuthentication", form_based_config
        )
        print(
            f"Configured form based authentication for login url: {login_url} with request data:{login_request_data}"
        )

    def set_user_auth_config(self, user: str, username: str, password: str):
        if not user or not username or not password:
            raise ValueError(
                f"parameters 'user', 'username' and 'password' must be set, received: user:{user},username:{username},password:{password}"
            )

        self.user_id = self.zap.users.new_user(self.context_id, user)
        user_auth_config = f"username={urllib.parse.quote(username)}&password={urllib.parse.quote(password)}"
        self.zap.users.set_authentication_credentials(
            self.context_id, self.user_id, user_auth_config
        )
        self.zap.users.set_user_enabled(self.context_id, self.user_id, "true")
        self.zap.forcedUser.set_forced_user(self.context_id, self.user_id)
        self.zap.forcedUser.set_forced_user_mode_enabled("true")
        print(f"User Auth Configured for user {user} with username {username}")
        return self.user_id

    def start_authenticated_spider(self, user_id):
        scan_id = self.zap.spider.scan_as_user(
            self.context_id, user_id, self.target_url, recurse="true"
        )
        print(f"Started Spidering with Authentication for zap userid: {user_id}")
        return scan_id

    def start_spider(self):
        scan_id = self.zap.spider.scan(url=self.target_url, recurse=False,subtreeonly=True)
        print(f"Started Spidering")
        return scan_id

    def get_spider_status(self, scanID):
        return self.zap.spider.status(scanid=scanID)

    def active_authenticated_scan(self, scan_duration):
        self.zap.ascan.set_option_max_scan_duration_in_mins(scan_duration)
        self.zap.ascan.exclude_from_scan(
            regex=self.excluded_regexp, apikey=self.api_key
        )
        return self.zap.ascan.scan_as_user(
            url=self.target_url,
            contextid=self.context_id,
            userid=self.user_id,
            recurse=False,
            apikey=self.api_key,
        )

    def active_scan(self, scan_duration):
        self.zap.ascan.set_option_max_scan_duration_in_mins(scan_duration)
        self.zap.ascan.exclude_from_scan(
            regex=self.excluded_regexp, apikey=self.api_key
        )
        return self.zap.ascan.scan(
            url=self.target_url,
            contextid=self.context_id,
            recurse=False,
            apikey=self.api_key,
        )

    def get_scan_status(self, scanID):
        return self.zap.ascan.status(scanid=scanID)

    def get_report(
        self,
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
        "--login-indicator",
        default=get_env_or_default("", "LOGIN_INDICATOR"),
        type=str,
        help="login indicator",
    )
    parser.add_argument(
        "--logout-indicator",
        default=get_env_or_default("", "LOGOUT_INDICATOR"),
        type=str,
        help="logout indicator",
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

    args = parser.parse_args()
    if args.username and args.password:
        run_zap_authenticated_scan(args)
    else:
        run_zap_baseline_scan(args)


def run_zap_authenticated_scan(args):
    print(
        f"received a username and a password, running an authenticated scan for target: '{args.target}'"
    )
    sub_target_list = args.sub_targets.split(",") if args.sub_targets else []

    runner = ZapRunner(api_key=args.api_key, target_url=args.target)
    runner.set_form_based_auth(login_url=args.login_url)
    user_id_response = runner.set_user_auth_config(
        user=args.username, username=args.username, password=args.password
    )
    runner.set_include_in_context(logout_url=args.logout_url, target_url=args.target)
    runner.set_logged_in_indicator(logged_in_regexp=args.login_indicator)
    spider_id = runner.start_authenticated_spider(user_id=user_id_response)

    spider_status = runner.get_spider_status(spider_id)
    while "100" not in spider_status:
        print(f"spider scan status: {spider_status}%")
        time.sleep(10)
        spider_status = runner.get_spider_status(spider_id)

    scan_id = runner.active_authenticated_scan(args.max_scan_duration)
    scan_status = runner.get_scan_status(scanID=scan_id)
    while "100" not in scan_status:
        print(f"active scan status: {scan_status}%")
        time.sleep(10)
        scan_status = runner.get_scan_status(scanID=scan_id)

    print(
        f"report stored successfully at: {runner.get_report(report_dir=args.report_dir,filename=args.report_name)}"
    )


def run_zap_baseline_scan(args):
    print(
        f"did not receive a username and a password, running an unauthenticated baseline scan for target '{args.target}'"
    )
    runner = ZapRunner(api_key=args.api_key, target_url=args.target)
    runner.set_include_in_context(target_url=args.target)
    spider_id = runner.start_spider()
    spider_status = runner.get_spider_status(spider_id)
    while "100" not in spider_status:
        print(f"spider scan status: {spider_status}%")
        time.sleep(10)
        spider_status = runner.get_spider_status(spider_id)
    print("finished spidering")
    
    print("running active scan")
    scan_id = runner.active_scan(args.max_scan_duration)
    scan_status = runner.get_scan_status(scanID=scan_id)
    while "100" not in scan_status:
        print(f"active scan status: {scan_status}%")
        time.sleep(10)
        scan_status = runner.get_scan_status(scanID=scan_id)
    print("finished active scan")
    print(
        f"report stored successfully at: {runner.get_report(report_dir=args.report_dir,filename=args.report_name)}"
    )

if __name__ == "__main__":
    main()
