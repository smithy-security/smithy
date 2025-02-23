
#!/usr/bin/env python
# Base64 orchestration file
import time
import requests
import urllib

zap_api_key="changeme"
zap_api_host="localhost"
zap_api_port="8081"
target_url="http://bodgeit.com:8080/bodgeit"
report_dir="/scratch"
report_filename="zap-report.json"

report_title="TestReport"
# TODO make configurable

def is_url_reachable()->bool:
    resp = requests.get(target_url)
    return resp.status_code == 200

def register()->str:
    response = requests.post(f"http://{target_url}/register.jsp",data={
    "username":"test@example.com",
    "password1":"foobar",
    "password2":"foobar",
    })
    if response.status_code != 200:
        raise RuntimeError(f"the bodgeit server replied with {response.status_code} while registering")
    return response.cookies.get('JSESSIONID')

def add_context():
    print("adding new context")
    response = requests.get(f"http://{zap_api_host}:{zap_api_port}/JSON/context/action/newContext/?apikey={zap_api_key}&contextName=bodgeit")
    if response.status_code != 200:
        raise RuntimeError(f"the zap server replied with {response.status_code} while adding a context")
    return response.json()['contextId']

def exclude_logout_from_context():
    print("excluding logout from context")
    response = requests.get(f"http://{zap_api_host}:{zap_api_port}/JSON/context/action/excludeFromContext/?apikey={zap_api_key}&contextName=bodgeit&regex=.*ogout.*")
    if response.status_code != 200:
        raise RuntimeError(f"the zap server replied with {response.status_code} while excluding logout from context")

def exclude_logout_from_spider():
    print("excluding logout from spider")
    response = requests.get(f"http://{zap_api_host}:{zap_api_port}/JSON/spider/action/excludeFromScan/?apikey={zap_api_key}&regex=.*ogout.*")
    if response.status_code != 200:
        raise RuntimeError(f"the zap server replied with {response.status_code} while excluding logout from spidering")

def spider():
    print("spidering")
    response = requests.get(f"http://{zap_api_host}:{zap_api_port}/JSON/spider/action/scan/?apikey={zap_api_key}&url={urllib.parse.quote_plus(target_url)}&maxChildren=&recurse=&contextName=&subtreeOnly=")
    if response.status_code != 200:
        raise RuntimeError(f"the zap server replied with {response.status_code} while spidering")
    return response.json()["scan"]

def wait_for_spider(scanId:int):
    print("waiting for spider to finish")
    status=0
    while status < 100:
        response = requests.get(f"http://{zap_api_host}:{zap_api_port}/JSON/spider/view/status/?apikey={zap_api_key}&scanId={scanId}")
        if response.status_code != 200:
            raise RuntimeError(f"the zap server replied with {response.status_code} while checking spider status")
        status = int(response.json()["status"])
        print(f"spider completion status: {status}")
        time.sleep(3)

def attack():
    print("running active scan against target")
    response = requests.get(f"http://{zap_api_host}:{zap_api_port}/JSON/ascan/action/scan/?apikey={zap_api_key}&url={urllib.parse.quote_plus(target_url)}&recurse=true&inScopeOnly=&scanPolicyName=&method=&postData=&contextId=")
    if response.status_code != 200:
        print(response.text)
        raise RuntimeError(f"the zap server replied with {response.status_code} while attacking")
    return response.json()["scan"]

def wait_for_scan(scanId:int):
    print("waiting for active scan to finish")
    status=0
    while status < 100:
        response = requests.get(f"http://{zap_api_host}:{zap_api_port}/JSON/ascan/view/status/?apikey={zap_api_key}&scanId={scanId}")
        if response.status_code != 200:
            raise RuntimeError(f"the zap server replied with {response.status_code} while checking scan status")
        status = int(response.json()["status"])
        print(f"active scan completion status for scanId: {scanId} is: {status}")
        time.sleep(3)

def get_report():
    print("generating report")
    response = requests.get(f"http://{zap_api_host}:{zap_api_port}/JSON/reports/action/generate/?apikey={zap_api_key}&title={report_title}&template=sarif-json&theme=&description=&contexts=&sites=&sections=&includedConfidences=&includedRisks=&reportFileName={report_filename}&reportFileNamePattern=&reportDir={report_dir}&display=")
    if response.status_code != 200:
        raise RuntimeError(f"the zap server replied with {response.status_code} while generating report")
    return response.json()["generate"]

if not is_url_reachable():
    raise RuntimeError(f"url {target_url} is not reachable")

exclude_logout_from_spider()
spiderId=spider()
wait_for_spider(spiderId)
scanId=attack()
wait_for_scan(scanId)
print(f"report location is:{get_report()}")

