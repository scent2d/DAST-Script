from selenium import webdriver # pip install -U selenium
from selenium.webdriver.common.proxy import *
import subprocess
import time
import os
from zapv2 import ZAPv2 as ZAP
import time
from selenium.webdriver.common.by import By
from selenium.webdriver import Firefox
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.firefox.options import Options

class TargetAuthScript(object):
    def __init__(self, proxy_host='localhost', proxy_port='8090', target='http://localhost:9000'):
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.target = target
    
    def get(self):
        options = Options()
        options.headless = True
        options.set_preference("network.proxy.type", 1)
        options.set_preference("network.proxy.http", proxy_host)
        options.set_preference("network.proxy.http_port", proxy_port)
        options.set_preference("network.proxy.ssl", proxy_host)
        options.set_preference("network.proxy.ssl_port", proxy_port)
        options.set_preference("network.proxy.no_proxies_on", "*.googleapis.com,*.google.com,*.gstatic.com,*.googleapis.com,*.mozilla.net,*.mozilla.com,ocsp.pki.goog")
        service = Service('/usr/local/bin/geckodriver')

        driver = Firefox(service=service, options=options)
        # driver = webdriver.Firefox(Service=service, options=options)
        print("[+] Initialized firefox driver")
        driver.implicitly_wait(120)
        print("[+] ================ Implicit Wait is Set =================")
        url = self.target
        driver.get('{}/login/'.format(url))
        print('[+] ' + driver.current_url)
        time.sleep(10)

        id_element = driver.find_element(By.XPATH, '//*[@id="username"]')       
        id_element.clear()
        id_element.send_keys('bruce.banner@we45.com')
    
        pw_element = driver.find_element(By.XPATH, '//*[@id="password"]')
        pw_element.clear()
        pw_element.send_keys('secdevops')
        
        login_element = driver.find_element(By.XPATH, '//*[@id="submit"]')
        login_element.click()
        time.sleep(10)
        print('[+] ' + driver.current_url)
        driver.get('{}/technicians/'.format(url))
        time.sleep(10)
        print('[+] ' + driver.current_url)
        driver.get('{}/appointment/plan'.format(url))
        time.sleep(10)
        print('[+] ' + driver.current_url)
        driver.get('{}/appointment/doctor'.format(url))
        time.sleep(10)
        print('[+] ' + driver.current_url)
        driver.get('{}/secure_tests/'.format(url))
        time.sleep(10)


###############################################
# Stage 1 - Setting
###############################################

base_path = '/home/scent2d/tool/zap/ZAP_2.12.0/'
headless_command = base_path + 'zap.sh -daemon -host 0.0.0.0 -port 8090 -config api.disablekey=true -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true'

print('[+] Execute ZAP Command: ' + headless_command)
zap_process = subprocess.Popen(headless_command.split(' '), stdout = open(os.devnull, 'w'))
start_time = time.time()
seconds = 20

while True:
  current_time = time.time()
  elapsed_time = current_time - start_time
  if elapsed_time > seconds:
    print("[+] ZAP Started ")
    break
  print("[+] ZAP Starting ...")
  time.sleep(10)

proxy_host = 'localhost'
proxy_port = 8090
target_ip = 'localhost'
proxy_url = "http://{0}:{1}".format(proxy_host,proxy_port)
target = "http://{0}:9000".format(target_ip)
print('[+] Target URL', target)

zap = ZAP(proxies = {'http': proxy_url, 'https': proxy_url})

zap.urlopen(target)
print('[+] Hello Target: ' + target)


###############################################
# Stage 2 - Login with Selenium
###############################################
TargetAuthScript(proxy_host=proxy_host, proxy_port=proxy_port, target=target).get()


###############################################
# Stage 3 - Spider
###############################################

# This line of code kicks off the ZAP default Spider. This returns an ID value for the spider
scan_id = zap.spider.scan(target)

# Give the Spider a chance to start
print('[*] Spider ID: {0}'.format(scan_id))
time.sleep(1)

# Now we can start monitoring the Spider's status
while(int(zap.spider.status(scan_id)) < 100):
  print('[*] Current Status of ZAP Spider: {0}%'.format(zap.spider.status(scan_id)))
  time.sleep(5)

print('[*] Spider Completed')
print('[*] ZAP Spider Result: ', zap.core.urls())


###############################################
# Stage 4 - Active Scan
###############################################
policyName = 'customPolicy'

if policyName not in zap.ascan.scan_policy_names:
    print('[*] ' + policyName + ' has been created')
    zap.ascan.add_scan_policy(
        policyName, alertthreshold="Low", attackstrength="Low")

active_scan_id = zap.ascan.scan(target,scanpolicyname=policyName)
print("[+] Active scan id: {0}".format(active_scan_id))
print("[+] ================ Scan Started =================")

while int(zap.ascan.status(active_scan_id)) < 100:
    print("[+] Scan progress: {0}%".format(zap.ascan.status(active_scan_id)))
    time.sleep(10)

print("[+] ================ Scan Completed =================")


###############################################
# Stage 5 - Report
###############################################
headers = {
  'Accept': 'application/json'
}
r = requests.get('http://localhost:8090/OTHER/core/other/jsonreport/', params={}, headers = headers)
r_json = json.loads(r.text)

fileName = 'result/selenium_auth_active_result.json'
with open(fileName, 'w') as fp:
    json.dump(r_json, fp)

print('[*] Check ' + fileName)


##############################################
# Stage 6 - Shutdown
##############################################
zap.core.shutdown() 
print("[*] ZAP has been Stopped !")



###############################################
# Stage 5 - Scan Result
###############################################

# alerts = zap.core.alerts()
# print('_'*125)
# print('|'+' '*48+'Name'+' '*47+'  |'+'  Severity  '+'|'+'  CWE  |')
# print('_'*125)
# for alert in alerts:
#     name = alert.get('name')
#     l = 100 - len(name)
#     sev = alert.get('risk')
#     sl = 10 - len(sev)
#     cwe = alert.get('cweid')
#     cl = 7 - len(cwe) - 1
#     print('| '+name+' '*l+'|  '+sev+' '*sl +'|  '+cwe+' '*cl+ '|')
#     print('_'*125)


