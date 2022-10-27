import subprocess
import os
import time

# 1. Execute
base_path = '/Users/scent2d/Downloads/ZAP_2.11.0/'
gui_command = base_path + 'zap.sh -config api.disablekey=true -port 8090'
headless_command = base_path + 'zap.sh -daemon -host 0.0.0.0 -port 8090 -config api.disablekey=true -config api.addrs.addr.name=.* -config api.addrs.addr.re    x=true'

zap_process = subprocess.Popen(headless_command.split(' '), stdout = open(os.devnull, 'w'))
start_time = time.time()
seconds = 30

while True:
  current_time = time.time()
  elapsed_time = current_time - start_time
  if elapsed_time > seconds:
    print("[*] ZAP Started ")
    break
  print("[*] ZAP Starting ...")
  time.sleep(5)

# 2. Spider
# pip install python-owasp-zap-v2.4
from zapv2 import ZAPv2 as ZAP

# Setting the local ZAP instance that is open on your local system
zap = ZAP(proxies = {'http': 'http://localhost:8090', 'https': 'http://localhost:8090'})
print('[*] ZAP Proxy Setting')

target = 'http://192.168.0.104:5050'

# Opens up the target site. Makes a single GET request
zap.urlopen(target)

# This line of code kicks off the ZAP default Spider. This returns an ID value for the spider
scan_id = zap.spider.scan(target)

# Give the Spider a chance to start
print('[*] Spider ID: {0}'.format(scan_id))
time.sleep(1)

# Now we can start monitoring the Spider's status
while(int(zap.spider.status(scan_id)) < 100):
  print('[*] Current Status of ZAP Spider: {0}%'.format(zap.spider.status(scan_id)))
  time.sleep(2)

print('[*] Spider Completed')

# Create a new scan policy with attack threshold and attack strength (low)
customPolicy = zap.ascan.add_scan_policy('customPolicy', alertthreshold='Low', attackstrength='Low')
print('[*] customPolicy has been created')

# Query all scan policies by name
#print(zap.ascan.scan_policy_names)

# Start Active Scan 
active_scan_id = zap.ascan.scan(target, scanpolicyname='customPolicy')
print('[*] Active Scan Id: {0}'.format(active_scan_id))

# Now we can start monitoring the spider's status
while int(zap.ascan.status(active_scan_id)) < 100:
    print('[*] Current Status of ZAP Active Scan: {0}%'.format(zap.ascan.status(active_scan_id)))
    time.sleep(2)

print('[*] Active Scan Completed')

# Report
import requests
import os

url = 'http://localhost:8090/JSON/exportreport/action/generate/'
export_path = os.getcwd() + '/vul.json'
extension = 'json'
source_info = 'Vulnerability Report'
alert_severity = 't;t;t;t' #High;Medium;Low;Info
alert_details = 't;t;t;t;t;t;f;f;f;f' #CWEID;#WASCID;Description;Other Info;Solution;Reference;Request Header;Response Header;Request Body;Response Body

data = {'absolutePath': export_path, 'fileExtension': extension, 'sourceDetails': source_info, 'alertSeverity': alert_severity, 'alertDetails': alert_details}

r = requests.post(url, data=data)
print('[*][*] Active Scan Result: ', r.content)

# Shuts down the ZAP Scanner
zap.core.shutdown() 
print("[*] ZAP has been stopped !")