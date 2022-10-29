import requests
import subprocess
from pprint import pprint
# import pickle
import json
import os
import time
from zapv2 import ZAPv2 as ZAP # pip install python-owasp-zap-v2.4

###############################################
# Stage 1 - Setting
###############################################
base_path = '/home/scent2d/tool/zap/ZAP_2.12.0/'
gui_command = base_path + 'zap.sh -config api.disablekey=true -port 8090'

print('[*] Execute ZAP Command: ' + gui_command)
zap_process = subprocess.Popen(gui_command.split(' '), stdout = open(os.devnull, 'w'))
start_time = time.time()
seconds = 30

while True:
  current_time = time.time()
  elapsed_time = current_time - start_time
  if elapsed_time > seconds:
    print("[*] ZAP Started ")
    break
  print("[*] ZAP Starting ...")
  time.sleep(10)

# Setting the local ZAP instance that is open on your local system
# proxySettings = 'http://localhost:8090'
proxySettings = {'http': 'http://localhost:8090', 'https': 'http://localhost:8090'}
zap = ZAP(proxies = proxySettings)
print('[*] ZAP Proxy Setting: ', proxySettings)

# Setting Target
target = 'http://localhost:5050'

# Opens up the target site. Makes a single GET request
zap.urlopen(target)
print('[*] Hello Target: ' + target)

###############################################
# Stage 2 - Get Auth Token for Authenticated Scan
###############################################

auth_dict = {'username': 'admin', 'password': 'admin123'}

login = requests.post(target + '/login', json=auth_dict)

if login.status_code == 200:
    auth_token = login.headers['Authorization']
    # print('[*] Auth Header: ', auth_token)
    zap.replacer.add_rule(description = "AuthHeader", enabled = True, matchtype = "REQ_HEADER", matchregex = False, matchstring = "Authorization", replacement = auth_token)
    print('[*] Add AuthToken: ', auth_token)
    

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
  time.sleep(2)

print('[*] Spider Completed')
print('[*] ZAP Spider Result: ', zap.core.urls())


###############################################
# Stage 4 - Active Scan
###############################################

policyName = 'customPolicy'
customPolicy = zap.ascan.add_scan_policy(policyName, alertthreshold='High', attackstrength='High')
print('[*] ' + policyName + ' has been created')

# # Query all scan policies by name
# print(zap.ascan.scan_policy_names)

# Start Active Scan 
active_scan_id = zap.ascan.scan(target, scanpolicyname='customPolicy')
print('[*] Active Scan Id: {0}'.format(active_scan_id))

# Now we can start monitoring the spider's status
while int(zap.ascan.status(active_scan_id)) < 100:
    print('[*] Current Status of ZAP Active Scan: {0}%'.format(zap.ascan.status(active_scan_id)))
    time.sleep(2)

print('[*] Active Scan Completed')


###############################################
# Stage 5 - Report
###############################################
headers = {
  'Accept': 'application/json'
}
r = requests.get('http://localhost:8090/OTHER/core/other/jsonreport/', params={}, headers = headers)
r_json = json.loads(r.text)

fileName = 'result/auth_active_result_gui.json'
with open(fileName, 'w') as fp:
    json.dump(r_json, fp)

print('[*] Check ' + fileName)


###############################################
# Stage 6 - Shutdown
###############################################
# zap.core.shutdown() 
# print("[*] ZAP has been Stopped !")

