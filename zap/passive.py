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
headless_command = base_path + 'zap.sh -daemon -host 0.0.0.0 -port 8090 -config api.disablekey=true -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true'
# gui_command = base_path + 'zap.sh -config api.disablekey=true -port 8090'

print('[*] Execute ZAP Command: ' + headless_command)
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
  time.sleep(10)

# Setting the local ZAP instance that is open on your local system
proxySettings = 'http://localhost:8090'
zap = ZAP(proxies = {'http': proxySettings, 'https': proxySettings})
print('[*] ZAP Proxy Setting: ' + proxySettings)

# Setting Target
target = 'http://localhost:5050'

# Opens up the target site. Makes a single GET request
zap.urlopen(target)
print('[*] Hello Target: ' + target)

###############################################
# Stage 2 - Spider
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
print('[*] ZAP Spider urls: ', zap.core.urls())
print('[*] ZAP Spider stats: ', zap.stats.site_stats(site=target))
print('[*] ZAP Spider params: ', zap.params.params())
print('[*] ZAP Spider scanners: ', zap.pscan.scanners)
print('[*] ZAP Spider alerts: ', zap.core.alerts(baseurl=target))

###############################################
# Stage 3 - Report
###############################################
headers = {
  'Accept': 'application/json'
}
r = requests.get('http://localhost:8090/OTHER/core/other/jsonreport/', params={}, headers = headers)
r_json = json.loads(r.text)

fileName = 'passive_result.json'
with open(fileName, 'w') as fp:
    json.dump(r_json, fp)

print('[*] Check ' + fileName)


###############################################
# Stage 4 - Shutdown
###############################################
zap.core.shutdown() 
print("[*] ZAP has been Stopped !")