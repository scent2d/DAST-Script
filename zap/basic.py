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

# Fetch list of urls enumerated by ZAP
print('[*] ZAP URL Lists: ', zap.core.urls()[:10])

print('[*] ZAP Stats: ', zap.stats.site_stats(site = target)[:10])
print('[*] ZAP Params: ', zap.params.params()[0]['Parameter'][:5])
print('[*] ZAP Scanners: ', zap.pscan.scanners)

# Get an existing list of vulnerabilities
print('[*][*] ZAP Alerts: ', zap.core.alerts(baseurl=target)[:2])