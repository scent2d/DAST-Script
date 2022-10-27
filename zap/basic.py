import subprocess
import os
import time

#GUI ZAP
base_path = ''
gui_command = base_path + 'zap.sh -config api.disablekey=true -port 8090'
headless_command = base_path + 'zap.sh -daemon -host 0.0.0.0 -port 8090 -config api.disablekey=true -config api.addrs.addr.name=.* -config api.addrs.addr.re    gex=true'
ap_process = subprocess.Popen(headless_command.split(' '), stdout = open(os.devnull, 'w'))
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