*** Settings ***
Library  RoboZap  http://127.0.0.1:8090/  8090
Library  OperatingSystem

*** Variables ***
${ZAP_PATH}  /home/scent2d/tool/zap/ZAP_2.12.0/
${ZAP_TARGET}  http://127.0.0.1:9000/
${CONTEXT}  SecDevOps
${REPORT_FORMAT}  json
${REPORT_TITLE}  ZAP Report
${REPORT_AUTHOR}  we45
${EXPORT_FILE_PATH}  ${CURDIR}/zap.json
${SCANPOLICY}  Default Policy

*** Test Cases ***

Start ZAP
    start headless zap  ${ZAP_PATH}
    sleep  30
    zap open url  ${ZAP_TARGET}

ZAP Contextualize
    ${contextid}=  zap define context  ${CONTEXT}  ${ZAP_TARGET}
    set suite variable  ${CONTEXT_ID}  ${contextid}

ZAP Crawl
    ${spider_id}=  zap start spider  ${CONTEXT}  ${ZAP_TARGET}
    zap spider status  ${spider_id}
    sleep  30

ZAP Active Scan
    ${scan_id}=  zap start ascan  ${CONTEXT_ID}  ${ZAP_TARGET}  ${SCANPOLICY}
    sleep  5
    set suite variable  ${SCAN_ID}  ${scan_id}
    zap scan status  ${scan_id}

ZAP Generate Report
    zap export report  ${EXPORT_FILE_PATH}  ${REPORT_FORMAT}  ${REPORT_TITLE}  ${REPORT_AUTHOR}

ZAP Die
    zap shutdown