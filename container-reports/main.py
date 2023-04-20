import requests
import json
import os

PCC_ACCESS_KEY = os.environ['PCC_ACCESS_KEY']
PCC_SECRET_KEY = os.environ['PCC_SECRET_KEY']
PCC_API_VERSION = '22.12'
PCC_EXCLUDE_BASE_IMAGES = False
PCC_COMPUTE_API_URL = 'https://europe-west3.cloud.twistlock.com/eu-103407/'

images_deployed = 0
images_with_vulns = 0
images_with_critical_vulns = 0
images_with_critical_vulns_with_fix = 0
images_with_high_vulns = 0
images_with_high_vulns_with_fix = 0
images_with_compliance_issues = 0

while True:
    r = requests.get(PCC_COMPUTE_API_URL + '/api/v' +  PCC_API_VERSION + '/images?offset=' +  str(images_deployed + 1) + '&filterBaseImage=' + str(PCC_EXCLUDE_BASE_IMAGES), auth=(PCC_ACCESS_KEY, PCC_SECRET_KEY))
    images = json.loads(r.text)

    images_deployed = images_deployed + len(images)

    for image in images:
        low = 0
        medium = 0
        high = 0
        critical = 0
        hasfix_high = 0
        hasfix_critical = 0

        if image['complianceIssues']:
            images_with_compliance_issues = images_with_compliance_issues + 1

        if image['vulnerabilities']:
            if len(image['vulnerabilities']) > 0:
                images_with_vulns = images_with_vulns + 1

            for vuln in image['vulnerabilities']:
                match vuln['severity']:

                    case 'critical':
                        critical = critical + 1
                        for riskfactor in vuln['riskFactors']:
                            if riskfactor == "Has fix":
                                hasfix_critical = hasfix_critical + 1                       
                    
                    case 'high':
                        high = high + 1
                        for riskfactor in vuln['riskFactors']:
                            if riskfactor == "Has fix":
                                hasfix_high = hasfix_high + 1                       
                    
                    case 'important':
                        high = high + 1
                    
                    case 'medium':
                        medium = medium + 1
                    
                    case 'moderate':
                        medium = medium + 1
                    
                    case 'low':
                        low = low + 1
                    
                    case 'unimportant':
                        low = low + 1
                    
                    case 'negligible':
                        low = low + 1
                    
                    case _:
                        print('error: unhandled vuln: ' + vuln['severity'])
                        exit(1)

            if critical > 0:
                images_with_critical_vulns = images_with_critical_vulns + 1

            if hasfix_critical > 0:
                images_with_critical_vulns_with_fix = images_with_critical_vulns_with_fix + 1
            
            if high > 0:
                images_with_high_vulns = images_with_high_vulns + 1
            
            if hasfix_high > 0:
                images_with_high_vulns_with_fix = images_with_high_vulns_with_fix + 1

    if len(images) < 50:
        break

print('-' * 96)
print('  Image Vulnerabilty and Compliance Summary Report')
print('-' * 96)
print('PCC_EXCLUDE_BASE_IMAGES: ' + str(PCC_EXCLUDE_BASE_IMAGES))
print('images_deployed: ' +  str(images_deployed))
print('images_with_vulns: ' + str(images_with_vulns))
print('images_with_critical_vulns: ' + str(images_with_critical_vulns))
print('images_with_critical_vulns_with_fix: ' + str(images_with_critical_vulns_with_fix))
print('images_with_high_vulns: ' + str(images_with_high_vulns))
print('images_with_high_vulns_with_fix: ' + str(images_with_high_vulns_with_fix))
print('images_with_compliance_issues: ' + str(images_with_compliance_issues))


