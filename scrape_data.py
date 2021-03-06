import json
import pandas as pd
import urllib
import os
import gzip

d = {'CVE_ID':[],'CWE':[],'accessVector':[],'accessComplexity':[],'authentication':[],'confidentialityImpact':[],'integrityImpact':[],'availabilityImpact':[],'baseScore':[],'severity':[],'exploitabilityScore':[],'impactScore':[],'publishedDate':[],'lastModifiedDate':[]}

prefix = 'nvdcve-1.0-'
url = 'https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-'
for year in range(2002,2019):
    # originally I had downloaded manually for jupyter but still that failed.
    file_tmp = urllib.request.urlretrieve(url+str(year)+'.json.gz', filename=None)[0]

    with gzip.open(file_tmp,'rb') as f:
        cve = json.load(f)

    for c in cve['CVE_Items']:
        id_num= c['cve']['CVE_data_meta']['ID']
        try:
            impactV2 = c['impact']['baseMetricV2']['cvssV2']
        except:
            impactV2=None
        # Only taking cves that have a problem type described
        for problem in c['cve']['problemtype']['problemtype_data']:
            for desc in problem['description']:
                d['CVE_ID'].append(id_num)
                d['CWE'].append(desc['value'])
                d['publishedDate'].append(c['publishedDate'])
                d['lastModifiedDate'].append(c['lastModifiedDate'])
                if impactV2:
                    d['severity'].append(c['impact']['baseMetricV2']['severity'])
                    d['exploitabilityScore'].append(c['impact']['baseMetricV2']['exploitabilityScore'])
                    d['impactScore'].append(c['impact']['baseMetricV2']['impactScore'])
                    d['accessVector'].append(impactV2['accessVector'])
                    d['accessComplexity'].append(impactV2['accessComplexity'])
                    d['authentication'].append(impactV2['authentication'])
                    d['confidentialityImpact'].append(impactV2['confidentialityImpact'])
                    d['integrityImpact'].append(impactV2['integrityImpact'])
                    d['availabilityImpact'].append(impactV2['availabilityImpact'])
                    d['baseScore'].append(impactV2['baseScore'])
                else:
                    d['severity'].append('NA')
                    d['exploitabilityScore'].append('NA')
                    d['impactScore'].append('NA')
                    d['accessVector'].append('NA')
                    d['accessComplexity'].append('NA')
                    d['authentication'].append('NA')
                    d['confidentialityImpact'].append('NA')
                    d['integrityImpact'].append('NA')
                    d['availabilityImpact'].append('NA')
                    d['baseScore'].append('NA')

cve_df = pd.DataFrame.from_dict(d)
cve_df.to_csv('cve_data.csv')
