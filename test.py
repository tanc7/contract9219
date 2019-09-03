import requests, json,random,toolkits

def testFunction(host):

    url = 'https://www.virustotal.com/vtapi/v2/domain/report'

    params = {'apikey':'4dcd540878ed289068319b829736b6bbe9dcfa406e98d3bd8d93f31a6cd09ddb','domain':'usaa.com-sec-inet-auth-logon-ent-logon-logon-redirectjsp.chrischadwick.com.au'}

    response = requests.get(url, params=params)

    # print(response.json())
    jsonret = response.json()
    # iterate through all keys
    # data = json.loads(jsonret)
    # iterList = []
    # for i in jsonret['detected_urls']:
    #     malwareURL = i['url']
    #     iterList.append(malwareURL)
    for i in jsonret.keys():
        print i
    return
def readSuspectedDomains(suspectedDomains='/home/ctlister/Documents/Contract-VirusTotal/real_malware_domains.txt'):
    r = open(suspectedDomains,'r')
    l = r.readlines()
    randomlypicked = random.sample(l,4)
    for line in l:
        host = line.strip().rstrip()
        print toolkits.green("Targeting {}".format(str(host)))
        # print red("Debug: Running investigation on host\r\n{}".format(str(host)))
        testFunction(host)

        # results = queryUrl(key,host)
        # print yellow(results)
        # writeResults(results,host)
    return

readSuspectedDomains()
# url = 'https://www.virustotal.com/vtapi/v2/domain/report'

# params = {'apikey':'4dcd540878ed289068319b829736b6bbe9dcfa406e98d3bd8d93f31a6cd09ddb','domain':'usaa.com-sec-inet-auth-logon-ent-logon-logon-redirectjsp.chrischadwick.com.au'}

# response = requests.get(url, params=params)

# # print(response.json())
# jsonret = response.json()
# # iterate through all keys
# # data = json.loads(jsonret)
# # iterList = []
# # for i in jsonret['detected_urls']:
# #     malwareURL = i['url']
# #     iterList.append(malwareURL)

# for i in jsonret.keys():
#     print i

# first of all, take notes. Have it iterate through a sample of 1000 malicious domains and then take down each domain's category. As you can see from sampling google.com and a actual malicious domain: amazon.co.uk.security-check.ga, it actually returns different JSON objects with different keys. We need to enumerate all of these keys.

# keys in json found

# Alexa category
# Alexa domain info
# Alexa rank
# BitDefender category
# BitDefender domain info
# categories
# detected_communicating_samples
# detected_downloaded_samples
# detected_referrer_samples
# detected_urls
# dns_records
# dns_records_date
# domain_siblings
# Dr.Web category
# favicon
# Forcepoint ThreatSeeker category
# https_certificate_date
# last_https_certificate
# Opera domain info
# pcaps
# popularity_ranks
# resolutions
# response_code
# subdomains
# TrendMicro category
# undetected_communicating_samples
# undetected_downloaded_samples
# undetected_referrer_samples
# undetected_urls
# verbose_msg
# Websense ThreatSeeker category
# Webutation domain info
# whois
# whois_timestamp
# WOT domain info