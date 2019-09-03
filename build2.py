#!/usr/bin/python
#coding=utf-8
import os, sys, socket, operator, threading, subprocess, re, toolkits, requests

os.system('clear')
keyABIPDB = "0a88770931dcd9faec4aa6e9ac74a975be90b6cc53fad5e6346935177286f2d042454dfbba42ddce"
keyVTAPI = "4dcd540878ed289068319b829736b6bbe9dcfa406e98d3bd8d93f31a6cd09ddb"

# Whoever wrote Sooty is a dumbass. He couldn't differentiate between a IP address, a DNS query, or a hostname. AbuseIPDB only checks IPv4 or IPv6 addresses
red = toolkits.red
green = toolkits.green
yellow = toolkits.yellow
cyan = toolkits.cyan

def readTargetsFile(targetFile):
    r = open(targetFile,'r')
    lines = r.readlines()
    t = []
    for l in lines:
        s = str(l.encode('utf-8')).strip().rstrip()
        t.append(s)
    return t

def convertHostnameToIP(host):
    try:
        addr = socket.gethostbyname(host)
        debugStr = green("Resolved {} to {}".format(str(host),str(addr)))
        # print(str(debugStr))
        print str(debugStr)
        ip = addr
    except Exception:
        # print(red("Warning: The URL provided {} no longer resolves to a IP Address! Inactive URL!\r\nQuitting".format(str(host))))
        # print red("Warning: The URL provided {} no longer resolves to a IP Address! Inactive URL!\r\nQuitting".format(str(host))
        print red("Warning: The URL provided {} no longer resolves to a IP Address! Inactive URL!".format(str(host)))
        ip = host
    return ip

# Checks if it's a URL or IP address.
def checkHost(host):
    p = re.compile('^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?')
    m = p.match(host)
    if m:
        # print(cyan("Debug: {} has been detected as a URL/hostname\r\nConverting to IP address".format(str(host))))
        # print cyan("Debug: {} has been detected as a URL/hostname\r\nConverting to IP address".format(str(host))))
        print cyan("Debug: {} has been detected as a URL/hostname\r\nConverting to IP address".format(str(host)))
        # Verifies that it's a URL
        return False
    else:
        # Verifies that it's a IP address
        return True

# This functionality is broken because I need to convert CIDR to a address range. Worth a shot though
# def checkCloudFlare(ip):
#     print(yellow("Checking if {} is a cloudflare IP address".format(str(ip))))
#     # if IP is IPv4
#     octets = ip.split('.')
#     IPv4Match = "{}.{}".format(
#         str(octets[0]),
#         str(octets[1])
#     )

#     r = open('cloudflareips.txt','r+')
#     lines = r.read()
#     if re.search(IPv4Match,lines):
#         print(green("Alert, {} is found to be a Cloudflare Nameserver".format(
#             str(ip)
#         )))
#     else:
#         print(red("IP {} not found in Cloudflare IPv4 Database".format(str(ip))))

#     return

def VTCheck(keyVTAPI, ip):
    VT_API_KEY = keyVTAPI
    # print(yellow("Checking {} on VirusTotal".format(str(ip))))
    print yellow("Checking {} on VirusTotal".format(str(ip)))
    try:    # try IP else fall through to URL
        result = response.json()
        for each in result['detected_urls']:
            tot = tot + 1
            pos = pos + each['positives']

        if tot != 0:
            # print(green("   No of Reportings: " + str(tot)))
            # print(green("   Average Score:    " + str(pos / tot)))
            # print(green("   VirusTotal Report Link: " + "https://www.virustotal.com/gui/ip-address/" + str(ip)))
            print green("\tNo of Reportings: {}".format(str(tot)))
            print green("\tAverage Score:\t{}".format(str(pos/tot)))
            print green("\tVirusTotal Report Link: https://www.virustotal.com/gui/ip-address/{}".format(str(ip)))
        else:
            # print(green("   No of Reportings: " + str(tot)))
            print green("\tNo of Reportings: {}".format(str(tot)))
    except:
        try: #EAFP
            url = 'https://www.virustotal.com/vtapi/v2/url/report'
            params = {'apikey': VT_API_KEY, 'resource': ip}
            response = requests.get(url, params=params)
            result = response.json()
            # print(green("\n VirusTotal Report:"))
            # print(green("   URL Malicious Reportings: " + str(result['positives']) + "/" + str(result['total'])))
            # print(green("   VirusTotal Report Link: " + str(result['permalink'])))
            print green("\n VirusTotal Report:")
            print green("\tURL Malicious Reportings: {}/{}".format(
                str(result['positives']),
                str(result['total'])
            ))
            print green("\tVirusTotal Report Link: {}".format(str(result['permalink'])))
            # gives URL for report (further info)
        except:
            # print(red(" Not found in database"))
            print red(" Not found in database")
    else:
        # print(red(" There's been an error - check your API key, or VirusTotal is possible down"))
        print red(" There's been an error - check your API key, or VirusTotal is possible down")
        return
def checkTorURL(ip):
    # print(yellow("Checking if {} is a Tor Exit Node".format(str(ip))))
    print yellow("Checking if {} is a Tor Exit Node".format(str(ip)))
    TOR_URL = "https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1"
    req = requests.get(TOR_URL)
    print("\n TOR Exit Node Report: ")
    print "\n TOR Exit Node Report: "
    if req.status_code == 200:
        tl = req.text.split('\n')
        c = 0
        for i in tl:
            if ip == i:
                #print(green("  " + i + " is a TOR Exit Node"))
                print green("\t{} is a TOR Exit Node".format(str(i)))
                c = c+1
        if c == 0:
            # print(red("  " + ip + " is NOT a TOR Exit Node"))
            print red("\t{} is NOT a TOR Exit Node".format(str(i)))
    else:
        # print(red("   TOR LIST UNREACHABLE"))
        print red("\tTOR LIST UNREACHABLE")
    return
def checkAbuseIPDB(keyABIPDB,ip):
    key = keyABIPDB


    try:
        AB_URL = 'https://api.abuseipdb.com/api/v2/check'
        days = '180'

        querystring = {
            'ipAddress': ip,
            'maxAgeInDays': days
        }

        headers = {
            'Accept': 'application/json',
            'Key': key
        }
        response = requests.request(method='GET', url=AB_URL, headers=headers, params=querystring)
        if response.status_code == 200:
            req = response.json()

            # print(green("   IP:          " + str(req['data']['ipAddress'])))
            print green("\t IP:\t\t{}".format(str(
                req['data']['ipAddress']
            )))
            # print(green("   Reports:     " + str(req['data']['totalReports'])))
            print green("\tReports:\t\t{}".format(str(req['data']['totalReports'])))
            # print(green("   Abuse Score: " + str(req['data']['abuseConfidenceScore']) + "%"))
            print green("\tAbuse Score: {}%".format(req['data']['abuseConfidenceScore']))
            # print(green("   Last Report: " + str(req['data']['lastReportedAt'])))
            print green("\tLast Report: {}".format(str(req['data']['lastReportedAt'])))
        else:
            # print(red("   Error Reaching ABUSE IPDB"))
            print red("\tError Reaching ABUSE IPDB")
    except:
            # print(red('   IP Not Found in AbuseIP Database'))
            print red("\tIP Not Found in AbuseIP Database")
    return

def checkBadIPs(ip):
    # print(yellow("\n Checking BadIP's... "))
    print yellow("\n Checking BadIP's...")
    try:
        BAD_IPS_URL = 'https://www.badips.com/get/info/' + ip
        response = requests.get(BAD_IPS_URL)
        if response.status_code == 200:
            result = response.json()

            sc = result['Score']['ssh']
            # print(green("  " + str(result['suc'])))
            print green("\t{}".format(str(results['suc'])))
            # print(green("  Score: " + str(sc)))
            print green("\tScore: {}".format(str(sc)))
        else:
            # print(red('  Error reaching BadIPs'))
            print red("\tError reaching BadIPs")
    except:
        # print(red('  IP not found in BadIPs database'))
        print red("\tIP not found in BadIPs Database")
    return
def main(host):
    if checkHost(host) == False:
        # Convert hostname to IP address
        ip = convertHostnameToIP(host)
    else:
        ip = host
    # print(yellow("Checking reputation of {}".format(str(host))))
    print yellow("Checking reputation of {}".format(str(host)))
    checkAbuseIPDB(keyABIPDB,ip)
    checkBadIPs(ip)
    checkTorURL(ip)
    VTCheck(keyVTAPI,ip)
    # checkCloudFlare(ip)
    return
if len(sys.argv) < 2:
    print "Usage, python app.py <wordlist of URLs to scan>"
    exit(0)
else:
    listOfUrls = sys.argv[1]
    targets = readTargetsFile(listOfUrls)
    for target in targets:
        main(target)