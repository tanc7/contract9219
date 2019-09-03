#!/usr/bin/python
#coding=utf-8
import os, sys, subprocess, json, requests, toolkits, time

# Color coding toolkit

red = toolkits.red
green = toolkits.green
yellow = toolkits.yellow
cyan = toolkits.cyan

key = '4dcd540878ed289068319b829736b6bbe9dcfa406e98d3bd8d93f31a6cd09ddb'

# Runs shell commands in foreground
def bash_cmd_fg(cmd):
    subprocess.call(cmd,shell=True,executable="/bin/bash")
    return

# Runs shell commands in background
def bash_cmd_bg(cmd):
    p = subprocess.Popen(cmd,shell=True,executable="/bin/bash",stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    o = p.stdout.read()
    e = p.stdout.read()
    out = o + e
    out = str(out.encode('utf-8')).strip().rstrip()
    return out

# Converts any lists and arrays into a string
def convertToString(listObject):
    s = ""
    return (s.join(listObject))
def virusTotalQuery(key,host):

    url = 'https://www.virustotal.com/vtapi/v2/domain/report'

    params = {'apikey':key,'domain':host}
    try:
        response = requests.get(url, params=params)

        # print(response.json())
        jsonret = response.json()
        # iterate through all keys
        # data = json.loads(jsonret)
        iterList = []
        for i in jsonret['detected_urls']:
            malwareURL = i['url']
            iterList.append(malwareURL)

        # print iterList
        try:
            # if any of the following JSON arrays are available, automatically append it
            iterList.append(jsonret['BitDefender domain info'])
            iterList.append(jsonret['domain_siblings'])
            iterList.append(jsonret['Opera domain info'])
            iterList.append(jsonret['undetected_urls'])
            iterList.append(jsonret['subdomains'])
            iterList.append(jsonret['whois'])
        # If that JSON array is not available, skip
        except Exception:
            pass
    # If no JSON is returned, in other words, VirusTotal limit reached
    except ValueError:
        print red("Warning, your 4 query limit per minute for VirusTotal.com's public API has been used up! Sleeping 10 seconds.")
        time.sleep(10)
        main(targets)
    print cyan("Debug, contents of iterlist {}".format(iterList))
    return iterList

def shodanLookup(host):
    return results

def censysLookup(host):
    return results

def securityTrailsLookup(host):
    return results

def nsLookup(host):
    print green("Executing nslookup on {}".format(host))
    cmd = "nslookup {}".format(str(host))
    results = bash_cmd_bg(cmd)
    return results

def hostLookup(host):
    print green("Executing host on {}".format(host))

    cmd = "host {}".format(str(host))
    results = bash_cmd_bg(cmd)
    return results

# def whoisLookup(host):
#     print green("Executing whois on {}".format(host))
#     cmd = "whois {}".format(str(host))
#     results = bash_cmd_bg(cmd)
#     return results

def fiercedns(host):
    print green("Executing fierce -dns module on {}".format(host))
    cmd = "fierce -dns {0} 2>&1 | tee ./reports/{0}-fiercedns.txt".format(str(host))
    results = bash_cmd_bg(cmd)
    return results

def dnsRecon(host):
    print green("Executing dnsrecon on {}".format(host))
    cmd = "touch ./reports/{0}-dnsrecon.txt && dnsrecon -d {0} -t std -c ./reports/{0}-dnsrecon.csv".format(str(host))
    results = bash_cmd_fg(cmd)
    return results

def readTargetsFile(targetFile):
    r = open(targetFile,'r')
    lines = r.readlines()
    t = []
    for l in lines:
        s = str(l.encode('utf-8')).strip().rstrip()
        t.append(s)
    return t

def writeResultsFile(host,content,resultsFile):
    w = open(resultsFile,'ab+')
    w.write(content + '\r\n')
    # print yellow("Debug: Written line\r\n{}\r\nInto {}".format(str(content),str(resultsFile)))
    w.close()
    return

banner = yellow("""Note: This is designed to be used with Kali Linux as it already comes with the necessary tools to perform DNS reconnaissance\r\nI may add additional reconnaissance and forensics tools, particularly DNS history from censys and securitytrails and host information from shodan.io""")
print banner
time.sleep(2)
def main(target):
    host = target
    # pulls associated results from the virustotal query which returns as a JSON object, you can turn each URL into a string
    # Returns a list object of related URLs of the target

    # VirusTotal Block
    virusTotalResults = virusTotalQuery(key, target)
    resultsFile = "./reports/{}_virustotal.txt".format(str(host))
    for l in virusTotalResults:
        if type(l) == list:
            l = convertToString(l)
        try:
            s = str(l.encode('utf-8')).strip().rstrip()
        except Exception:
            pass
        writeResultsFile(host,s,resultsFile)
    print green("Report generated for VirusTotal on {}: {}".format(str(host),str(resultsFile)))
    # Hosts command block
    hostsResults = hostLookup(host)
    resultsFile = "./reports/{}_hostscommand.txt".format(str(host))
    s = str(hostsResults.encode('utf-8')).strip().rstrip()
    writeResultsFile(host, s, resultsFile)
    print green("Report generated for hosts command on {}: {}".format(str(host),str(resultsFile)))

    # def nsLookup(host):
    nslookupResults = nsLookup(host)
    resultsFile = "./reports/{}_nslookup.txt".format(str(host))
    print green("Report generated for nslookup on {}: {}".format(str(host),str(resultsFile)))
    s = str(nslookupResults.encode('utf-8')).strip().rstrip()
    writeResultsFile(host, s, resultsFile)
    
    # def hostLookup(host):
    # def whoisLookup(host):
    # Refrain from using whois manually, because you get put on timeout. Use VirusTotal's whois results
    # whoisLookupResults = whoisLookup(host)
    # resultsFile = "./reports/{}_whois.txt".format(str(host))
    # s = str(whoisLookupResults.encode('utf-8')).strip().rstrip()
    # writeResultsFile(host, s, resultsFile)
    # print green("Report generated for whois on {}: {}".format(str(host),str(resultsFile)))

    fierceDNSResults = fiercedns(host)
    resultsFile = "./reports/{}_fiercedns.txt".format(str(host))
    s = str(fierceDNSResults.encode('utf-8')).strip().rstrip()
    writeResultsFile(host, s, resultsFile)
    print green("Report generated for fierce dns at {}".format(resultsFile))

    dnsRecon(host)
    print green("Report generated for dnsrecon at ./reports/{}-dnsrecon.txt".format(str(host)))
    # dnsReconResults = dnsRecon(host)
    # resultsFile = "./reports/{}_dnsrecon.txt".format(str(host))
    # s = str(dnsReconResults.encode('utf-8')).strip().rstrip()
    # writeResultsFile(host, s, resultsFile)

    return
if len(sys.argv) < 2:
    print "Usage, python app.py <wordlist of URLs to scan>"
    exit(0)
else:
    listOfUrls = sys.argv[1]
    targets = readTargetsFile(listOfUrls)
    for target in targets:
        main(target)