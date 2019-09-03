import requests, json, toolkits, os, sys, random

red = toolkits.red
green = toolkits.green
yellow = toolkits.yellow
cyan = toolkits.cyan

key = '4dcd540878ed289068319b829736b6bbe9dcfa406e98d3bd8d93f31a6cd09ddb'

# def writeResults(results,host):
#     resultsFile = './reports/{}.txt'.format(str(host))
#     w = open(resultsFile,'a+')
#     # print "Debug: Contents of results object\r\n{}".format(str(results))
#     for writable in results:
#         writable = str(writable.encode('utf-8')).strip().rstrip()
#         w.write(writable)
#     w.close()
#     return resultsFile

# Okay, forget about writing JSON objects to a file, clearly this is not well documented. I am going to do what he asked of me, which is to run additional queries on these webpages.
def writeResults(content,host):
    content = str(content.encode('utf-8')).strip().rstrip()
    resultsFile = './reports/{}.txt'.format(str(host))
    w = open(resultsFile,'a+')
    w.write(content)
    w.close()
    return

def queryUrl(key,host):
    relevant_keys = [
        'detected_urls',
        'domain_siblings',
        'subdomains'
    ]
    url = 'https://www.virustotal.com/vtapi/v2/domain/report'

    params = {'apikey':key,'domain':host}

    response = requests.get(url, params=params)

    jsonReturned = response.json()
    jsonReturned.keys()
    return


def readSuspectedDomains(suspectedDomains='/home/ctlister/Documents/Contract-VirusTotal/real_malware_domains.txt'):
    r = open(suspectedDomains,'r')
    l = r.readlines()
    print l
    # pick four random hosts to readlines from and target for virustotal
    randomlypicked = random.sample(l,4)
    print red("DEBUG: Randomly picked hosts\r\n{}".format(randomlypicked))
    for line in randomlypicked:
        host = line.strip().rstrip()
        # print red("Debug: Running investigation on host\r\n{}".format(str(host)))

        resultsFile = queryUrl(key,host)
        # cmd = "cat {}".format(str(resultsFile))
        # os.system(cmd)
        # # print yellow(results)
        # writeResults(results,host)
    return
os.system('clear')
readSuspectedDomains()
