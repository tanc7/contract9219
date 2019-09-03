#!/usr/bin/python
#coding=utf-8
import requests, json, toolkits

red = toolkits.red
green = toolkits.green
yellow = toolkits.yellow
cyan = toolkits.cyan

key = '4dcd540878ed289068319b829736b6bbe9dcfa406e98d3bd8d93f31a6cd09ddb'

def writeResults(results,host):
    resultsFile = './reports/{}.txt'.format(str(host))
    w = open(resultsFile,'a+')
    print "Debug: Contents of results object\r\n{}".format(str(results))
    for writable in results:
        w.write(writable)
    w.close()
    # for k in results:
    #     w.write("{}\r\n".format(str(k))
    #     # debugString = "Wrote\r\n{}\r\nInto{}".format(
    #     #     str(k),
    #     #     str(resultsFile)
    #     # )
    #     # debugString = "Wrote\r\nData:{}\r\nInto{}".format(
    #     #     str(k),
    #     #     str(resultsFile)
    #     # )
    #     # print green(debugString)
    #     w.close()
    return
def writeJson(host,jsonReturned):
    jsonFile = "./reports/{}.json".format(str(host))
    w = open(jsonFile,'w+')
    w.write(jsonReturned)
    w.close()
    return jsonFile
def queryUrl(key,host):
    interesting_keys = [
        'Alexa domain info',
        'BitDefender domain info',
        'detected_communicating_samples',
        'detected_downloaded_samples',
        'detected_referrer_samples',
        'detected_urls',
        'dns_records',
        'domain_siblings',
        'https_certificate_date',
        'last_https_certificate',
        'subdomains',
        'undetected_communicating_samples',
        'undetected_downloaded_samples',
        'undetected_referrer_samples',
        'undetected_urls',
        'whois'
    ]
    # Narrowed down what the employer wants
    relevant_keys = [
        'detected_urls',
        'domain_siblings',
        'subdomains'
    ]
    url = 'https://www.virustotal.com/vtapi/v2/domain/report'

    params = {'apikey':key,'domain':host}

    response = requests.get(url, params=params)

    # print(response.json())
    jsonReturned = response.json()
    # jsonFile = writeJson(host,jsonReturned)
    # pyDict = json.load(jsonFile)
    # print pyDict
    # pyDict = json.load(jsonReturned)
    # print pyDict
    for k in relevant_keys:
        results = []
        # results = {k, v}
        try:
            if k != 'detected_urls':
                print yellow(k)
                print cyan(jsonReturned[k])
                print yellow("Debug: Contents of results\r\n{}".format(results))
                v = "Key = {},Value = {}".format(k,jsonReturned[k])
                results.append(v)
            if k == 'detected_urls':
                for element in jsonReturned['detected_urls']:
                    URLObject = element
                    # URLObject is a JSON object, turn it into a list
                    URLObjectKeys = [
                        'url',
                        'positives',
                        'total',
                        'scan_date'
                    ]
                    for key in URLObject:
                        print "Key: {}\r\nValue: {}\r\n".format(str(key),str(URLObject[key]))
                    for url in URLObject:
                        # this is what the employer wants
                        print red(URLObject['url'])
                        directURLs = "Related URL: {}".format(URLObject['url'])
                        results.append(directURLs)
            # detected_urls = results['detected_urls']
            # for v in detected_urls:
            #     # v is a list like object
            #     print red("Debug: Type of object v is {}".format(str(type(v))))
            #     print green(v)
        except KeyError:
            # key does not exist
            pass
        # print yellow(k)
        # print cyan(jsonReturned[k])
        # Stringify all elements of the results list
        for i in results:
            i = str(i.encode('utf-8')).strip().rstrip()
            print i
    return results

# queryUrl(key,'google.com')

def readSuspectedDomains(suspectedDomains='/home/ctlister/Documents/Contract-VirusTotal/real_malware_domains.txt'):
    r = open(suspectedDomains,'r')
    l = r.readlines()
    for line in l:
        host = line.strip().rstrip()
        print red("Debug: Running investigation on host\r\n{}".format(str(host)))

        results = queryUrl(key,host)
        print yellow(results)
        writeResults(results,host)
    return

readSuspectedDomains()