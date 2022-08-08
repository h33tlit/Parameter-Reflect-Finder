import json
import requests
from concurrent.futures import ThreadPoolExecutor
import re
import random


#Author: Jubaer Alnazi




user_agent_list = [
'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Safari/605.1.15',
'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:77.0) Gecko/20100101 Firefox/77.0',
'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36',
'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:77.0) Gecko/20100101 Firefox/77.0',
'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36',
]

user_agent = random.choice(user_agent_list)



fetched_url = []
common_fetched_url = set()

#Taking user inputs
domain = input('Type domain (eg. test.com) ==> ')
max_thread = input('Max thread (eg. 1000) ==> ')
max_link_to_scan = input('Max Link To Scan (eg. 1000) ==> ')


print("=>>> We just started! Give us some time!")


if len(max_link_to_scan) == 0:
    max_link_to_scan = 10000

allurl = set()
#Capturing API results to get URLs

try:
    alienvault_request_fetch = requests.get('https://otx.alienvault.com/api/v1/indicators/hostname/'+domain+'/url_list?limit=1000', headers = {'User-Agent': user_agent}, timeout=5).json()
    for request_url in alienvault_request_fetch['url_list']:
        allurl.add(request_url['url'])
        for characters in request_url['url']:
            if '?' and '=' in characters:
                common_fetched_url.add(request_url['url'])
            else:
                pass
except:
    pass

waybackURL = "https://web.archive.org/cdx/search/cdx?url=*."+ domain +"&output=json&fl=original&collapse=urlkey"


try:
    request = requests.get(waybackURL, headers = {'User-Agent': user_agent}, timeout=5)
    load = json.loads(request.text)
    for ur in load:
        for char in ur[0]:
            allurl.add(ur[0])
            if '?' and '=' in char:
                common_fetched_url.add(ur[0])
            else:
                pass
except:
    pass

link_count = 0
# Formatting the URLs
for url in common_fetched_url:
    try:
        urlpara = url.split("?")[1]
        urlpara2 = urlpara.split("&")
        for parameters in urlpara2:
                para_index = parameters.split("=")
                para_string = str(para_index[0] + "=" + para_index[1])
                param_check = str(para_index[0]) + "=" + str(para_index[1]).replace(str(para_index[1]), 'jUbAeR')
                formatted_url = url.replace(para_string, param_check)
                fetched_url.append(formatted_url)
                link_count += 1
        if link_count > int(max_link_to_scan):
            break

    except:
        pass

print("==>>> We will be scanning "+str(len(fetched_url))+" links!")



#Scan for reflected keyword
def check_xss(xss_urls):
    try:
        req = requests.get(xss_urls, headers = {'User-Agent': user_agent}, timeout=1).text
        regex = re.findall('jUbAeR', req)
        if len(regex) != 0:
            return str(xss_urls)
        else:
            pass
    except:
        pass


found_links = set()
open_redirect = set()

if len(max_thread) == 0:
    max_thread = 1000

try:
        with ThreadPoolExecutor(max_workers=int(max_thread)) as pool:
            response_list = list(pool.map(check_xss, fetched_url))
        file_write = []

        for r in response_list:
            if r is not None:
                found_links.add(r)
                if 'url' and '=http' in r:
                    open_redirect.add(r)
except:
    pass


#Showing results



if len(found_links) != 0:
    print('\n#######################-  Possible XSS   -###########################')
    for links1 in found_links:
        print(links1)
    print('\n#######################-  Possible Open Redirect   -###########################')
    if len(open_redirect) != 0:
        for links in open_redirect:
            print(links)
    elif len(open_redirect) == 0:
        print("No links found!")
elif len(found_links) == 0:
    print('\n#######################-  Result   -###########################')
    print('We could not find anything :( ')

with open('url-%s.txt' % str(domain), 'w') as f:
    for urls in allurl:
        f.write('%s\n' % urls)
print('\n#######################-  We saved all the fetched urls in a text file name "url-%s.txt"!   -###########################' %  str(domain))
