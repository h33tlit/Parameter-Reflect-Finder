import json
import requests
from concurrent.futures import ThreadPoolExecutor
import re
from fake_useragent import UserAgent


#Author: Jubaer Alnazi



fetched_url = []
common_fetched_url = set()
ua = UserAgent()
domain = input('Type domain (eg. test.com) ==> ')


print("=>>> We just started! Give us some time!")
try:
    alienvault_request_fetch = requests.get('https://otx.alienvault.com/api/v1/indicators/hostname/'+domain+'/url_list?limit=1000', timeout=5, headers = {'User-Agent':str(ua.chrome)}).json()
    for request_url in alienvault_request_fetch['url_list']:
        for characters in request_url['url']:
            if '?' and '=' in characters:
                common_fetched_url.add(request_url['url'])
            else:
                pass
except:
    pass

waybackURL = "https://web.archive.org/cdx/search/cdx?url=*."+ domain +"&output=json&fl=original&collapse=urlkey"


try:
    request = requests.get(waybackURL,headers = {'User-Agent':str(ua.chrome)}, timeout=5)
    load = json.loads(request.text)
    for ur in load:
        for char in ur[0]:
            if '?' and '=' in char:
                common_fetched_url.add(ur[0])
            else:
                pass
except:
    pass


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
    except:
        pass

print("==>>> We will be scanning "+str(len(fetched_url))+" links!")



def check_xss(xss_urls):
    try:
        req = requests.get(xss_urls, timeout=1, headers = {'User-Agent':str(ua.chrome)}).text
        regex = re.findall('jUbAeR', req)
        if len(regex) != 0:
            return str(xss_urls)
        else:
            pass
    except:
        pass


found_links = set()
open_redirect = set()
try:

    with ThreadPoolExecutor(max_workers=1000) as pool:
        response_list = list(pool.map(check_xss, fetched_url))
    file_write = []
    for r in response_list:
        if r is not None:
            found_links.add(r)
            if 'url' and '=http' in r:
                open_redirect.add(r)
except:
    pass

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

