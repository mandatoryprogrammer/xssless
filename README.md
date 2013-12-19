xssless
======

An automated XSS payload generator written in python.

Usage
-----

1. Record request(s) with [Burp proxy](http://portswigger.net/burp/proxy.html)
2. Select requests you want to generate, then right click and select "Save items"
3. Use xssless to generate your payload: `./xssless.py -s burp_export_file`
4. Pwn!

Installation
------------

If you don't have BeautifulSoup installed:
    pip install beautifulsoup4

Download the latest xssless:
    git clone https://github.com/mandatoryprogrammer/xssless

Run the script:
    ./xssless.py -h


Contributing
------------

Want to contribute some code to this project? Great! I'm not the best at Python or Javascript so I appreciate any additions to the project. Contributions can also be in the form of new feature ideas, if you've got one let me know!


