# Basic-XSS-Checker

This is a very basic python script that runs through website search parameter such as https://www.google.com/search?q=helloworld, and tries to find a potential XSS vulnerability.
If the website detects this, it will sometimes display your browser information. This could be another XSS vulnerability, as you can modify your User-Agent to an XSS payload and it can be ran on the code.
The default payload is <script>alert('fsociety');</script>, you can set your custome payload with the --payload option.
