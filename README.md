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
