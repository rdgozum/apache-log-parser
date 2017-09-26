# Apache-Log-Parser
Author: Ryan Paul Gozum<br/><br/>
This is a python script for parsing server apache logs and detecting anomalous events, particularly SQL Injection, Remote File Inclusion, and Web Shell attacks using regular expressions derived from known patterns. 


## Developer Guide
* Make sure you have a Python 2.7 or later installed in your computer.
* Install pip package manager from <i>https://pypi.python.org/pypi/pip</i>.
* To gain access to GeoIP databases for locating IP Address, get the library directly from PyPI: 
```
$ pip install python-geoip
```
* If you also want the free MaxMind Geolite2 database, you can in addition:
```
$ pip install python-geoip-geolite2
```
* Put the test log files inside the Test folder. In this project, I have a Test.log file which is a subfile of CLTF1.log containing 50,000 requests. 
```
ryan:~/Documents/Horangi$ tail -50000 CTF1.log > src/test/Test.log
```

## User Guide
### analyze_log.py
* Main python script
* Requires apache log as input following the standard format below:
```
# Software: Microsoft Internet Information Services 8.5
# Version: 1.0
# Date: 2015-10-12 12:00:01
# Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken
```
* `DefineVariable` function generates the regex pattern based on the standard format above.
* `ExtractData` function extracts corresponding field values from each log entry.
* `OrganizeRecord` function organizes extracted data into a dictionary data structure to ease with the processing.
```
client_ip_record[key] = [hits, activity 1, activity 2, ... , activity n] 
where key is the client ip address
```
* `PrintResult` function writes the record into files located in the Result folder. This also calls the analyze_query.py to check whether passed query parameter is malicious.

```
List of unique IP addresses as a flat text file
List of unique IP addresses with country and number of hits as a flat text file
List of all activity per IP address to individual flat text files per IP
Detect SQLi with found entries to flat text file
Detect remote file inclusion with found entries to flat text file
Detect web shells with found entries to flat text file
```

### analyze_query.py
* Return `True` if input query is malicious. Otherwise, return `False`.
* Divided into three parts:

detectSQLi
```
Checks if input query performs SQL Injection attack.
Regex based on https://forensics.cert.org/latk/loginspector.py
```

detectRFI
```
Checks if input query performs Remote File Inclusion attack.
Regex based on https://www.trustwave.com/Resources/SpiderLabs-Blog/ModSecurity-Advanced-Topic-of-the-Week--Remote-File-Inclusion-Attack-Detection/
```

detectWebShell
```
Checks if input query performs Web Shell attack.
Regex based on https://github.com/emposha/PHP-Shell-Detector
```
