# Apache-Log-Parser
Author: Ryan Paul Gozum<br/><br/>
This is a python script for parsing apache log and detecting anomalous client requests, particularly SQL Injection, Remote File Inclusion, and Web Shell using regular expression derived from known patterns. 


## Developer Guide
* Make sure you have a Python 2.7 or later installed in your computer.
* Install python package manager from <i>https://pypi.python.org/pypi/pip</i>.
* To gain access to GeoIP databases for IP Address location, get the library directly from PyPI: 
```
$ pip install python-geoip
```
* If you also want the free MaxMind Geolite2 database you can in addition:
```
$ pip install python-geoip-geolite2
```
* Put the log file to be tested inside Test folder. In this code, I have a Test.log file which is a subfile of CLTF1.log. 
```
ryan:~/Documents/Horangi$ tail -50000 CTF1.log > src/test/Test.log</i>
```

## User Guide
### analyze_log.py
* Main python script
* Requires apache log as the input following the standard below:
```
# Software: Microsoft Internet Information Services 8.5
# Version: 1.0
# Date: 2015-10-12 12:00:01
# Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken
```
* `DefineVariable` function generates the regex based on the standard log pattern.
* `ExtractData` function extracts corresponding fields from each log entry.
* `OrganizeRecord` function stores the extracted data into a dictionary to ease with the processing.
```
client_ip_record[key] = [hits, activity 1, activity 2, ... , activity n] 
where key is the client ip address
```
* `PrintResult` function writes the record into files. This also calls the analyze_query.py to check whether passed query is malicious.

```
List of unique IP addresses as a flat text file
List of unique IP addresses with country and number of hits as a flat text file
List of all activity per IP address to individual flat text files per IP
Detect SQLi with found entries to flat text file
Detect remote file inclusion with found entries to flat text file
Detect web shells with found entries to flat text file
```

### analyze_query.py
* Returns `True` if input query is malicious. Otherwise, return `False`.
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
