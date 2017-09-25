# returns True if malicious
# returns false otherwise
import re

'''
REGULAR EXPRESSION IS BASED ON https://forensics.cert.org/latk/loginspector.py
'''
def detectSQLi(query):

	#Clear Text SQL injection test, will create false positives. 
	regex=re.compile('drop|delete|truncate|update|insert|select|declare|union|create|concat', re.IGNORECASE)
	if regex.search(query):
		return True

	#look for single quote, = and --
	regex=re.compile('((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))|\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))', re.IGNORECASE)
	if regex.search(query):
		return True
	
	#look for MSExec
	regex=re.compile('exec(\s|\+)+(s|x)p\w+', re.IGNORECASE)
	if regex.search(query):
		return True

	# hex equivalent for single quote, zero or more alphanumeric or underscore characters
	regex=re.compile('/\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/ix', re.IGNORECASE)
	if regex.search(query):
		return True

	return False

'''
REGULAR EXPRESSION IS BASED ON https://www.trustwave.com/Resources/SpiderLabs-Blog/ModSecurity-Advanced-Topic-of-the-Week--Remote-File-Inclusion-Attack-Detection/
'''
def detectRFI(query):
	regex=re.compile('^(?:ht|f)tps?:\/\/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', re.IGNORECASE)
	if regex.search(query):
		return True
	
	regex=re.compile('(?:\binclude\s*\([^)]*(ht|f)tps?:\/\/)', re.IGNORECASE)
	if regex.search(query):
		return True
	
	regex=re.compile('(?:ft|htt)ps?.*\?+$', re.IGNORECASE)
	if regex.search(query):
		return True
	
	regex=re.compile('^(?:ht|f)tps?://(.*)\?$', re.IGNORECASE)
	if regex.search(query):
		return True

	return False

'''
REGULAR EXPRESSION IS BASED ON https://github.com/emposha/PHP-Shell-Detector
'''
def detectWebShell(query):
	regex=re.compile('%(preg_replace.*\/e|`.*?\$.*?`|\bcreate_function\b|\bpassthru\b|\bshell_exec\b|\bexec\b|\bbase64_decode\b|\bedoced_46esab\b|\beval\b|\bsystem\b|\bproc_open\b|\bpopen\b|\bcurl_exec\b|\bcurl_multi_exec\b|\bparse_ini_file\b|\bshow_source\b)%', re.IGNORECASE)
	if regex.search(query):
		return True

	return False