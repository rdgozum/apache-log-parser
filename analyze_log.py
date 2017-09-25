from sets import Set
from geoip import geolite2
import re, os
import analyze_query as aq

##########################
def DefineVariable():
	p = {
		's' : r'\s',									# space
		'0' : r'\d{4}-\d{2}-\d{2}',						# date
		'1' : r'\d{2}:\d{2}:\d{2}',						# time
		'2' : r'172.17.100.\d{1,3}',					# server_ip
		'3' : 'GET|POST|HEAD|OPTIONS',					# method
		'4' : '.*',										# uri_stem & query
		'5' : '80|443',									# port
		'6' : '.*',										# client_username
		'7' : r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',	# client_ip
		'8' : '.*',										# client_agent
		'9' : r'\d{3}',									# status
		'10' : r'\d{1,3}',								# substatus
		'11' : r'\d{1,3}',								# win_status
		'12' : r'\d{1,3}' 								# time_taken
	}

	# CREATING REGEX PATTERN
	Pattern = ""
	for i in range(len(p)-2):
		Pattern = Pattern+"("+p[str(i)]+")"
		if i < len(p)-3 and i != 4:
			Pattern = Pattern + p['s']
	ExtractData(Pattern)

##########################
def ExtractData(Pattern):
	f = open(os.getcwd()+"/test/Test.log", "r")
	client_ip_record = {}
	unique_client_ip_set = set()

	# ITERATE APACHE LOG
	for String in f:
		result = re.match(Pattern, String)
		if(result is None):
			pass
		else:
			activity = result.groups(0)[3]+" "+result.groups(0)[4]
			client_ip = result.groups(0)[7]
			unique_client_ip_set.add(client_ip)				# unique ip address list
			OrganizeRecord(result, activity, client_ip, client_ip_record)
	
	f.close()
	PrintResult(unique_client_ip_set, client_ip_record)

##########################
def OrganizeRecord(result, activity, key, client_ip_record):
	if(not(key in client_ip_record.keys())):
		client_ip_record[key] = [1,activity]
	else:
		client_ip_record[key][0] = client_ip_record[key][0] + 1
		client_ip_record[key].append(activity)

	return client_ip_record

##########################
def PrintResult(unique_client_ip_set, client_ip_record):
	with open(os.getcwd()+"/result/[1] IP Address List.txt", "w") as f1:
		f1.write("LIST OF UNIQUE IP ADDRESS\n")
		for element in unique_client_ip_set:
			f1.write(element+"\n")

	with open(os.getcwd()+"/result/[2] IP Address Records.txt", "w") as f2:
		for element in unique_client_ip_set:
			if(geolite2.lookup(element) is None):
				country = "N/A"
			else:
				country = geolite2.lookup(element).country

			f2.write("IP ADDRESS: " + element + " --- COUNTRY: " + country + " --- HITS: " + str(client_ip_record[element][0]))
			f2.write("\n")

	with open(os.getcwd()+"/result/[3] IP Address Activity.txt", "w") as f3:
		for element in unique_client_ip_set:
			f3.write("\nIP ADDRESS: " + element + "\nTRANSACTION LIST:\n")
			for activity in client_ip_record[element][1:]:
				f3.write(activity.strip(' - ')+"\n")

	with open(os.getcwd()+"/result/[4] SQL Injection.txt", "w") as f4:
		f4.write("SQL INJECTION\n")
		for element in unique_client_ip_set:
			Flag = False
			for activity in client_ip_record[element][1:]:
				if(aq.detectSQLi(activity)):
					Flag = True
					f4.write("\nIP ADDRESS " + element + " --- REQUEST: ")
					f4.write(activity.strip(' - '))
			if(Flag):
				f4.write("\n")

	with open(os.getcwd()+"/result/[5] RFI.txt", "w") as f5:
		f5.write("REMOTE FILE INCLUSIONS\n")
		for element in unique_client_ip_set:
			Flag = False
			for activity in client_ip_record[element][1:]:
				if(aq.detectRFI(activity)):
					Flag = True
					f5.write("\nIP ADDRESS " + element + " --- REQUEST: ")
					f5.write(activity.strip(' - '))
			if(Flag):
				f5.write("\n")

	with open(os.getcwd()+"/result/[6] WEB SHELL.txt", "w") as f6:
		f6.write("WEB SHELL\n")
		for element in unique_client_ip_set:
			Flag = False
			for activity in client_ip_record[element][1:]:
				if(aq.detectWebShell(activity)):
					Flag = True
					f6.write("\nIP ADDRESS " + element + " --- REQUEST: ")
					f6.write(activity.strip(' - '))
			if(Flag):
				f6.write("\n")

##########################
if __name__ == '__main__':
	DefineVariable()