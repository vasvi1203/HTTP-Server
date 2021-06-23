from socket import *
import sys
import os
from copy import *
import threading
from datetime import *
import calendar
import pytz
import mimetypes
import email
import http.client
import uuid
import base64
from config import *

class Cookie:
	def __init__(self):
		self.name = 'cookie'
		self.value = uuid.uuid1() #generates unique id


class HTTPRequest():
	def __init__(self, data):
		self.method = None  # get, post etc
		try:
			self.data = data.decode()
		except:
			self.data = str(email.message_from_bytes(data))
		self.original_data = data
		self.headers = dict()  # content_length etc
		self.uri = "index.html"  # /index.html
		self.version = VERSION
		self.parse(self.data)


	def parse(self, data):
		self.data = data.strip()
		try:
			words = self.data.split()
			self.method = words[0]
			try:
				self.uri = words[1]
			except:
				pass
			try:
				self.version = words[2]
			except:
				pass
		except:
			self.method = data


class HTTPServer():
	def __init__(self):
		self.monthDict = {1:"Jan", 2:"Feb", 3:"Mar", 4:"Apr", 5:"May", 6:"Jun", 7:"Jul", 8:"Aug", 9:"Sep", 10:"Oct", 11:"Nov", 12:"Dec"}
		self.status_codes = http.client.responses
		self.client = None
		self.clientAddress = None
		self.dateHeader = self.getDate()
		self.headers = {
			"Date" : self.dateHeader,
			"Server" : "VV's Server",
			"Content-Type" : "text/html",
			"Connection" : "close"
			}
		self.logFile = LOGFILE
		self.default_directory = 'uploads'
		self.postdir = POST_DIR
		self.cookielist = {}
    


	def sendCookie(self):
		if(self.clientAddress not in self.cookielist):
			c = Cookie()
			s = f"{c.name}={c.value}"
			self.cookielist[self.clientAddress] = c.value
			return s


	def allHeaders(self, extraHeaders = None):
		headersCopy = deepcopy(self.headers)
		if extraHeaders:
			headersCopy.update(extraHeaders)
		headers = ""
		for header in headersCopy:
			headers += "{}: {}\r\n".format(header, headersCopy[header])
		return headers


	def errorHeaders(self, responseLine, error):
		headers = self.allHeaders()
		headers += "\r\n"
		responseBody = "<head><title>{} {}</title></head><body><h1>{} {}</h1><p>Your browser sent a request that this server could not understand.<br /></p><hr><address>Apache/2.4.41 (Ubuntu) Server at 127.0.1.1 Port 12345</address></body>".format(
			error, self.status_codes[error], error, self.status_codes[error])
		self.client.send((responseLine + headers + responseBody).encode())


	def getDate(self):
		date_time = datetime.now(pytz.timezone("GMT"))
		year = date_time.year
		month = self.monthDict[date_time.month]
		date = str(date_time.day).zfill(2)
		hour = str(date_time.hour).zfill(2)
		minute = str(date_time.minute).zfill(2)
		second = str(date_time.second).zfill(2)

		today = "{} {} {}".format(date, date_time.month, year)
		day = datetime.strptime(today, "%d %m %Y").weekday()
		dateHeader = "{}, {} {} {} {}:{}:{} GMT".format((calendar.day_name[day])[:3], date, month, year, hour, minute, second)
		return dateHeader


	def parseDate(self, header, filename):
		x = datetime.strptime(header, '%a, %d %b %Y %H:%M:%S GMT')
		t = os.path.getmtime(filename) 		# last date of file modification
		return datetime.fromtimestamp(t) > x, datetime.fromtimestamp(t)


	def GETMethod(self, request):
		filename = request.uri.strip('/')
		lines = request.data.split("\r\n")
		request_line = lines[0]
		h = self.splitRequest(lines)
		c = self.CHECKDir(filename)

		if(not c and os.path.exists(filename)):
			r = os.access(filename, os.R_OK) # Check for read access
			if(not r):
				responseLine = self.responseLine(request, 403)
				self.errorHeaders(responseLine, 403)
				return
		elif(c and os.path.exists(filename)):
			print(os.listdir(filename))
			responseLine = self.responseLine(request, 415)
			self.errorHeaders(responseLine, 415)  #unsupported media
			return
		try:
			host = h['Host']
		except:
			host = ''
		extraHeaders = {}
		statusCode = 400
		#log format: host date request_line status_code bytes
		if os.path.exists(filename):
			if('If-Modified-Since' in h):
				c,d = self.parseDate(h['If-Modified-Since'], filename)
				if(c): #file is modified
					statusCode = 200
					contentType = mimetypes.guess_type(filename)[0] or 'text/html'
					extraHeaders = {
					"Content-Type" : contentType,
					"Content-Length" : os.path.getsize(filename),
					}
					htmlFile = open(filename, 'rb')
				else:
					statusCode = 304
					extraHeaders['Last-Modified'] = d
					extraHeaders['Content-Length'] = 0
			else:
				statusCode = 200
				contentType = mimetypes.guess_type(filename)[0] or 'text/html'
				extraHeaders = {
				"Content-Type" : contentType,
				"Content-Length" : os.path.getsize(filename),
				}
				htmlFile = open(filename, 'rb')
			responseLine = self.responseLine(request, statusCode)
			s = self.sendCookie()
			if(s != None):
				extraHeaders['Set-Cookie'] = s
			headers = self.allHeaders(extraHeaders)
			headers += "\r\n"
			self.client.send((responseLine + headers).encode())
			try:
				self.client.sendfile(htmlFile)
				htmlFile.close()
			except:
				pass
			f = open(self.logFile, "a")
			s = "{} {} {} 200 {}\n".format(host, self.dateHeader, request_line, extraHeaders["Content-Length"])
			f.write(s)
			f.close()

		else:
			responseLine = self.responseLine(request, 404)
			statusCode = 404
			self.errorHeaders(responseLine, 404)


	def HEADMethod(self, request):
		filename = request.uri.strip('/')
		lines = request.data.split("\r\n")
		request_line = lines[0]
		h = self.splitRequest(lines)
		c = self.CHECKDir(filename)
		if(not c and os.path.exists(filename)):
			r = os.access(filename, os.R_OK) # Check for read access
			if(not r):
				responseLine = self.responseLine(request, 403)
				self.errorHeaders(responseLine, 403)
				return
		elif(c and os.path.exists(filename)):
			print(os.listdir(filename))
			responseLine = self.responseLine(request, 415)
			self.errorHeaders(responseLine, 415)  #unsupported media
			return
		try:
			host = h['Host']
		except:
			host = ''
		extraHeaders = {}
		statusCode = 400
		#log format: host date request_line status_code bytes
		if os.path.exists(filename):
			if('If-Modified-Since' in h):
				c,d = self.parseDate(h['If-Modified-Since'], filename)
				if(c): #file is modified
					statusCode = 200
					contentType = mimetypes.guess_type(filename)[0] or 'text/html'
					extraHeaders = {
					"Content-Type" : contentType,
					"Content-Length" : os.path.getsize(filename),
					}
					htmlFile = open(filename, 'rb')
				else:
					statusCode = 304
					extraHeaders['Last-Modified'] = d
					extraHeaders['Content-Length'] = 0
			else:
				statusCode = 200
				contentType = mimetypes.guess_type(filename)[0] or 'text/html'
				extraHeaders = {
				"Content-Type" : contentType,
				"Content-Length" : os.path.getsize(filename),
				}
				htmlFile = open(filename, 'rb')
			responseLine = self.responseLine(request, statusCode)
			s = self.sendCookie()
			if(s != None):
				extraHeaders['Set-Cookie'] = s
			headers = self.allHeaders(extraHeaders)
			headers += "\r\n"

			contentType = mimetypes.guess_type(filename)[0] or 'text.html'
			extraHeaders = {
				"Content-Type" : contentType,
				"Content-Length" : os.path.getsize(filename)
			}
			headers = self.allHeaders(extraHeaders)
			headers += "\r\n"
			self.client.send((responseLine + headers).encode())

			f = open(self.logFile, "a")
			s = "{} {} {} 200 {}\n".format(host, self.dateHeader, request_line, extraHeaders["Content-Length"])
			f.write(s)
			f.close()

		else:
			responseLine = self.responseLine(request, 404)
			statusCode = 404
			self.errorHeaders(responseLine, 404)

	def POSTMethod(self, request):
		blank_line = "\r\n"
		extra_headers = {}
		special_characters = {'%21': '!', '%23': '#', '%24': '$', '%25': '%', '%26': '&', '%27': "'", '%28': '(', '%29': ')', '%2A': '*','%2B': '+', '%2C': ',', "%2F": '/', '%3A': ':', '%3B': ';', '%3D': '=', '%3F': '?', '%40': '@', '%5B': '[', '%5D': ']'}
		words = [i.strip("\r") for i in request.data.split("\n")]
		lines = request.data.split("\r\n")
		if(len(lines) == 1):
			lines = request.data.split("\n")
			request_line = lines[0]
			filename = request.uri.strip('/')
			if(not os.path.exists(filename)):
				responseLine = self.responseLine(request, 404)
				statusCode = 404
				self.errorHeaders(responseLine, 404)
				return
			h = self.splitRequest(lines)
			try:
				host = h['Host']
			except:
				host = ''
			for x in words:
				y = [i.strip(" ") for i in x.split(":", 1)]
				if(len(y) > 1 and y[0] == 'Content-Type'):
					extra_headers[y[0]] = y[1] #dont add all request headers in response headers
					break
			extra_headers["Cache-Control"] = "No-Store"
			s = self.sendCookie()
			if(s != None):
				extra_headers['Set-Cookie'] = s
			try:
				if(extra_headers['Content-Type'] == "application/x-www-form-urlencoded"):
					field_values = words[-1]
					#converting the percent encoded data into text data
					for i in special_characters:
						if(i in field_values):
							field_values = field_values.replace(i, special_characters[i])
					keys_values = field_values.split("&")
					data_dict = {}
					for i in keys_values:
						x = i.split("=")
						if(len(x) > 1):
							if('+' in x[1]):
								x[1] = x[1].replace('+', ' ')
							data_dict[x[0]] = x[1]
						else:
							data_dict[x[0]] = ''
					data = ""

				
					for i in data_dict:
						data += i + ": " + data_dict[i] + "\r\n"
					response_headers = self.allHeaders(extra_headers)
					if os.path.exists(filename):
						#if resource is created then send 201 else 200
						status_code = 200
						response_line = self.responseLine(request, 200)
						content_type = mimetypes.guess_type(filename)[0] or 'text/html'
						extra_headers["Content-Type"] = content_type
						extra_headers["Content-Length"] = os.path.getsize(filename)
						response_headers = self.allHeaders(extra_headers)
						f = open(self.logFile, "a")
						s = host + ' ' + self.dateHeader + ' ' + request_line + ' ' + str(status_code) + ' ' + str(extra_headers["Content-Length"])+'\n'
						f.write(s)
						f.close()
						f = open(self.postdir + '/' + POST_DATA, 'a')
						f.write(data)
						f.close()
					
				
					self.client.send(response_line.encode() +
									response_headers.encode() + blank_line.encode())
					try:
						f = open(filename, 'rb')
						self.client.sendfile(f)
					except:
						pass
					
			except:
				pass
			else:
				status_code = 200
				#find first occurence of boundary
				b = request.original_data.find(b"boundary")
				#find first occurence of \n after boundary so as to get the boundary eg. ---------------122334354535\n
				n = request.original_data.find(b"\n", b)
				b = b + 9  # ignoring boundary=
				boundary = request.original_data[b:n]
				# returns index of first occurence of Content-Disposition
				i = request.original_data.find(b"Content-Disposition")
				content = request.original_data[i:]
				words = content.rstrip(b'\n\r\n' + b'--' + boundary + b'--\r\n').split(b'--' + boundary) #remving the last line and then splitting
				
				#for each word in words
				#check for name and value stored in it eg.name="fname" value=?
				#If after name there is no filename then value is stored in the form of \n\nvalue\n
				data_dict = {}
				hashm = {}
				
				for w in range(len(words)):
					words[w] = words[w].replace(
						b'Content-Disposition: form-data;', b'')
					words[w] = words[w].lstrip(b'\n name="')
					if(b"Content-Type" in words[w]):
						# stores the location of string containing filename
						hashm[w] = 1
				for w in range(len(words)):
					name = b""
					i = 0
					while(i < len(words[w]) and words[w][i] != 34):
						i = i + 1
					name = name + (words[w][:i])
						#4 for \r\n\r\n
					if w not in hashm:
						value = words[w][i+1 + 4: -2]
						data_dict[name] = value
					else:
						#for files
						#i points to ", i + 1 to ;
						c = i + 13
						init = c
						filen = b""
						while(words[w][c] != 34):
							c = c + 1
						filen += words[w][init:c]
						#print(filen)
						if(len(filen) > 0):
							i = words[w].find(b'\r\n\r\n', c) #after Content-Type header
							i = i + 4
							data_in_file = words[w][i:]
							#print(len(data_in_file))
							#how to append file data
							f = open(self.postdir + '/' + filen.decode(), 'wb')
							f.write(data_in_file)
							f.close()
							
							
				if os.path.exists(filename): #for all the data inside the form accept for files
					#if resource is created then send 201 else 200
					data = b""
					#print(data_dict)
					for i in data_dict:
						data += i + b": " + data_dict[i] + b"\r\n"
					response_line = self.responseLine(request, 200)
					content_type = mimetypes.guess_type(filename)[0] or 'text/html'
					extra_headers["Content-Type"] = content_type
					extra_headers["Content-Length"] = os.path.getsize(filename)
					response_headers = self.allHeaders(extra_headers)
					print("This is post logfile")
					f = open(self.logFile, "a")
					s = "{} {} {} 200 {}\n".format(host, self.dateHeader, request_line, extra_headers["Content-Length"])
					f.write(s)
					f.close()
					f = open(self.postdir + '/' + + POST_DATA, 'a')
					f.write(data.decode())
					f.close()
				else:
					response_line = self.responseLine(request, 404)
					response_headers = self.allHeaders()
					response_body = "<h1>404 Not Found</h1>"
				self.client.send(response_line.encode() + response_headers.encode() + blank_line.encode())
				try:
					f = open(filename, 'rb')
					self.client.sendfile(f)
					f.close()
				except:
					pass
	def PUTMethod(self, request):
		filename = request.uri.strip('/')
		lines = request.data.split("\r\n")
		request_line = lines[0]
		if(len(lines) == 1):
			lines = request.data.split("\n")
			request_line = lines[0]

		h = self.splitRequest(lines)
		try:
			host = h['Host']
		except:
			host = ''
		#if filename is a file
		d = self.CHECKDir(filename)
		extraHeaders = {}
		blank_line = '\r\n'

		s = self.sendCookie()
		if(s != None):
			extraHeaders['Set-Cookie'] = s
		flag = 0
		if( not d):
			i = (request.original_data).find(b'\r\n\r\n') #for getting the actual data appended
			if(not os.path.exists(self.default_directory)):
				os.mkdir(self.default_directory)
			p = self.default_directory + '/' + filename
			per= self.CHECKPermission(p)
			if(per == None):
				per = True
			if(os.path.exists(p)):
				statusCode = 200
			else:
				statusCode = 201 #created
			extraHeaders["Content-Location"] = p
			extraHeaders["Cache-Control"] = "No-Store"

			if(per):
				try:
					if(i != -1):
						f = open(p, 'wb')
						f.truncate(0)
						c = request.original_data[i+4:]
						start = i + 4
						while(start < len(request.original_data)):
							y = start
							flag = 0
							while(y < len(request.original_data) and (request.original_data[y]) > 127):
								y = y + 1
								flag = 1
							if(flag == 1):
								f.write(request.original_data[start:y])
							start = y
							while(y < len(request.original_data) and (request.original_data[y]) <= 127):
								y = y + 1
								flag = 0
							if(flag == 0):
								f.write(request.original_data[start:y])
							start = y
						f.close()
					else:
						for x in range(len(request.original_data)):
							if((request.original_data[x]) > 127):
								break
						f = open(p, 'wb')
						f.truncate(0)
						f.write(request.original_data[x:])
						f.close()
					response_body = "<h1>Success</h1>"
				except:
					statusCode = 400
					response_body = "<h1>Bad Request</h1>"
			else:
				statusCode = 403
				response_body = "<h1>Forbidden</h1>"

			response_line = self.responseLine(request, statusCode)
			response_headers = self.allHeaders(extraHeaders)
			self.client.send(response_line.encode() + response_headers.encode() + blank_line.encode())
			f = open(self.logFile, "a")
			s = host + ' ' + self.dateHeader + ' ' + request_line + ' ' + str(statusCode) + ' ' + ' 0 ' +'\n'
			f.write(s)


	def DELETEMethod(self, request):
		lines = request.data.split('\r\n')
		filename = request.uri.strip('/')
		request_line = lines[0]
		h = self.splitRequest(lines)

		try:
			host = h['Host']
		except:
			host = ''
		extraHeaders = {}
		blank_line = '\r\n'
		isdir = self.CHECKDir(filename)
		s = self.sendCookie()
		if(s != None):
			extraHeaders['Set-Cookie'] = s
		if(isdir):
			response_line = self.responseLine(request, 405)
			response_headers = self.allHeaders()
			response_body = "<h1>405 Not Allowed</h1>"
			self.client.send(response_line.encode() +
							response_headers.encode() + blank_line.encode())
			return

		if(not os.path.exists(filename)):
			response_line = self.responseLine(request, 404)
			response_headers = self.allHeaders()
			response_body = "<h1>404 Not Found</h1>"
			self.client.send(response_line.encode() +
							response_headers.encode() + blank_line.encode())
			return
		h = {}
		for i in range(1, len(lines)):
			line = lines[i].split(':')
			h[line[0]] = line[1][1:]
		try:
			host = h['Host']
		except:
			host = ''
		if('Authorization' in h):
			string = h['Authorization'].lstrip('Basic ')
			x = base64.decodebytes(string.encode()).decode()
			u = x.split(':')
			username = u[0]
			password = u[1]

			if(username == USERNAME and password == PASSWORD):
				p = self.CHECKPermission(filename)
				if(p):
					os.remove(filename)
					statusCode = 204
				else:
					statusCode = 403
					response_body = "<h1>Forbidden</h1>"
					print('No permission')


			else:
				statusCode = 401
				response_body = "<h1>Unauthorized</h1>"
				extraHeaders["WWW-Authenticate: "] = 'Basic , charset="UTF-8"'
		else:
			statusCode = 401
			response_body = "<h1>Unauthorized</h1>"
			extraHeaders["WWW-Authenticate: "] = 'Basic , charset="UTF-8"'
		#extraHeaders['Connection'] = 'close'
		self.finish(request, statusCode, extraHeaders, host)


	def finish(self, request, statusCode, extraHeaders, host):
		blank_line = '\r\n'
		response_line = self.responseLine(request, statusCode)
		response_headers = self.allHeaders(extraHeaders)
		self.client.send(response_line.encode() + response_headers.encode() + blank_line.encode())
		lines = request.data.split("\r\n")
		request_line = lines[0]
		f = open(self.logFile, "a")
		print('host', host, 'date', self.dateHeader)
		s = host + ' ' + self.dateHeader + ' ' + request_line + ' ' + str(statusCode) + ' ' + ' 0 ' +'\n'
		f.write(s)


	def CHECKDir(self, filename):
		return os.path.isdir(filename)


	def CHECKPermission(self, p):
		if(os.path.exists(p)):
			r = os.access(p, os.R_OK) # Check for read access
			w = os.access(p, os.W_OK)
			return r and w


	def splitRequest(self,lines):
		h = {}
		for i in range(1, len(lines)):
			line = lines[i].split(':', 1)
			if(len(line) > 1):
				h[line[0]] = line[1][1:]
		return h


	def responseLine(self, request, statusCode):
		return "{} {} {}\r\n".format(request.version, statusCode, self.status_codes[statusCode])


	def receiveRequest(self, client, clientAddress):
		self.client = client
		self.clientAddress = clientAddress[0]
		data = b''
		flag = 1
		length = 0
		c = 0
		i = 0
		while True:
			p = self.client.recv(SIZE) # considering sum of the request line and ALL header fields is <= SIZE
			data += p
			if(b'Content-Length: ' in p and flag == 1):
				i = data.find(b'Content-Length: ')
				e = data.find(b'\r\n', i)
				length = int(data[i + 16: e].decode()) # length of entity body
				flag = 0
				c = c + 1
				i = data.find(b'\r\n\r\n') # first occurence of \r\n\r\n marks the start of entity body
				if(i != -1):
					i = i + 4  # 4 for \r\n\r\n
				length = length + i

			elif(flag == 1 and len(data) < SIZE): # for head and get
				break

			if(len(data) >= length):
				break

		request = HTTPRequest(data)

		# if no file name given
		if "HTTP/" in request.uri:
			responseLine = self.responseLine(request, 400)
			self.errorHeaders(responseLine, 400)
			return

		if request.method == "GET":
			self.GETMethod(request)

		elif request.method == "HEAD":
			self.HEADMethod(request)

		elif request.method == 'POST':
			self.POSTMethod(request)

		elif request.method == "PUT":
			self.PUTMethod(request)

		elif(request.method == "DELETE"):
			self.DELETEMethod(request)

		else:
			responseLine = self.responseLine(request, 501)
			self.errorHeaders(responseLine, 501)

		self.client.close()


class TCPServer():
	def __init__(self, ipAddress = '127.0.0.1', portNo = 1300):
		self.ipAddress = ipAddress
		self.portNo = portNo


	def createSocket(self):
		server = socket(AF_INET, SOCK_STREAM)
		server.bind((self.ipAddress, self.portNo))
		server.listen(10)
		print("TCP Server connected.....")
		httpServer = HTTPServer()
		while True:
			client, clientAddress = server.accept()
			print("Connection socket is: \n", clientAddress)
			threading.Thread(target = httpServer.receiveRequest, args = (client, clientAddress,)).start()


if __name__ == '__main__':
	if len(sys.argv) != 2:
		print("Usage : python3 get.py <port-no>")
		sys.exit()

	ipAddress = ''
	portNo = int(sys.argv[1])

	server = TCPServer(ipAddress, portNo)
	server.createSocket()
