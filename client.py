from threading import *
import requests
import webbrowser, os, sys
from _thread import *
from requests.auth import HTTPBasicAuth 
import time

def get():
    webbrowser.open_new_tab(base_url + 'testfiles/hci.pdf')
    webbrowser.open_new_tab(base_url + 'testfiles/diagram.png')
    webbrowser.open_new_tab(base_url + 'testfiles/form.html')
    webbrowser.open_new_tab(base_url + 'testfiles/movie.mp4')
    headers = {'If-Modified-Since': 'Thu, 09 Oct 2020 17:15:00 GMT'}
    response = requests.get(base_url + 'testfiles/form.html', headers=headers)
    print('CONDITIONAL GET:',response, response.headers)
    headers = {'If-Modified-Since': 'Thu, 11 Nov 2020 17:15:00 GMT'}
    response = requests.get(base_url + 'testfiles/form.html', headers=headers)
    print('CONDITIONAL GET:',response, response.headers)
  
def delete():
    r = requests.delete(base_url + 'testfiles/delete1.txt', ) #no authentication
    print('DELETE:',r,r.headers)
    r = requests.delete(base_url + 'testfiles/delete1.txt', auth = HTTPBasicAuth('VAISH', 'vaish81') ) #wrong authentication
    print('DELETE:',r,r.headers)
    r = requests.delete(base_url + 'testfiles/delete1.txt', auth = HTTPBasicAuth('Vasvi', 'vaish') ) #correct authentication
    print('DELETE:',r,r.headers)
    r = requests.delete(base_url + 'testfiles/permission.txt', auth = HTTPBasicAuth('Vasvi', 'vaish') ) #no permission
    print('DELETE:',r,r.headers)

def put():
    with open('testfiles/diagram.png', 'rb') as f:               #image file
        r = requests.put(base_url + 'putreq', data = f)
    print('PUT: ',r, r.headers)
    with open('testfiles/http', 'rb') as f:                      #text file
        r = requests.put(base_url + 'http', data = f)
    print('PUT: ',r, r.headers)
    with open('testfiles/post.txt', 'rb') as f:                  #no permission
        r = requests.put(base_url + 'permission.txt', data = f)
    print('PUT: permission',r, r.headers)
    with open('testfiles/1kb.jpg', 'rb') as f:                    #overwriting file
        r = requests.put(base_url + 'putreq', data = f)
    print('PUT: ',r, r.headers)

def head():
    print("Inside head")
    r = requests.head(base_url + 'testfiles/hci.pdf')
    print("head: ", r.headers)
    r = requests.head(base_url + 'testfiles/movie.mp4')
    print("head: ", r.headers)
    r = requests.head(base_url + 'testsfiles/hello.html')
    print("head: ", r.headers)

host = "127.0.0.1"
if(len(sys.argv) != 2):
    print("Please enter data in this format: filename port_number username")
    exit()
port = int(sys.argv[1])
base_url = 'http://' + host + ':' + str(port) + '/'

thread1 = Thread(target = get, args = ())
thread2 = Thread(target = delete, args = ()) 
thread4 = Thread(target = put, args=())
thread3 = Thread(target = head, args = ())
thread1.start() 
time.sleep(5)
thread2.start()
time.sleep(5)
thread4.start()
time.sleep(5)
thread3.start()
thread1.join()
thread2.join()
thread4.join()
thread3.join()


