import os.path as path
import os
import time
import datetime
#email

MAX_DELTA_S = 60 * 60   #max is 1 hour
DATA_DIR    = 'user_data'
DIR         = os.getcwd()+'/'+DATA_DIR+'/'
N = len(os.listdir(DIR))
print 'N files = ', N
if N > 0:
    i = 0
    for filename in os.listdir(DIR):
        tm = path.getmtime(DIR + filename)
        if (time.time() - tm) > MAX_DELTA_S:
            print filename, 'late'
            i+=1
        else:
            print filename, 'up to date, so aborting!'
            break
    if i >= N:
        print 'Manager not updating'
        print 'Sending q to solmanager'
        os.system('screen -S solmanager -p 0 -X stuff "login user$printf \\rq$printf \\r"')

