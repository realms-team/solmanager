#Sami connection fail recovery
import os
import datetime

MAX_ALLOWED_FAILS = 10   #after that, dust manager is reset

f = open('con_fails.log', 'r')
con_fails = int(f.readline())
print 'con_fails = ' + str(con_fails)
f.close()
if(con_fails >= MAX_ALLOWED_FAILS):
    print 'resetting Dust Manager...'
    os.system('screen -S serial -p 0 -X stuff "login user$printf \\rreset system$printf \\r"')
    lf = open('resets.log', 'a')
    lf.write(str(datetime.datetime.now())+': Dust reset at confails = ' + str(con_fails) + '\n')
    lf.close()
else:
    #testing
    #os.system('screen -S serial -p 0 -X stuff "login user$printf \\rsm$printf \\rtest2$printf \\r"')
    lf = open('resets.log', 'a')
    lf.write(str(datetime.datetime.now())+': Checked, good.\n')
    lf.close()
