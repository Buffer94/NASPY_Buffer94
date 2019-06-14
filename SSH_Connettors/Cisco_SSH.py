import pexpect
import sys

switch_ip = "10.0.0.102"
switch_name = "switch2"
switch_pwd = "ciki"
switch_en_pwd = "ciki"

try:
    try:
        child = pexpect.spawn("ssh %s@%s" % (switch_name, switch_ip))
        child.timeout = 20
        child.expect('Password:')
        # if verbose:
        #     child.logfile = sys.stdout
    except pexpect.TIMEOUT:
        raise Exception("Couldn't log to the Switch")

    child.sendline(switch_pwd)
    child.expect('>')
    child.sendline('terminal lenght 0')
    child.expect('>')
    child.sendline('enable')
    child.expect('Password:')
    child.sendline(switch_en_pwd)
    child.expect('%s#' % switch_name)
    child.sendline('show ip interface brief')
    child.expect('%s#' % switch_name)
    #Take Output from child.before or child.after
    child.sendline('configure terminal')
    child.expect('\(config\)#')

    #Event that will trigger 300 seconds upon now that will close the monitor session
    child.sendline('event manager applet no-monitor-session')
    child.expect('\(config-applet\)#')
    child.sendline('event timer countdown time 300')
    child.expect('\(config-applet\)#')
    child.sendline('action 01 cli command \"configure terminal\"')
    child.expect('\(config-applet\)#')
    child.sendline('action 02 cli command \"no monitor session 1\"')
    child.expect('\(config-applet\)#')
    child.sendline('action 03 cli command \"end\"')
    child.expect('\(config-applet\)#')
    child.sendline('exit')

    child.expect('\(config\)#')
    child.sendline('monitor session 1 destination interface GigabitEthernet 3/3 encapsulation replicate')
    child.expect('\(config\)#')
    child.sendline('monitor session 1 source interface GigabitEthernet 0/0 - 3 , GigabitEthernet 1/0 - 3 , GigabitEthernet 2/0 - 3 , GigabitEthernet 3/0 - 2')
    child.expect('\(config\)#')
    child.sendline('end')
    child.expect('%s#' % switch_name)

    #Close connection
    child.close()

except (pexpect.EOF, pexpect.TIMEOUT) as e:
    raise Exception("Couldn't connect to the Switch")
