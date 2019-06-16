import pexpect


class CiscoModule:

    def __init__(self, s_ip, s_name, s_pwd, s_en_pwd, c_interface, m_timeout):
        self.switch_ip = s_ip
        self.switch_name = s_name
        self.switch_pwd = s_pwd
        self.switch_en_pwd = s_en_pwd
        self.connected_interface = c_interface
        self.monitor_timeout = m_timeout
        try:
            self.child = pexpect.spawn("ssh %s@%s" % (self.switch_name, self.switch_ip))
            self.child.timeout = 20
            self.child.expect('Password:')
            self.child.sendline(self.switch_pwd)
            self.child.expect('>')
            self.child.sendline('terminal length 0')
            self.child.expect('>')
            self.child.sendline('enable')
            self.child.expect('Password:')
            self.child.sendline(self.switch_en_pwd)
            self.child.expect('%s#' % self.switch_name)
        except (pexpect.EOF, pexpect.TIMEOUT) as e:
            print("%s\n\n>>>>>>>>>>>CONNECTION ERROR<<<<<<<<<<<\n\n" % e)
            self.child.close()

    def take_interfaces(self):
        self.child.sendline('show interfaces | i (.* line protocol is )|(.* address is)')
        self.child.expect('%s#' % self.switch_name)
        raw_port = self.child.before

        # Take Output from child.before or child.after

    def put_callback(self):
        # Event that will trigger after 300 sec that will close the monitor session
        self.child.sendline('configure terminal')
        self.child.expect('\(config\)#')
        self.child.sendline('event manager applet no-monitor-session')
        self.child.expect('\(config-applet\)#')
        self.child.sendline('event timer countdown time %s' % self.monitor_timeout)
        self.child.expect('\(config-applet\)#')
        self.child.sendline('action 01 cli command "enable"')
        self.child.expect('\(config-applet\)#')
        self.child.sendline('action 02 cli command "configure terminal"')
        self.child.expect('\(config-applet\)#')
        self.child.sendline('action 03 cli command "no monitor session 1"')
        self.child.expect('\(config-applet\)#')
        self.child.sendline('action 04 cli command "end"')
        self.child.expect('\(config-applet\)#')
        self.child.sendline('end')
        self.child.expect('%s#' % self.switch_name)

    def enable_monitor_mode(self):
        self.child.sendline('configure terminal')
        self.child.expect('\(config\)#')
        self.child.sendline('monitor session 1 source interface Gi0/0 - 3')
        self.child.expect('\(config\)#')
        self.child.sendline('monitor session 1 source interface Gi1/0 - 3')
        self.child.expect('\(config\)#')
        self.child.sendline('monitor session 1 source interface Gi2/0 - 3')
        self.child.expect('\(config\)#')
        self.child.sendline('monitor session 1 source interface Gi3/0 - 2')
        self.child.expect('\(config\)#')
        self.child.sendline(
            'monitor session 1 destination interface %s encapsulation replicate' % self.connected_interface)
        self.child.close()
