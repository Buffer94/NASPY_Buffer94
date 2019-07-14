import pexpect
import re
from NetworkElements import Switch
from NetworkElements import Port
import os


class CiscoSSH:

    def __init__(self, c_interface, m_timeout):
        self.connected_interface = c_interface
        self.monitor_timeout = m_timeout
        self.switch_interfaces = list()
        self.child = None
        self.switch = None

    def connect(self, ip, name, pwd, en_pwd):
        try:
            self.child = pexpect.spawn("ssh %s@%s" % (name, ip))
            self.child.timeout = 15
            self.child.expect('Password:')
            self.child.sendline(pwd)
            self.child.expect('>')
            self.child.sendline('terminal length 0')
            self.child.expect('>')
            self.child.sendline('enable')
            self.child.expect('Password:')
            self.child.sendline(en_pwd)
            self.child.expect('%s#' % name)
            print("Connected!")
            self.switch = Switch(name, ip, pwd, en_pwd, self.connected_interface)
        except pexpect.EOF as e:
            if "Host key verification failed." in str(self.child.before):
                print("Host key verification failed. Retring!")
                os.system('ssh-keygen -f "/root/.ssh/known_hosts" -R %s' % ip)
                self.connect_with_no_host_auth(ip, name, pwd, en_pwd)
            else:
                print("%s\n\n>>>>>>>>>>>CONNECTION ERROR<<<<<<<<<<<\n\n" % e)
        except pexpect.TIMEOUT as e:
            if "The authenticity of host" in str(self.child.before):
                self.connect_with_no_host_auth(ip, name, pwd, en_pwd)
            else:
                print("%s\n\n>>>>>>>>>>>CONNECTION ERROR<<<<<<<<<<<\n\n" % e)
                self.child.close()

    def connect_with_no_host_auth(self, ip, name, pwd, en_pwd):
        print("I'm trying to acknowledge the authenticity of the new host")
        try:
            self.child = pexpect.spawn("ssh %s@%s" % (name, ip))
            self.child.expect('The authenticity of host')
            self.child.sendline('yes')
            self.child.expect('Password:')
            self.child.sendline(pwd)
            self.child.expect('>')
            self.child.sendline('terminal length 0')
            self.child.expect('>')
            self.child.sendline('enable')
            self.child.expect('Password:')
            self.child.sendline(en_pwd)
            self.child.expect('%s#' % name)
            print("Connected!")
            self.switch = Switch(name, ip, pwd, en_pwd, self.connected_interface)
        except (pexpect.EOF, pexpect.TIMEOUT) as e:
            print("%s\n\n>>>>>>>>>>>CONNECTION ERROR<<<<<<<<<<<\n\n" % e)
            self.child.close()

    def reconnect(self, ip, name, pwd, en_pwd, c_interface, m_timeout):
        self.connected_interface = c_interface
        self.monitor_timeout = m_timeout
        attempts = 0
        connected = False
        while attempts < 20 and not connected:
            try:
                self.child = pexpect.spawn("ssh %s@%s" % (name, ip))
                self.child.timeout = 15
                self.child.expect('Password:')
                self.child.sendline(pwd)
                self.child.expect('>')
                self.child.sendline('terminal length 0')
                self.child.expect('>')
                self.child.sendline('enable')
                self.child.expect('Password:')
                self.child.sendline(en_pwd)
                self.child.expect('%s#' % name)
                connected = True
                print("Connected!")
                self.switch = Switch(name, ip, pwd, en_pwd, self.connected_interface)
            except (pexpect.EOF, pexpect.TIMEOUT) as e:
                if attempts < 20:
                    print("Attempt #%s failed! i'm triyng again!" % attempts)
                else:
                    print("%s\n\n>>>>>>>>>>>CONNECTION ERROR<<<<<<<<<<<\n\n" % e)
                self.child.close()
                attempts += 1

    def connect_with_attempts(self, ip, name, pwd, en_pwd, max_attempts):
        attempts = 0
        connected = False
        while attempts < max_attempts and not connected:
            try:
                self.child = pexpect.spawn("ssh %s@%s" % (name, ip))
                self.child.timeout = 15
                self.child.expect('Password:')
                self.child.sendline(pwd)
                self.child.expect('>')
                self.child.sendline('terminal length 0')
                self.child.expect('>')
                self.child.sendline('enable')
                self.child.expect('Password:')
                self.child.sendline(en_pwd)
                self.child.expect('%s#' % name)
                connected = True
                print("Connected!")
                self.switch = Switch(name, ip, pwd, en_pwd, self.connected_interface)
            except (pexpect.EOF, pexpect.TIMEOUT) as e:
                if attempts < max_attempts:
                    print("Attempt #%s failed! i'm triyng again!" % attempts)
                else:
                    print("%s\n\n>>>>>>>>>>>CONNECTION ERROR<<<<<<<<<<<\n\n" % e)
                self.child.close()
                attempts += 1

    def take_interfaces(self):
        self.child.sendline('show interfaces | i (.* line protocol is )|(.* address is)')
        self.child.expect('%s#' % self.switch.name)
        output = str(self.child.before)
        raw_port_name = re.findall('([^\\n]\w*[^0-9]\d\/\d\.*\d*)', output)
        raw_port_mac = re.findall('([a-fA-F0-9]{4}[.][a-fA-F0-9]{4}[.][a-fA-F0-9]{4})[^\)]', output)

        if len(raw_port_mac) == len(raw_port_name):
            dim = len(raw_port_name)
        else:
            if len(raw_port_mac) < len(raw_port_name):
                dim = len(raw_port_mac)
            else:
                dim = len(raw_port_name)

        for i in range(dim):
            name = raw_port_name[i].lstrip('\\n')
            mac_parts = raw_port_mac[i].split('.')
            mac = mac_parts[0][:2] + ':' + mac_parts[0][2:4] + ':' + mac_parts[1][:2] + ':' + \
                  mac_parts[1][2:4] + ':' + mac_parts[2][:2] + ':' + mac_parts[2][2:4]
            self.switch.add_ports(Port(name, mac))

            if name == self.connected_interface:
                self.switch.set_designated_port(mac)

            if name not in self.switch_interfaces:
                self.switch_interfaces.append(name)
        return self.switch

    def put_callback(self):
        print("I'm trying to enable the callback")
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
        self.child.sendline('action 05 cli command "exit"')
        self.child.expect('\(config-applet\)#')
        self.child.sendline('end')
        self.child.expect('%s#' % self.switch.name)
        print("Finished!")

    def enable_monitor_mode(self):
        try:
            self.clear_vty_line()
            self.put_callback()
            print("Enabling monitor mode...")
            self.child.sendline('configure terminal')
            self.child.expect('\(config\)#')

            for interface in self.switch_interfaces:
                if interface != self.connected_interface:
                    self.child.sendline('monitor session 1 source interface %s' % interface)
                    self.child.expect('\(config\)#')

            self.child.sendline(
                'monitor session 1 destination interface %s encapsulation replicate' % self.connected_interface)
            self.child.expect('\(config\)#')
            self.child.close()
        except (pexpect.EOF, pexpect.TIMEOUT) as e:
            print("Connection Closed!")

    def enable_monitor_mode_on_interface_range(self, interfaces):
        try:
            self.clear_vty_line()
            self.put_callback()
            print("Enabling monitor mode...")
            self.child.sendline('configure terminal')
            self.child.expect('\(config\)#')

            for interface in interfaces:
                if interface != self.connected_interface:
                    self.child.sendline('monitor session 1 source interface %s' % interface)
                    self.child.expect('\(config\)#')

            self.child.sendline(
                'monitor session 1 destination interface %s encapsulation replicate' % self.connected_interface)
            self.child.expect('\(config\)#')
        except (pexpect.EOF, pexpect.TIMEOUT):
            print("Connection Closed!")
        self.child.close()

    def enable_monitor_mode_on_specific_port(self, port_name):
        try:
            self.clear_vty_line()
            self.put_callback()
            print("Enabling monitor mode...")
            self.child.timeout = 5
            self.child.sendline('configure terminal')
            self.child.expect('\(config\)#')
            self.child.sendline('monitor session 1 source interface %s' % port_name)
            self.child.expect('\(config\)#')
            self.child.sendline(
                'monitor session 1 destination interface %s encapsulation replicate' % self.connected_interface)
            self.child.expect('\(config\)#')
        except (pexpect.EOF, pexpect.TIMEOUT):
            print("Connection Closed!")
        self.child.close()

    def clear_vty_line(self):
        print("Clearing vty lines")
        for i in range(5):
            self.child.sendline('clear line vty %s' % i)
            self.child.expect('[confirm]')
            self.child.sendline('\n')
            self.child.expect('%s#' % self.switch.name)
        print("Done!")
