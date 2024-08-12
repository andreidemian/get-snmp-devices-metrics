from lib.snmpCyberPower import upsCyberPower
from subprocess import Popen, PIPE
import sys
import os


# SSH Configuration
SSH_HOST = '192.168.1.1'
SSH_USER = 'user'
SSH_KEY = '/path/to/key'

# UPS SNMP Configuration
UPS_SNMP_HOST = '192.168.1.142'
UPS_SNMP_COMMUNITY = 'public'


# example of power off host
def power_off_host(ssh_host=None, ssh_user=None, ssh_key=None):

    cmd = "poweroff"

    if(ssh_host):
        if(os.isfile(ssh_key)):
            cmd = f"ssh -i {ssh_key} {ssh_user}@{ssh_host} {cmd}"
        else:
            sys.exit(f"Error: SSH Key {ssh_key} not found")

    rp = Popen(cmd,shell=True,stdout=PIPE,stderr=PIPE)
    if(rp.returncode == 0):
        return True
    return False

# example class usage
if __name__ == "__main__":


    ups = upsCyberPower(UPS_SNMP_HOST, UPS_SNMP_COMMUNITY)

    if(ups.get_baseOutputStatus[0] == 3 and ups.get_batteryChargePercentage < 40):
        print("UPS is on battery and battery charge is less than 40%")
        #if power_off_host(ssh_host=SSH_HOST, ssh_user=SSH_USER, ssh_key=SSH_KEY):
        #    print("Host is shutting down")
        #else:
        #    print("Error shutting down host")

    print(f"Name: {ups.get_name}")
    print(f"Description: {ups.get_description}")
    print(f"Contact: {ups.get_contact}")
    print(f"Location: {ups.get_location}")
    print(f"UPS Temperature: {ups.get_upsTemperature}")
    print(f"Temperature: {ups.get_envTemp}")
    print(f"Humidity: {ups.get_envHumidity}")
    print(f"Battery Charge Percentage: {ups.get_batteryChargePercentage}")
    print(f"Input Voltage: {ups.get_inputVoltage}")
    print(f"Input Frequency: {ups.get_inputFrequency}")
    print(f"Output Voltage: {ups.get_outputVoltage}")
    print(f"Output Frequency: {ups.get_outputFrequency}")
    print(f"Output Current: {ups.get_outputCurrent}")
    print(f"UPS State: {ups.get_baseOutputStatus}")
    print(f"Input Transfer Reason: {ups.get_inputTransferReason}")
    print(f"Battery Replace: {ups.get_batteryReplace}")
    print(f"Battery Status: {ups.get_batteryStatus}")
    print(f"Input Status: {ups.get_inputStatus}")
    print(f"Output Battery Voltage: {ups.get_outputBatteryVoltage}")
    print(f"Load Percentage: {ups.get_loadPercentage}")
    print(f"Battery Runtime: {ups.get_batteryRuntime}")
