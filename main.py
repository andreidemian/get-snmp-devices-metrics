from upsSNMP.ups import upsCyberPower, upsAPC
from subprocess import Popen, PIPE
import sys
import os

### SSH Configuration
# ssh host address
SSH_HOST = '192.168.1.2'
# ssh user
SSH_USER = 'user'
# ssh key
SSH_KEY = '/path/to/key'

### UPS SNMP Configuration
# ups snmp host address
UPS_SNMP_HOST = '192.168.111.143'
# ups snmp community
UPS_SNMP_COMMUNITY = 'public'
# ups snmp user
UPS_SNMP_USER = 'ups'
# ups snmp authkey
UPS_SNMP_AUTHKEY = 'jSjej92nJQnsdif94k12khj589jksS'
# ups snmp privkey
UPS_SNMP_PRIVKEY = 'jSjej92nJQnsdif94k12khj589jksS'

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

    #ups = upsCyberPower(ip=UPS_SNMP_HOST, community=UPS_SNMP_COMMUNITY, snmpv=1)

    #ups = upsCyberPower(ip=UPS_SNMP_HOST, user=UPS_SNMP_USER, authkey=UPS_SNMP_AUTHKEY, privkey=UPS_SNMP_PRIVKEY, snmpv=3)

    ups = upsAPC(ip=UPS_SNMP_HOST, community=UPS_SNMP_COMMUNITY, snmpv=2)

    # APC UPS
    print(f"Name: {ups.get_name}")
    print(f"Model: {ups.get_model}")
    print(f"Contact: {ups.get_contact}")
    print(f"Location: {ups.get_location}")

    print(f"Tempature environment: {ups.get_uioEnvTempP1}")

    print(f"UPS Battery Temperature: {ups.get_batteryTemperature}")
    print(f"Battery Charge Percentage: {ups.get_batteryChargePercentage}")
    print(f"Battery Replace: {ups.get_batteryReplace}")
    print(f"Battery Status: {ups.get_batteryStatus}")
    print(f"Battery Runtime: {ups.get_batteryRuntime}")
    print(f"Output Battery Voltage: {ups.get_batteryVoltage}")

    print(f"Input Voltage: {ups.get_inputVoltage}")
    print(f"Input Frequency: {ups.get_inputFrequency}")
    print(f"Input Line Fail Cause {ups.get_inputLineFailCause}")
    
    print(f"Output Voltage: {ups.get_outputVoltage}")
    print(f"Output Frequency: {ups.get_outputFrequency}")
    print(f"Output Current: {ups.get_outputCurrent}")
    print(f"baseOutputStatus: {ups.get_baseOutputStatus}")

    print(f"Load Percentage: {ups.get_loadPercentage}")
    

    print("="*50)


    upcCP = upsCyberPower(ip='192.168.111.142', community='public', snmpv=2)

    # CyberPower UPS
    print(f"Name: {upcCP.get_name}")
    print(f"Model: {upcCP.get_model}")
    print(f"Contact: {upcCP.get_contact}")
    print(f"Location: {upcCP.get_location}")

    print(f"UPS Temperature: {upcCP.get_upsTemperature}")
    print(f"Environment Temperature: {upcCP.get_envTemp}")
    print(f"Environment Humidity: {upcCP.get_envHumidity}")

    print(f"Battery Charge Percentage: {upcCP.get_batteryChargePercentage}")
    print(f"Battery Runtime: {upcCP.get_batteryRuntime}")
    print(f"Battery Voltage: {upcCP.get_batteryVoltage}")
    print(f"Battery Status: {upcCP.get_batteryStatus}")

    print(f"Input Voltage: {upcCP.get_inputVoltage}")
    print(f"Input Frequency: {upcCP.get_inputFrequency}")
    print(f"Input Line Fail Cause {upcCP.get_inputLineFailCause}")

    print(f"Output Voltage: {upcCP.get_outputVoltage}")
    print(f"Output Frequency: {upcCP.get_outputFrequency}")
    print(f"Output Current: {upcCP.get_outputCurrent}")

    print(f"Load Percentage: {upcCP.get_loadPercentage}")
    print(f"baseOutputStatus: {upcCP.get_baseOutputStatus}")

    print(f"UPS power rating: {upcCP.get_powerRating}")