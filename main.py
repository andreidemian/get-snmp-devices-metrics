from snmpDevices import upsCyberPower, upsAPC, HWgSTE, ifaceMetrics, host

# ups snmp user
#UPS_SNMP_USER = 'ups'
# ups snmp authkey
#UPS_SNMP_AUTHKEY = 'jSjej92nJQnsdif94k12khj589jksS'
# ups snmp privkey
#UPS_SNMP_PRIVKEY = 'jSjej92nJQnsdif94k12khj589jksS'

# example class usage
import pprint
if __name__ == "__main__":
    pp = pprint.PrettyPrinter(indent=4)

    lx = host(ip='192...' , community='public', snmpv=2)

    pp.pprint(lx.get_hostName)
    pp.pprint(lx.get_contact)
    pp.pprint(lx.get_location)
    pp.pprint(lx.get_upTime)

    #lx = ifaceMetrics(ip='192...' , community='public', snmpv=2)
    
    pp.pprint(lx.get_memMetrics)
    pp.pprint(lx.get_memSwapMetrics)
    pp.pprint(lx.get_cpuMetrics)
    pp.pprint(lx.get_LoadAvg)
    
    pp.pprint(lx.get_storage)
    pp.pprint(lx.get_diskIO)
    pp.pprint(lx.get_diskIOLA)
    pp.pprint(lx.get_diskION)
    pp.pprint(lx.get_diskIONX)

    pp.pprint(lx.get_sensors)

#    pp.pprint(lx.get_ifType)
#    print("="*50)
#    pp.pprint(lx.get_ifMtu)
#    print("="*50)
#    pp.pprint(lx.get_ifSpeed)
#    print("="*50)
#    pp.pprint(lx.get_ifPhysAddress)
#    print("="*50)
#    pp.pprint(lx.get_ifAdminStatus)
#    print("="*50)
#    pp.pprint(lx.get_ifOperStatus)
#    print("="*50)
#    pp.pprint(lx.get_ifLastChange)
#    print("="*50)
#    pp.pprint(lx.get_ifIOOctets)
#    print("="*50)
#    pp.pprint(lx.get_ifIOErrors)
#    print("="*50)
#    pp.pprint(lx.get_ifIODiscards)
#    print("="*50)
#    pp.pprint(lx.get_ifUnknownProtos)
#    print("="*50)
#    pp.pprint(lx.get_ifNUcastPkts)
#    print("="*50)
#    pp.pprint(lx.get_ifUcastPkts)
#    print("="*50)
#    pp.pprint(lx.get_ifOutQLen)
#    print("="*50)
#    pp.pprint(lx.get_ifAlias)
#    print("="*50)
#    pp.pprint(lx.get_ifIPAddress)

#    ups = upsAPC(ip='192.168.2.2', community='public', snmpv=2)

    # APC UPS
#    print(f"Name: {ups.get_name}")
#    print(f"Model: {ups.get_model}")
#    print(f"Contact: {ups.get_contact}")
#    print(f"Location: {ups.get_location}")

#    print(f"Tempature environment: {ups.get_uioEnvTempP1}")

#    print(f"UPS Battery Temperature: {ups.get_batteryTemperature}")
#    print(f"Battery Charge Percentage: {ups.get_batteryChargePercentage}")
#    print(f"Battery Replace: {ups.get_batteryReplace}")
#    print(f"Battery Status: {ups.get_batteryStatus}")
#    print(f"Battery Runtime: {ups.get_batteryRuntime}")
#    print(f"Output Battery Voltage: {ups.get_batteryVoltage}")

#    print(f"Input Voltage: {ups.get_inputVoltage}")
#    print(f"Input Frequency: {ups.get_inputFrequency}")
#    print(f"Input Line Fail Cause {ups.get_inputLineFailCause}")
    
#    print(f"Output Voltage: {ups.get_outputVoltage}")
#    print(f"Output Frequency: {ups.get_outputFrequency}")
#    print(f"Output Current: {ups.get_outputCurrent}")
#    print(f"baseOutputStatus: {ups.get_baseOutputStatus}")

#    print(f"Load Percentage: {ups.get_loadPercentage}")
    

#    print("="*50, "\n")

    #upsCP = upsCyberPower(ip='192.168.2.142', user=UPS_SNMP_USER, authkey=UPS_SNMP_AUTHKEY, privkey=UPS_SNMP_PRIVKEY, snmpv=3)
#    upsCP = upsCyberPower(ip='192.168.2.142', community='public', snmpv=2)

    # CyberPower UPS
#    print(f"Name: {upsCP.get_name}")
#    print(f"Model: {upsCP.get_model}")
#    print(f"Contact: {upsCP.get_contact}")
#    print(f"Location: {upsCP.get_location}")

#    print(f"UPS Temperature: {upsCP.get_upsTemperature}")
#    print(f"Environment Temperature: {upsCP.get_envTemp}")
#    print(f"Environment Humidity: {upsCP.get_envHumidity}")

#    print(f"Battery Charge Percentage: {upsCP.get_batteryChargePercentage}")
#    print(f"Battery Runtime: {upsCP.get_batteryRuntime}")
#    print(f"Battery Voltage: {upsCP.get_batteryVoltage}")
#    print(f"Battery Status: {upsCP.get_batteryStatus}")

#    print(f"Input Voltage: {upsCP.get_inputVoltage}")
#    print(f"Input Frequency: {upsCP.get_inputFrequency}")
#    print(f"Input Line Fail Cause {upsCP.get_inputLineFailCause}")

#    print(f"Output Voltage: {upsCP.get_outputVoltage}")
#    print(f"Output Frequency: {upsCP.get_outputFrequency}")
#    print(f"Output Current: {upsCP.get_outputCurrent}")

#    print(f"Load Percentage: {upsCP.get_loadPercentage}")
#    print(f"baseOutputStatus: {upsCP.get_baseOutputStatus}")

#    print(f"UPS power rating: {upsCP.get_powerRating}")


#    print("="*50, "\n")

#    sensors = HWgSTE(ip='192.168.2.3',community='public', snmpv=2)

#    print(f"Name: {sensors.get_name}")
#    print(f"Model: {sensors.get_model}")
#    print(f"Contact: {sensors.get_contact}")
#    print(f"Location: {sensors.get_location}")
#    print(f"UpTime: {sensors.get_upTime}")
#    print(f"ObjectID: {sensors.get_ObjectID}")
#    print(f"MAC Address: {sensors.get_macAddress}")
#    print(f"Sensors: {sensors.get_sensors}")