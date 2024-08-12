# py-ups-snmp
Python UPS SNMP

CyberPower UPS:
    Class to get UPS data from a CyberPower UPS using SNMP v1

    example usage:

        ups = upsCyberPower('192.168.1.1', 'public')

        temp = ups.get_envTemp
        print(f"Temperature: {temp}")
        
        humidity = ups.get_envHumidity
        print(f"Humidity: {humidity}")
        
        ups_state = ups.get_BaseOutputStatus
        print(f"UPS State: {ups_state}")