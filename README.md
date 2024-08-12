# py-ups-snmp
Python UPS SNMP

CyberPower UPS Get SNMP V1 data

    example usage:

        ups = upsCyberPower('192.168.1.1', 'public')

        temp = ups.get_envTemp
        print(f"Temperature: {temp}")
        
        humidity = ups.get_envHumidity
        print(f"Humidity: {humidity}")
        
        ups_state = ups.get_BaseOutputStatus
        print(f"UPS State: {ups_state}")