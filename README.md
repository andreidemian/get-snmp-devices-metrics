# py-ups-snmp
Python UPS SNMP

### The pysnmp lib is needed for this class
`python3 -m pip install pysnmp==7.1.16`

CyberPower UPS Get SNMP V1 data

    example usage:
```
        ups = upsCyberPower('192.168.1.1', 'public')

        temp = ups.get_envTemp
        print(f"Temperature: {temp}")
        
        humidity = ups.get_envHumidity
        print(f"Humidity: {humidity}")
        
        ups_state = ups.get_BaseOutputStatus
        print(f"UPS State: {ups_state}")
```