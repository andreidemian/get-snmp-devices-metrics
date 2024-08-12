import asyncio
from pysnmp.hlapi.asyncio import getCmd, SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity

class upsCyberPower:

    """
        Get SNMP V1 data from a CyberPower UPS

        example usage:

            ups = upsCyberPower('192.168.1.1', 'public')

            temp = ups.get_envTemp
            print(f"Temperature: {temp}")
            
            humidity = ups.get_envHumidity
            print(f"Humidity: {humidity}")
            
            ups_state = ups.get_BaseOutputStatus
            print(f"UPS State: {ups_state}")
    """

    def __init__(self, ip:str, community:str):
        self.ip = ip
        self.community = community

    async def get_snmp_v1_data(self, ip:str, community:str, oid:str):

        errorIndication, errorStatus, errorIndex, varBinds = await getCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=0),
            UdpTransportTarget((ip, 161)),
            ContextData(),
            ObjectType(ObjectIdentity(oid))
        )

        value = None
        if errorIndication:
            print(f"Error Indication: {errorIndication}")
        elif errorStatus:
            print(f"Error Status: {errorStatus.prettyPrint()}")
        else:
            for varBind in varBinds:
                if(varBind):
                    value = varBind[1].prettyPrint()
        return value

    def toFloat(self,strValue: str) -> float:
        if(strValue == '0'):
            return '0'
        return float(f"{strValue[:-1]}.{strValue[-1]}")

    @property
    def get_name(self) -> str:
        oid = '.1.3.6.1.2.1.1.5.0'
        return asyncio.run(self.get_snmp_v1_data(self.ip, self.community, oid))

    @property
    def get_description(self) -> str:
        oid = '.1.3.6.1.2.1.1.1.0'
        return asyncio.run(self.get_snmp_v1_data(self.ip, self.community, oid))
   
    @property
    def get_contact(self) -> str:
        oid = '.1.3.6.1.2.1.1.4.0'
        return asyncio.run(self.get_snmp_v1_data(self.ip, self.community, oid))
    
    @property
    def get_location(self) -> str:
        oid = '.1.3.6.1.2.1.1.6.0'
        return asyncio.run(self.get_snmp_v1_data(self.ip, self.community, oid))
    
    @property
    def get_upsTemperature(self) -> float:
        oid = '.1.3.6.1.4.1.3808.1.1.1.10.2.0'
        return asyncio.run(self.get_snmp_v1_data(self.ip, self.community, oid))

    @property
    def get_envTemp(self) -> float:
        oid = '.1.3.6.1.4.1.3808.1.1.4.2.6.0'
        str_temp = asyncio.run(self.get_snmp_v1_data(self.ip, self.community, oid))
        if(str_temp):
            return self.toFloat(str_temp)
        return None

    @property
    def get_envHumidity(self) -> int:
        oid = '.1.3.6.1.4.1.3808.1.1.4.3.1.0'
        humidity = asyncio.run(self.get_snmp_v1_data(self.ip, self.community, oid))
        if(humidity):
            return int(humidity)
        return None
    
    @property
    def get_batteryChargePercentage(self) -> int:
        oid = '.1.3.6.1.4.1.3808.1.1.1.2.2.1.0'
        return int(asyncio.run(self.get_snmp_v1_data(self.ip, self.community, oid)))
    
    @property
    def get_batteryReplace(self) -> bool:
        oid = '.1.3.6.1.4.1.3808.1.1.1.2.2.5.0'
        return True if int(asyncio.run(self.get_snmp_v1_data(self.ip, self.community, oid))) == 2 else False

    @property
    def get_batteryStatus(self) -> tuple:
        """
            return the battery state and the battery state description
            example all output:
                (1, 'Unknown'),
                (2, 'Normal'),
                (3, 'Low')
        """
        oid = '.1.3.6.1.4.1.3808.1.1.1.2.1.1.0'
        battery_state = {
            '1': 'Unknown',
            '2': 'Normal',
            '3': 'Low',
        }
        state = asyncio.run(self.get_snmp_v1_data(self.ip, self.community, oid))
        return (int(state), battery_state[state])

    @property
    def get_batteryRuntime(self) -> str:
        oid = '.1.3.6.1.4.1.3808.1.1.1.2.2.4.0'
        return asyncio.run(self.get_snmp_v1_data(self.ip, self.community, oid))

    @property
    def get_inputVoltage(self) -> float:
        oid = '.1.3.6.1.4.1.3808.1.1.1.3.2.1.0'
        return self.toFloat(asyncio.run(self.get_snmp_v1_data(self.ip, self.community, oid)))
    
    @property
    def get_inputFrequency(self) -> float:
        oid = '.1.3.6.1.4.1.3808.1.1.1.3.2.4.0'
        return self.toFloat(asyncio.run(self.get_snmp_v1_data(self.ip, self.community, oid)))

    @property
    def get_inputStatus(self) -> tuple:
        """
            return the input status and the input status description
            example all output:
                (1, 'Normal'),
                (2, 'Over Voltage'),
                (3, 'Under Voltage'),
                (4, 'Frequency Failure'),
                (5, 'Blackout')
        """
        oid = '.1.3.6.1.4.1.3808.1.1.1.3.2.6.0'
        ups_state = {
            '1': 'Normal',
            '2': 'Over Voltage',
            '3': 'Under Voltage',
            '4': 'Frequency Failure',
            '5': 'Blackout'
        }
        state = asyncio.run(self.get_snmp_v1_data(self.ip, self.community, oid))
        return (int(state), ups_state[state])

    @property
    def get_outputVoltage(self) -> float:
        oid = '.1.3.6.1.4.1.3808.1.1.1.4.2.1.0'
        return self.toFloat(asyncio.run(self.get_snmp_v1_data(self.ip, self.community, oid)))
    
    @property
    def get_outputFrequency(self) -> float:
        oid = '.1.3.6.1.4.1.3808.1.1.1.4.2.2.0'
        return self.toFloat(asyncio.run(self.get_snmp_v1_data(self.ip, self.community, oid)))

    @property
    def get_outputCurrent(self) -> float:
        oid = '.1.3.6.1.4.1.3808.1.1.1.4.2.4.0'
        return self.toFloat(asyncio.run(self.get_snmp_v1_data(self.ip, self.community, oid)))
    
    @property
    def get_outputBatteryVoltage(self) -> float:
        oid = '.1.3.6.1.4.1.3808.1.1.1.2.2.2.0'
        return self.toFloat(asyncio.run(self.get_snmp_v1_data(self.ip, self.community, oid)))

    @property
    def get_baseOutputStatus(self) -> tuple:
        """
         return the UPS state and the UPS state description
         example all output: 
            (1, 'Unknown'), 
            (2, 'Online'), 
            (3, 'On Battery'), 
            (4, 'On Boost'), 
            (5, 'On Sleep'), 
            (6, 'Off'), 
            (7, 'Rebooting')
        """
        oid = '.1.3.6.1.4.1.3808.1.1.1.4.1.1.0'
        ups_state = {
            '1': 'Unknown',
            '2': 'Online',
            '3': 'On Battery',
            '4': 'On Boost',
            '5': 'On Sleep',
            '6': 'Off',
            '7': 'Rebooting'
        }
        state = asyncio.run(self.get_snmp_v1_data(self.ip, self.community, oid))
        return (int(state), ups_state[state])
    
    @property
    def get_inputTransferReason(self) -> int:
        """
            return the input transfer reason and the input transfer reason description
            example all output:
                (1, 'No Transfer'),
                (2, 'High Voltage'),
                (3, 'Brownout'),
                (4, 'Self Test')
        """
        oid = '.1.3.6.1.4.1.3808.1.1.1.3.2.5.0'
        transfer_reason = {
            '1': 'No Transfer',
            '2': 'High Voltage',
            '3': 'Brownout',
            '4': 'Self Test'
        }
        state = asyncio.run(self.get_snmp_v1_data(self.ip, self.community, oid))
        return (int(state), transfer_reason[state])
    
    @property
    def get_loadPercentage(self) -> int:
        oid = '.1.3.6.1.4.1.3808.1.1.1.4.2.3.0'
        return int(asyncio.run(self.get_snmp_v1_data(self.ip, self.community, oid)))
