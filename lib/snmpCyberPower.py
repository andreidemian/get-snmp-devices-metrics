import asyncio
from pysnmp.hlapi.asyncio import getCmd, SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity, UsmUserData, usmHMACSHAAuthProtocol, usmAesCfb128Protocol

class upsCyberPower:

    """
        CyberPower UPS: Get SNMP V1 data

        example usage:

            ups = upsCyberPower('192.168.1.1', 'public')

            temp = ups.get_envTemp
            print(f"Temperature: {temp}")
            
            humidity = ups.get_envHumidity
            print(f"Humidity: {humidity}")
            
            ups_state = ups.get_BaseOutputStatus
            print(f"UPS State: {ups_state}")
    """

    def __init__(self, ip:str, port:int = 161, snmpv:int=1, community:str=None, user:str=None, authkey:str=None, privkey:str=None):
        self.ip = ip
        self.port = port
        self.community = community
        self.snmpv = snmpv
        self.user = user
        self.authkey = authkey
        self.privkey = privkey

    async def get_snmp_data(self, oid:str) -> str:

        usm_data = None
        if(self.snmpv == 3):
            usm_data = UsmUserData(self.user)
            
            if self.authkey and self.authkey:
                # If both authKey and privKey are provided, use authPriv security level
                usm_data = UsmUserData(
                                self.user,
                                authKey=self.authkey,
                                privKey=self.authkey,
                                authProtocol=usmHMACSHAAuthProtocol,
                                privProtocol=usmAesCfb128Protocol
                        )   
            elif self.authkey:
                # If only authKey is provided, use authNoPriv security level
                usm_data = UsmUserData(
                                self.user,
                                authKey=self.authkey,
                                authProtocol=usmHMACSHAAuthProtocol
                            )
            else:
                # If no keys are provided, use noAuthNoPriv security level
                usm_data = UsmUserData(self.user)


        SNMP_V = { 1: 0, 2: 1, 3: 3 }

        
        errorIndication, errorStatus, errorIndex, varBinds = await getCmd(
            SnmpEngine(),
            usm_data if self.snmpv == 3 else CommunityData(self.community, mpModel=SNMP_V[self.snmpv]), # model 0 is SNMPv1, model 1 is SNMPv2c
            UdpTransportTarget((self.ip, self.port)),
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
        return asyncio.run(self.get_snmp_data('.1.3.6.1.2.1.1.5.0'))

    @property
    def get_description(self) -> str:
        return asyncio.run(self.get_snmp_data('.1.3.6.1.2.1.1.1.0'))
   
    @property
    def get_contact(self) -> str:
        return asyncio.run(self.get_snmp_data('.1.3.6.1.2.1.1.4.0'))
    
    @property
    def get_location(self) -> str:
        return asyncio.run(self.get_snmp_data('.1.3.6.1.2.1.1.6.0'))
    
    @property
    def get_upsTemperature(self) -> float:
        return asyncio.run(self.get_snmp_data('.1.3.6.1.4.1.3808.1.1.1.10.2.0'))

    @property
    def get_envTemp(self) -> float:
        str_temp = asyncio.run(self.get_snmp_data('.1.3.6.1.4.1.3808.1.1.4.2.6.0'))
        if(str_temp):
            return self.toFloat(str_temp)
        return None

    @property
    def get_envHumidity(self) -> int:
        humidity = asyncio.run(self.get_snmp_data('.1.3.6.1.4.1.3808.1.1.4.3.1.0'))
        if(humidity):
            return int(humidity)
        return None
    
    @property
    def get_batteryChargePercentage(self) -> int:
        bcp = asyncio.run(self.get_snmp_data('.1.3.6.1.4.1.3808.1.1.1.2.2.1.0'))
        if(bcp):
            return int(bcp)
        return None
    
    @property
    def get_batteryReplace(self) -> bool:
        br = asyncio.run(self.get_snmp_data('.1.3.6.1.4.1.3808.1.1.1.2.2.5.0'))
        if(br):
            return True if int(br) == 2 else False
        return None

    @property
    def get_batteryStatus(self) -> tuple:
        """
            return the battery state and the battery state description
            example all output:
                (1, 'Unknown'),
                (2, 'Normal'),
                (3, 'Low')
        """
        battery_state = { '1': 'Unknown', '2': 'Normal', '3': 'Low', }
        state = asyncio.run(self.get_snmp_data('.1.3.6.1.4.1.3808.1.1.1.2.1.1.0'))
        if(state):
            return (int(state), battery_state[state])
        return None

    @property
    def get_batteryRuntime(self) -> str:
        return asyncio.run(self.get_snmp_data('.1.3.6.1.4.1.3808.1.1.1.2.2.4.0'))

    @property
    def get_inputVoltage(self) -> float:
        iv = asyncio.run(self.get_snmp_data('.1.3.6.1.4.1.3808.1.1.1.3.2.1.0'))
        if(iv):
            return self.toFloat(iv)
        return None
    
    @property
    def get_inputFrequency(self) -> float:
        inf = asyncio.run(self.get_snmp_data('.1.3.6.1.4.1.3808.1.1.1.3.2.4.0'))
        if(inf):
            return self.toFloat(inf)
        return None

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
        ups_state = { '1': 'Normal', '2': 'Over Voltage', '3': 'Under Voltage', '4': 'Frequency Failure', '5': 'Blackout' }
        state = asyncio.run(self.get_snmp_data('.1.3.6.1.4.1.3808.1.1.1.3.2.6.0'))
        if(state):
            return (int(state), ups_state[state])
        return None

    @property
    def get_outputVoltage(self) -> float:
        ouv = asyncio.run(self.get_snmp_data('.1.3.6.1.4.1.3808.1.1.1.4.2.1.0'))
        if(ouv):
            return self.toFloat(ouv)
        return None
    
    @property
    def get_outputFrequency(self) -> float:
        ouf = asyncio.run(self.get_snmp_data('.1.3.6.1.4.1.3808.1.1.1.4.2.2.0'))
        if(ouf):
            return self.toFloat(ouf)
        return None

    @property
    def get_outputCurrent(self) -> float:
        ouc = asyncio.run(self.get_snmp_data('.1.3.6.1.4.1.3808.1.1.1.4.2.4.0'))
        if(ouc):
            return self.toFloat(ouc)
        return None
    
    @property
    def get_outputBatteryVoltage(self) -> float:
        obv = asyncio.run(self.get_snmp_data('.1.3.6.1.4.1.3808.1.1.1.2.2.2.0'))
        if(obv):
            return self.toFloat(obv)
        return None

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
        ups_state = { '1': 'Unknown','2': 'Online','3': 'On Battery','4': 'On Boost','5': 'On Sleep','6': 'Off','7': 'Rebooting' }
        state = asyncio.run(self.get_snmp_data('.1.3.6.1.4.1.3808.1.1.1.4.1.1.0'))
        if(state):
            return (int(state), ups_state[state])
        return None
    
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
        transfer_reason = { '1': 'No Transfer', '2': 'High Voltage', '3': 'Brownout', '4': 'Self Test' }
        state = asyncio.run(self.get_snmp_data('.1.3.6.1.4.1.3808.1.1.1.3.2.5.0'))
        if(state):
            return (int(state), transfer_reason[state])
        return None
    
    @property
    def get_loadPercentage(self) -> int:
        lper = asyncio.run(self.get_snmp_data('.1.3.6.1.4.1.3808.1.1.1.4.2.3.0'))
        if(lper):
            return int(lper)
        return None
