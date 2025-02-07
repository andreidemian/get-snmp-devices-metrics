from .snmp import snmpRead
from .convertTools import (
    convert_centiseconds,
    toFloat
)

class upsAPC(snmpRead):

    def __init__(self, ip:str, port:int = 161, snmpv:int=1, community:str=None, user:str=None, authkey:str=None, privkey:str=None):
        super().__init__(ip, port, snmpv, community, user, authkey, privkey)

    @ property
    def get_name(self) -> str:
        return self.get_oid('1.3.6.1.4.1.318.1.1.1.1.1.2.0')
    
    @ property
    def get_model(self) -> str:
        return self.get_oid('1.3.6.1.4.1.318.1.1.1.1.1.1.0')
    
    @property
    def get_contact(self) -> str:
        return self.get_oid('1.3.6.1.2.1.1.4.0')
    
    @property
    def get_location(self) -> str:
        return self.get_oid('.1.3.6.1.2.1.1.6.0')
    
    @property
    def get_uioEnvTempP1(self) -> int:
        temp = self.get_oid('1.3.6.1.4.1.318.1.1.25.1.2.1.6.1.1')
        if(temp):
            return int(temp)
        return None
    
    @property
    def get_batteryTemperature(self) -> int:
        temp = self.get_oid('1.3.6.1.4.1.318.1.1.1.2.2.2.0')
        if(temp):
            return int(temp)
        return None

    @property
    def get_batteryChargePercentage(self) -> int:
        bcp = self.get_oid('1.3.6.1.4.1.318.1.1.1.2.2.1.0')
        if(bcp):
            return int(bcp)
        return None
    
    @property
    def get_batteryReplace(self) -> bool:
        br = self.get_oid('1.3.6.1.4.1.318.1.1.1.2.2.4.0')
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
        state = self.get_oid('1.3.6.1.4.1.318.1.1.1.2.1.1.0')
        if(state):
            return (int(state), battery_state[state])
        return None

    @property
    def get_batteryRuntime(self) -> dict:
        br = self.get_oid('1.3.6.1.4.1.318.1.1.1.2.2.3.0')
        if(br):
            return convert_centiseconds(int(br))
        return None

    @property
    def get_batteryVoltage(self) -> int:
        obv = self.get_oid('1.3.6.1.4.1.318.1.1.1.2.2.8.0')
        if(obv):
            return int(obv)
        return None

    @property
    def get_inputVoltage(self) -> int:
        iv = self.get_oid('1.3.6.1.4.1.318.1.1.1.3.2.1.0')
        if(iv):
            return int(iv)
        return None
    
    @property
    def get_inputFrequency(self) -> int:
        inf = self.get_oid('1.3.6.1.4.1.318.1.1.1.3.2.4.0')
        if(inf):
            return int(inf)
        return None

    @property
    def get_inputLineFailCause(self) -> tuple:
        """
            return the input status and the input status description
            example all output:
                (1,'noTransfer')
                (2,'highLineVoltage')
                (3,'brownout')
                (4,'blackout')
                (5,'smallMomentarySag')
                (6,'deepMomentarySag')
                (7,'smallMomentarySpike')
                (8,'largeMomentarySpike')
                (9,'selfTest')
                (10,'rateOfVoltageChange')
        """
        ups_state = {
            '1':'noTransfer',
            '2':'highLineVoltage',
            '3':'brownout',
            '4':'blackout',
            '5':'smallMomentarySag',
            '6':'deepMomentarySag',
            '7':'smallMomentarySpike',
            '8':'largeMomentarySpike',
            '9':'selfTest',
            '10':'rateOfVoltageChange'
        }
        state = self.get_oid('1.3.6.1.4.1.318.1.1.1.3.2.5.0')
        if(state):
            return (int(state), ups_state[state])
        return None

    @property
    def get_outputVoltage(self) -> int:
        ouv = self.get_oid('1.3.6.1.4.1.318.1.1.1.4.2.1.0')
        if(ouv):
            return int(ouv)
        return None
    
    @property
    def get_outputFrequency(self) -> int:
        ouf = self.get_oid('1.3.6.1.4.1.318.1.1.1.4.2.2.0')
        if(ouf):
            return int(ouf)
        return None

    @property
    def get_outputCurrent(self) -> int:
        ouc = self.get_oid('1.3.6.1.4.1.318.1.1.1.4.2.4.0')
        if(ouc):
            return int(ouc)
        return None
    
    @property
    def get_baseOutputStatus(self) -> tuple:
        """
         return the UPS state and the UPS state description
         example all output:
            (1, 'unknown'),
            (2, 'onLine'),
            (3, 'onBattery'),
            (4, 'onSmartBoost'),
            (5, 'timedSleeping'),
            (6, 'softwareBypass'),
            (7, 'off'),
            (8, 'rebooting'),
            (9, 'switchedBypass'),
            (10, 'hardwareFailureBypass'),
            (11, 'sleepingUntilPowerReturn'),
            (12, 'onSmartTrim')
        """
        ups_state = {
            '1':'unknown',
            '2':'onLine',
            '3':'onBattery',
            '4':'onSmartBoost',
            '5':'timedSleeping',
            '6':'softwareBypass',
            '7':'off',
            '8':'rebooting',
            '9':'switchedBypass',
            '10':'hardwareFailureBypass',
            '11':'sleepingUntilPowerReturn',
            '12':'onSmartTrim'
        }
        state = self.get_oid('1.3.6.1.4.1.318.1.1.1.4.1.1.0')
        if(state):
            return (int(state), ups_state[state])
        return None
    
    @property
    def get_loadPercentage(self) -> int:
        lper = self.get_oid('1.3.6.1.4.1.318.1.1.1.4.2.3.0')
        if(lper):
            return int(lper)
        return None

class upsCyberPower(snmpRead):

    def __init__(self, ip:str, port:int = 161, snmpv:int=1, community:str=None, user:str=None, authkey:str=None, privkey:str=None):
        super().__init__(ip, port, snmpv, community, user, authkey, privkey)

    @property
    def get_name(self) -> str:
        return self.get_oid('.1.3.6.1.2.1.1.5.0')

    @property
    def get_model(self) -> str:
        return self.get_oid('.1.3.6.1.2.1.1.1.0')
   
    @property
    def get_contact(self) -> str:
        return self.get_oid('.1.3.6.1.2.1.1.4.0')
    
    @property
    def get_location(self) -> str:
        return self.get_oid('.1.3.6.1.2.1.1.6.0')
    
    @property
    def get_serialNumber(self) -> str:
        get_sn = self.get_oid('.1.3.6.1.4.1.3808.1.1.1.1.2.3.0')
        if(get_sn):
            return get_sn
        return None
    
    @property
    def get_upsTemperature(self) -> int:
        temp = self.get_oid('.1.3.6.1.4.1.3808.1.1.1.10.2.0')
        if(temp):
            return int(temp)
        return None

    @property
    def get_envTemp(self) -> float:
        str_temp = self.get_oid('.1.3.6.1.4.1.3808.1.1.4.2.6.0')
        if(str_temp):
            return toFloat(str_temp)
        return None

    @property
    def get_envHumidity(self) -> int:
        humidity = self.get_oid('.1.3.6.1.4.1.3808.1.1.4.3.1.0')
        if(humidity):
            return int(humidity)
        return None
    
    @property
    def get_batteryChargePercentage(self) -> int:
        bcp = self.get_oid('.1.3.6.1.4.1.3808.1.1.1.2.2.1.0')
        if(bcp):
            return int(bcp)
        return None
    
    @property
    def get_batteryReplace(self) -> bool:
        br = self.get_oid('.1.3.6.1.4.1.3808.1.1.1.2.2.5.0')
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
        state = self.get_oid('.1.3.6.1.4.1.3808.1.1.1.2.1.1.0')
        if(state):
            return (int(state), battery_state[state])
        return None

    @property
    def get_batteryRuntime(self) -> str:
        br = self.get_oid('.1.3.6.1.4.1.3808.1.1.1.2.2.4.0')
        if(br):
            return convert_centiseconds(int(br))
        return None

    @property
    def get_batteryVoltage(self) -> float:
        obv = self.get_oid('.1.3.6.1.4.1.3808.1.1.1.2.2.2.0')
        if(obv):
            return toFloat(obv)
        return None

    @property
    def get_inputVoltage(self) -> float:
        iv = self.get_oid('.1.3.6.1.4.1.3808.1.1.1.3.2.1.0')
        if(iv):
            return toFloat(iv)
        return None
    
    @property
    def get_inputFrequency(self) -> float:
        inf = self.get_oid('.1.3.6.1.4.1.3808.1.1.1.3.2.4.0')
        if(inf):
            return toFloat(inf)
        return None

    @property
    def get_inputLineFailCause(self) -> tuple:
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
        state = self.get_oid('.1.3.6.1.4.1.3808.1.1.1.3.2.6.0')
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
        state = self.get_oid('.1.3.6.1.4.1.3808.1.1.1.3.2.5.0')
        if(state):
            return (int(state), transfer_reason[state])
        return None

    @property
    def get_outputVoltage(self) -> float:
        ouv = self.get_oid('.1.3.6.1.4.1.3808.1.1.1.4.2.1.0')
        if(ouv):
            return toFloat(ouv)
        return None
    
    @property
    def get_outputFrequency(self) -> float:
        ouf = self.get_oid('.1.3.6.1.4.1.3808.1.1.1.4.2.2.0')
        if(ouf):
            return toFloat(ouf)
        return None

    @property
    def get_outputCurrent(self) -> float:
        ouc = self.get_oid('.1.3.6.1.4.1.3808.1.1.1.4.2.4.0')
        if(ouc):
            return toFloat(ouc)
        return None
    
    @property
    def get_outputWattage(self) -> int:
        ouw = self.get_oid('.1.3.6.1.4.1.3808.1.1.1.4.2.5.0')
        if(ouw):
            return int(ouw)
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
        state = self.get_oid('.1.3.6.1.4.1.3808.1.1.1.4.1.1.0')
        if(state):
            return (int(state), ups_state[state])
        return None
    
    @property
    def get_loadPercentage(self) -> int:
        lper = self.get_oid('.1.3.6.1.4.1.3808.1.1.1.4.2.3.0')
        if(lper):
            return int(lper)
        return None
    
    @property
    def get_powerRating(self) -> int:
        upr = self.get_oid('.1.3.6.1.4.1.3808.1.1.1.1.2.6.0')
        if(upr):
            return int(upr)
        return None