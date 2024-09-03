import asyncio
from pysnmp.hlapi.asyncio import (
    getCmd, 
    SnmpEngine, 
    CommunityData, 
    UdpTransportTarget, 
    ContextData, 
    ObjectType, 
    ObjectIdentity, 
    UsmUserData, 
    usmHMACSHAAuthProtocol, 
    usmAesCfb128Protocol
)

class snmpRead:

    def __init__(self, ip:str, port:int = 161, snmpv:int=1, community:str=None, user:str=None, authkey:str=None, privkey:str=None):
        self.ip = ip
        self.port = port
        self.community = community
        self.snmpv = snmpv
        self.user = user
        self.authkey = authkey
        self.privkey = privkey

    async def run_snmp(self, oid:str) -> str:

        #print(f"Getting SNMP Data for OID: {oid}")

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
    
    def get_oid(self, oid:str) -> str:
        return asyncio.run(self.run_snmp(oid))