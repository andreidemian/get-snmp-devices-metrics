import asyncio
from pysnmp.hlapi.asyncio import (
    getCmd,
    nextCmd,
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
import re

class snmpRead:

    def __init__(self, ip:str, port:int = 161, snmpv:int=1, community:str=None, user:str=None, authkey:str=None, privkey:str=None):

        self.ip = ip
        self.port = port
        self.community = community

        self.usm_data = None
        if snmpv == 3:
            self.usm_data = UsmUserData(user)
            
            if authkey and privkey:
                # If both authKey and privKey are provided, use authPriv security level
                self.usm_data = UsmUserData(
                                user,
                                authKey=authkey,
                                privKey=privkey,
                                authProtocol=usmHMACSHAAuthProtocol,
                                privProtocol=usmAesCfb128Protocol
                        )   
            elif authkey:
                # If only authKey is provided, use authNoPriv security level
                self.usm_data = UsmUserData(
                                user,
                                authKey=authkey,
                                authProtocol=usmHMACSHAAuthProtocol
                            )
            else:
                # If no keys are provided, use noAuthNoPriv security level
                self.usm_data = UsmUserData(user)
        
        SNMP_V_MAP = { 1: 0, 2: 1, 3: 3 }
        self.snmpv = SNMP_V_MAP[snmpv]

    async def run_snmp_get(self,oid:str) -> str:

        errorIndication, errorStatus, errorIndex, varBinds = await getCmd(
            SnmpEngine(),
            self.usm_data if self.snmpv == 3 else CommunityData(self.community, mpModel=self.snmpv), # model 0 is SNMPv1, model 1 is SNMPv2c
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
                    value = str(varBind[1].prettyPrint())
        return value
    
    async def run_snmp_get_next(self,oid:str=None) -> tuple:

        # SNMP walk using nextCmd
        errorIndication, errorStatus, errorIndex, varBinds = await nextCmd(
            SnmpEngine(),
            self.usm_data if self.snmpv == 3 else CommunityData(self.community, mpModel=self.snmpv),  # Use correct model for SNMP version
            UdpTransportTarget((self.ip, self.port)),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False  # Set to False to stop when outside the subtree
        )

        if errorIndication:
            print(f"Error Indication: {errorIndication}")
            return (None, None)
        elif errorStatus:
            print(f'Error Status: {errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex)-1][0] or "?"}')
            return (None, None)
        else:
            for varBind in varBinds:
                return (str(varBind[0][0]), str(varBind[0][1]))
        return (None, None)
    
    def  match_oid_prefix(self,prefix:str=None, oid:str=None) -> bool:

        if(not oid or not prefix):
            return False
        
        compile = re.compile(f"^{prefix.replace('.', '')}")
        match = compile.match(oid.replace('.', ''))

        if match:
            return True
        return False

    def get_oid(self, oid:str) -> str:
        return asyncio.run(self.run_snmp_get(oid))

    def walk_oid(self, root_oid:str=None) -> tuple:

        result = []

        oid,value = asyncio.run(self.run_snmp_get_next(root_oid))
        
        if(self.match_oid_prefix(root_oid, oid)):
            result = [(oid,value)]

        while oid:

            oid,value = asyncio.run(self.run_snmp_get_next(oid))
            if self.match_oid_prefix(root_oid, oid):
                result.append((oid,value))

        if(not result):
            return [(root_oid, self.get_oid(root_oid))]
        
        return result