from .snmp import snmpRead
from .convertTools import convert_centiseconds


class HWgSTE(snmpRead):

    def __init__(self, ip:str, port:int = 161, snmpv:int=1, community:str=None, user:str=None, authkey:str=None, privkey:str=None):
        super().__init__(ip, port, snmpv, community, user, authkey, privkey)

    @ property
    def get_name(self) -> str:
        return self.get_oid('.1.3.6.1.2.1.1.5.0')
    
    @ property
    def get_model(self) -> str:
        return self.get_oid('.1.3.6.1.2.1.1.1.0')
    
    @property
    def get_contact(self) -> str:
        return self.get_oid('.1.3.6.1.2.1.1.4.0')
    
    @property
    def get_location(self) -> str:
        return self.get_oid('.1.3.6.1.2.1.1.6.0')
    
    @property
    def get_upTime(self) -> str:
        up_time_c = self.get_oid('.1.3.6.1.2.1.1.3.0')
        if(up_time_c):
            return convert_centiseconds(int(up_time_c))
    
    @property
    def get_ObjectID(self) -> str:
        obj_id = self.get_oid('.1.3.6.1.2.1.1.2.0')
        if(obj_id):
            return str(obj_id)
        return None

    @property
    def get_macAddress(self) -> str:
        return self.get_oid('.1.3.6.1.4.1.21796.4.1.70.1.0')

    @property
    def get_sensors(self) -> str:
        sensor_name =  self.walk_oid('.1.3.6.1.4.1.21796.4.1.3.1.2')
        sensor_value = self.walk_oid('.1.3.6.1.4.1.21796.4.1.3.1.4')
        sensor_sn = self.walk_oid('.1.3.6.1.4.1.21796.4.1.3.1.6')
        sensors = []
        for i, name in enumerate(sensor_name):
            sensors.append({
                name[1]:float(sensor_value[i][1]),
                'sn':sensor_sn[i][1]
            })
        return sensors
        