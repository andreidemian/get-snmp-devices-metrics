from .snmp import snmpRead
from .snmpMibMapping import ( 
    get_iftype_description,
    get_ifOperStatus_description,
    get_ifAdminStatus_description
)
from .convertTools import (
    convert_centiseconds,
    toFloat
)

class pfSense(snmpRead):
    """
    pfSense SNMP class
    """

    def __init__(self,ip: str,port: int = 161,snmpv: int = 1,community: str = None,user: str = None,authkey: str = None,privkey: str = None):
        super().__init__(ip, port, snmpv, community, user, authkey, privkey)
        
    @property
    def get_hostName(self) -> str:
        hostname = self.get_oid(".1.3.6.1.2.1.1.5.0")
        return str(hostname) if hostname else None
    
    @property
    def get_contact(self) -> str:
        contact = self.get_oid(".1.3.6.1.2.1.1.4.0")
        return str(contact) if contact else None
    
    @property
    def get_location(self) -> str:
        location = self.get_oid(".1.3.6.1.2.1.1.6.0")
        return str(location) if location else None
    
    @property
    def get_upTime(self) -> str:
        uptime = self.get_oid(".1.3.6.1.2.1.1.3.0")
        return str(uptime) if uptime else None
    
    @property
    def get_cpuTime(self) -> dict:

        """
        CPU in TimeTicks (1/100 of a second)
        """

        cpu_time = {}
        
        cpu_raw_user = self.get_oid(".1.3.6.1.4.1.2021.11.50.0")
        cpu_time['cpuRawUser'] = int(cpu_raw_user) if cpu_raw_user else None

        cpu_raw_nice = self.get_oid(".1.3.6.1.4.1.2021.11.51.0")
        cpu_time['cpuRawNice'] = int(cpu_raw_nice) if cpu_raw_nice else None

        cpu_raw_system = self.get_oid(".1.3.6.1.4.1.2021.11.52.0")
        cpu_time['cpuRawSystem'] = int(cpu_raw_system) if cpu_raw_system else None

        cpu_raw_idle = self.get_oid(".1.3.6.1.4.1.2021.11.53.0")
        cpu_time['cpuRawIdle'] = int(cpu_raw_idle) if cpu_raw_idle else None

        cpu_raw_wait = self.get_oid(".1.3.6.1.4.1.2021.11.54.0")
        cpu_time['cpuRawWait'] = int(cpu_raw_wait) if cpu_raw_wait else None

        cpu_raw_kernel = self.get_oid(".1.3.6.1.4.1.2021.11.55.0")
        cpu_time['cpuRawKernel'] = int(cpu_raw_kernel) if cpu_raw_kernel else None

        cpu_raw_interrupt = self.get_oid(".1.3.6.1.4.1.2021.11.56.0")
        cpu_time['cpuRawInterrupt'] = int(cpu_raw_interrupt) if cpu_raw_interrupt else None

        return cpu_time

    @property
    def get_memory(self) -> dict:

        """
        Memory in KB
        """

        memory = {}

        mem_total_real = self.get_oid(".1.3.6.1.4.1.2021.4.5.0")
        memory['memTotalReal'] = int(mem_total_real) if mem_total_real else None

        mem_avail_real = self.get_oid(".1.3.6.1.4.1.2021.4.6.0")
        memory['memAvailReal'] = int(mem_avail_real) if mem_avail_real else None

        mem_total_free = self.get_oid(".1.3.6.1.4.1.2021.4.11.0")
        memory['memTotalFree'] = int(mem_total_free) if mem_total_free else None

        mem_shared = self.get_oid(".1.3.6.1.4.1.2021.4.13.0")
        memory['memShared'] = int(mem_shared) if mem_shared else None

        mem_buffer = self.get_oid(".1.3.6.1.4.1.2021.4.14.0")
        memory['memBuffer'] = int(mem_buffer) if mem_buffer else None

        mem_cached = self.get_oid(".1.3.6.1.4.1.2021.4.15.0")
        memory['memCached'] = int(mem_cached) if mem_cached else None

        return memory

    @property
    def get_ifIndex(self) -> list[int]:
        network_interfaces_oid_prefix = ".1.3.6.1.2.1.2.2.1"
        indices = self.walk_oid(f"{network_interfaces_oid_prefix}.1")
        return indices if indices else []

    @property
    def get_ifMetrics(self) -> list[dict]:
        network_interfaces_oid_prefix = ".1.3.6.1.2.1.2.2.1"
        iface_indices = self.get_ifIndex
        iface_metrics = []
        for index in iface_indices:
            
            idx = index[1]
            iface_m = {}

            idx = int(idx) if idx else None
            iface_m['ifIndex'] = idx

            descr = self.get_oid(f"{network_interfaces_oid_prefix}.2.{idx}")
            iface_m['descr'] = str(descr) if descr else None

            type = self.get_oid(f"{network_interfaces_oid_prefix}.3.{idx}")
            iface_m['type'] = get_iftype_description(int(type)) if type else None

            mtu = self.get_oid(f"{network_interfaces_oid_prefix}.4.{idx}")
            iface_m['mtu'] = int(mtu) if mtu else None

            speed = int(self.get_oid(f"{network_interfaces_oid_prefix}.5.{idx}"))
            iface_m['speed'] = int(speed) if speed else None
            
            PhysAddress = str(self.get_oid(f"{network_interfaces_oid_prefix}.6.{idx}"))
            iface_m['PhysAddress'] = str(PhysAddress).replace("0x", "") if PhysAddress else None
            
            AdminStatus = int(self.get_oid(f"{network_interfaces_oid_prefix}.7.{idx}"))
            iface_m['AdminStatus'] = get_ifAdminStatus_description(AdminStatus) if AdminStatus else None
            
            OperStatus = int(self.get_oid(f"{network_interfaces_oid_prefix}.8.{idx}"))
            iface_m['OperStatus'] = get_ifOperStatus_description(OperStatus) if OperStatus else None
            
            # converted to seconds
            LastChange = int(self.get_oid(f"{network_interfaces_oid_prefix}.9.{idx}"))
            iface_m['LastChange'] = convert_centiseconds(LastChange) if LastChange else None
            
            InOctets = int(self.get_oid(f"{network_interfaces_oid_prefix}.10.{idx}"))
            iface_m['InOctets'] = int(InOctets) if InOctets else None
            
            InUcastPkts = int(self.get_oid(f"{network_interfaces_oid_prefix}.11.{idx}"))
            iface_m['InUcastPkts'] = int(InUcastPkts) if InUcastPkts else None
            
            InNUcastPkts = int(self.get_oid(f"{network_interfaces_oid_prefix}.12.{idx}"))
            iface_m['InNUcastPkts'] = int(InNUcastPkts) if InNUcastPkts else None
            
            InDiscards = int(self.get_oid(f"{network_interfaces_oid_prefix}.13.{idx}"))
            iface_m['InDiscards'] = int(InDiscards) if InDiscards else None
            
            InErrors = int(self.get_oid(f"{network_interfaces_oid_prefix}.14.{idx}"))
            iface_m['InErrors'] = int(InErrors) if InErrors else None
            
            InUnknownProtos = int(self.get_oid(f"{network_interfaces_oid_prefix}.15.{idx}"))
            iface_m['InUnknownProtos'] = int(InUnknownProtos) if InUnknownProtos else None
            
            OutOctets = int(self.get_oid(f"{network_interfaces_oid_prefix}.16.{idx}"))
            iface_m['OutOctets'] = int(OutOctets) if OutOctets else None
            
            OutUcastPkts = int(self.get_oid(f"{network_interfaces_oid_prefix}.17.{idx}"))
            iface_m['OutUcastPkts'] = int(OutUcastPkts) if OutUcastPkts else None
            
            OutNUcastPkts = int(self.get_oid(f"{network_interfaces_oid_prefix}.18.{idx}"))
            iface_m['OutNUcastPkts'] = int(OutNUcastPkts) if OutNUcastPkts else None
            
            OutDiscards = int(self.get_oid(f"{network_interfaces_oid_prefix}.19.{idx}"))
            iface_m['OutDiscards'] = int(OutDiscards) if OutDiscards else None
            
            OutErrors = int(self.get_oid(f"{network_interfaces_oid_prefix}.20.{idx}"))
            iface_m['OutErrors'] = int(OutErrors) if OutErrors else None
            
            OutQLen = int(self.get_oid(f"{network_interfaces_oid_prefix}.21.{idx}"))
            iface_m['OutQLen'] = int(OutQLen) if OutQLen else None

            iface_metrics.append(iface_m)
        return iface_metrics

    @property
    def get_ipAddEntIfIndex(self) -> list[dict]:
        """
        IP Address to Interface Index
        """
        ipAdEntIfIndex_oid = "1.3.6.1.2.1.4.20.1.2"
        ipAdEntNetMask_oid = "1.3.6.1.2.1.4.20.1.3"
        ipAdEntIfIndex = self.walk_oid(ipAdEntIfIndex_oid)
        if ipAdEntIfIndex:
            ipaddr_list = []
            for ip in ipAdEntIfIndex:
                interface_index = int(ip[1]) if ip[1] else None
                ip_address = str(ip[0][len(ipAdEntIfIndex_oid)+1:]) if ip[0] else None
                netmask = str(self.get_oid(f"{ipAdEntNetMask_oid}.{ip_address}")) if ip_address else None
                ipaddr = {
                    'ifIndex': interface_index,
                    'ip': ip_address,
                    'netmask': netmask
                }
                ipaddr_list.append(ipaddr)
            ipaddr_list.sort(key=lambda x: x['ifIndex'])
            return ipaddr_list
        return None

