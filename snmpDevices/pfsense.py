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
    
    # System Metrics
    @property
    def get_memSwapMetrics(self) -> dict:
        """
        Memory Swap Metrics
        """
        mem = {}
        # Swap Memory Statistics
        ## Total swap space available on the system (in KB).
        memTotalSwap = int(self.get_oid(".1.3.6.1.4.1.2021.4.3.0"))
        mem['memTotalSwap'] = memTotalSwap if memTotalSwap else None
        ## Currently available swap space (not used).
        memAvailSwap = int(self.get_oid(".1.3.6.1.4.1.2021.4.4.0"))
        mem['memAvailSwap'] = memAvailSwap if memAvailSwap else None
        ## Minimum required swap space before alerting (in KB).
        memMinimumSwap = int(self.get_oid(".1.3.6.1.4.1.2021.4.12.0"))
        mem['memMinimumSwap'] = memMinimumSwap if memMinimumSwap else None
    
        return mem

    @property
    def get_memMetrics(self) -> dict:
        """
        Memory Metrics
        """
        mem = {}
        # Physical (Real) Memory (RAM) Statistics
        ## Total RAM available on the system (in KB).
        memTotalReal = int(self.get_oid(".1.3.6.1.4.1.2021.4.5.0"))
        mem['memTotalReal'] = memTotalReal if memTotalReal else None
        ## Total RAM used on the system (in KB).
        memAvailReal = int(self.get_oid(".1.3.6.1.4.1.2021.4.6.0"))
        mem['memAvailReal'] = memAvailReal if memAvailReal else None
        ## Total RAM free on the system (in KB).
        memTotalReal = int(self.get_oid(".1.3.6.1.4.1.2021.4.11.0"))
        mem['memTotalFree'] = memTotalReal if memTotalReal else None

        # Memory Buffers
        ## Shared memory used by multiple processes
        memShared = int(self.get_oid(".1.3.6.1.4.1.2021.4.13.0"))
        mem['memShared'] = memShared if memShared else None
        ## Buffer memory used for temporary data.
        memBuffer = int(self.get_oid(".1.3.6.1.4.1.2021.4.14.0"))
        mem['memBuffer'] = memBuffer if memBuffer else None
        ## Cached memory (used for speeding up file access).
        memCached = int(self.get_oid(".1.3.6.1.4.1.2021.4.15.0"))
        mem['memCached'] = memCached if memCached else None
                                            
        return mem

    @property
    def get_cpuMetrics(self) -> dict:
        """
        CPU Metrics
        """
        cpu = {}
        # CPU Utilization (Percentage)
        ## Percentage of CPU time spent in user mode (processing applications)
        ssCpuUser = int(self.get_oid(".1.3.6.1.4.1.2021.11.9.0"))
        cpu['ssCpuUser'] = ssCpuUser if ssCpuUser != None else None
        ## Percentage of CPU time spent in system mode (kernel operations)
        ssCpuSystem = int(self.get_oid(".1.3.6.1.4.1.2021.11.10.0"))
        cpu['ssCpuSystem'] = ssCpuSystem if ssCpuSystem != None else None
        ## Percentage of CPU time the system is idle.
        ssCpuIdle = int(self.get_oid(".1.3.6.1.4.1.2021.11.11.0"))
        cpu['ssCpuIdle'] = ssCpuIdle if ssCpuIdle != None else None

        # CPU & Interrupts
        ## interrupts per second
        ssSysInterrupts = int(self.get_oid(".1.3.6.1.4.1.2021.11.7.0"))
        cpu['ssSysInterrupts'] = ssSysInterrupts if ssSysInterrupts else None
        ## context switches per second
        ssSysContext = int(self.get_oid(".1.3.6.1.4.1.2021.11.8.0"))
        cpu['ssSysContext'] = ssSysContext if ssSysContext else None

        return cpu

    @property
    def get_LoadAvg(self) -> list[float]:
        """
        Load Average
        """
        load_avg = {}
        # load average in 1 minute
        load_avg1 = self.get_oid(".1.3.6.1.4.1.2021.10.1.3.1")
        load_avg['load_avg1'] = float(load_avg1) if load_avg1 else None
        # load average in 5 minutes
        load_avg5 = self.get_oid(".1.3.6.1.4.1.2021.10.1.3.2")
        load_avg['load_avg5'] = float(load_avg5) if load_avg5 else None
        # load average in 15 minutes
        load_avg15 = self.get_oid(".1.3.6.1.4.1.2021.10.1.3.3")
        load_avg['load_avg15'] = float(load_avg15) if load_avg15 else None

        return load_avg

    # Interface Metrics

        """
        Interface IP Address and Netmask
        """
        # The index value which uniquely identifies the interface to which this entry is applicable.
        ipAdEntIfIndex_oid = "1.3.6.1.2.1.4.20.1.2"
        ipAdEntIfIndex = self.walk_oid(ipAdEntIfIndex_oid)

        if ipAdEntIfIndex:

            ipaddr_list = []
            ipAdEntNetMask_oid = "1.3.6.1.2.1.4.20.1.3"
            for ip in ipAdEntIfIndex:
                
                ipaddr = {}
                # The index value which uniquely identifies the interface to which this entry is applicable.
                ipaddr['ifIndex'] = int(ip[1])
                # The name of the interface.
                ipaddr['descr'] = str(self.get_oid(f".1.3.6.1.2.1.2.2.1.2.{ipaddr['ifIndex']}")) if ipaddr['ifIndex'] != None else None
                # The IP address to which this entry's information pertains.
                ipaddr['ipAddress'] = str(ip[0][len(ipAdEntIfIndex_oid)+1:]) if ip[0] != None else None
                # The subnet mask associated with the IP address of this entry.
                ipaddr['netmask'] = str(self.get_oid(f"{ipAdEntNetMask_oid}.{ipaddr['ipAddress']}")) if ipaddr['ipAddress'] != None else None

                ipaddr_list.append(ipaddr)
            # Sort by interface index
            ipaddr_list.sort(key=lambda x: x['ifIndex'])

            return ipaddr_list
        return None

    # Interface Metrics
    @property
    def get_ifType(self) -> list[dict]:
        """
        Interface Type  (Ethernet, Loopback, etc.)
        """
        if_root_oid = ".1.3.6.1.2.1.2.2.1"
        iface_indices = self.walk_oid(f"{if_root_oid}.1")

        if not iface_indices:
            return None

        iface_metrics = []
        for oid, id in iface_indices:
            iface = {}
            iface['Index'] = int(id)

            # The name of the interface.
            descr = self.get_oid(f"{if_root_oid}.2.{id}")
            iface['descr'] = str(descr) if descr else None

            # The type of interface.
            type = self.get_oid(f"{if_root_oid}.3.{id}")
            iface['type'] = get_iftype_description(int(type)) if type != None else None

            iface_metrics.append(iface)
        
        iface_metrics.sort(key=lambda x: x['Index'])
        return iface_metrics

    @property
    def get_ifMtu(self) -> list[dict]:
        """
        Interface MTU (Maximum Transmission Unit)
        """
        if_root_oid = ".1.3.6.1.2.1.2.2.1"
        iface_indices = self.walk_oid(f"{if_root_oid}.1")

        if not iface_indices:
            return None

        iface_metrics = []
        for oid, id in iface_indices:
            iface = {}
            iface['Index'] = int(id)

            # The name of the interface.
            descr = self.get_oid(f"{if_root_oid}.2.{id}")
            iface['descr'] = str(descr) if descr else None

            # The size of the largest packet that can be sent/received on the interface.
            mtu = self.get_oid(f"{if_root_oid}.4.{id}")
            iface['mtu'] = int(mtu) if mtu != None else None

            iface_metrics.append(iface)

        iface_metrics.sort(key=lambda x: x['Index'])
        return iface_metrics

    @property
    def get_ifSpeed(self) -> list[dict]:
        """
        Interface Speed (bits per second)
        """
        if_root_oid = ".1.3.6.1.2.1.2.2.1"
        iface_indices = self.walk_oid(f"{if_root_oid}.1")

        if not iface_indices:
            return None

        iface_metrics = []
        for oid, id in iface_indices:
            iface = {}
            iface['Index'] = int(id)

            # The name of the interface.
            descr = self.get_oid(f"{if_root_oid}.2.{id}")
            iface['descr'] = str(descr) if descr else None

            # The speed of the interface in bits per second.
            speed = int(self.get_oid(f"{if_root_oid}.5.{id}"))
            iface['speed'] = int(speed) if speed != None else None

            iface_metrics.append(iface)
        
        iface_metrics.sort(key=lambda x: x['Index'])
        return iface_metrics

    @property
    def get_ifPhysAddress(self) -> list[dict]:
        """
        Interface Physical Address (MAC Address)
        """
        if_root_oid = ".1.3.6.1.2.1.2.2.1"
        iface_indices = self.walk_oid(f"{if_root_oid}.1")

        if not iface_indices:
            return None

        iface_metrics = []
        for oid, id in iface_indices:
            iface = {}
            iface['Index'] = int(id)

            # The name of the interface.
            descr = self.get_oid(f"{if_root_oid}.2.{id}")
            iface['descr'] = str(descr) if descr else None

            # The interface's address at the protocol layer immediately 'below' the network layer in the protocol stack.
            PhysAddress = str(self.get_oid(f"{if_root_oid}.6.{id}"))
            iface['PhysAddress'] = None
            if PhysAddress:
                iface['PhysAddress'] = (":".join([PhysAddress[i:i+2] for i in range(0, len(PhysAddress), 2)])).replace("0x:", "")

            iface_metrics.append(iface)
        
        iface_metrics.sort(key=lambda x: x['Index'])
        return iface_metrics

    @property
    def get_ifAdminStatus(self) -> list[dict]:
        """
        Interface Admin Status (Up, Down)
        The current operational state of the interface
        """
        if_root_oid = ".1.3.6.1.2.1.2.2.1"
        iface_indices = self.walk_oid(f"{if_root_oid}.1")

        if not iface_indices:
            return None

        iface_metrics = []
        for oid, id in iface_indices:
            iface = {}
            iface['Index'] = int(id)

            # The name of the interface.
            descr = self.get_oid(f"{if_root_oid}.2.{id}")
            iface['descr'] = str(descr) if descr else None

            # The current operational state of the interface.
            AdminStatus = int(self.get_oid(f"{if_root_oid}.7.{id}"))
            iface['AdminStatus'] = get_ifAdminStatus_description(AdminStatus) if AdminStatus != None else None

            iface_metrics.append(iface)
        
        iface_metrics.sort(key=lambda x: x['Index'])
        return iface_metrics

    @property
    def get_ifOperStatus(self) -> list[dict]:
        """
        Interface Operational Status (Up, Down)
        """
        if_root_oid = ".1.3.6.1.2.1.2.2.1"
        iface_indices = self.walk_oid(f"{if_root_oid}.1")

        if not iface_indices:
            return None

        iface_metrics = []
        for oid, id in iface_indices:
            iface = {}
            iface['Index'] = int(id)

            # The name of the interface.
            descr = self.get_oid(f"{if_root_oid}.2.{id}")
            iface['descr'] = str(descr) if descr else None

            # The current operational state of the interface.
            OperStatus = int(self.get_oid(f"{if_root_oid}.8.{id}"))
            iface['OperStatus'] = get_ifOperStatus_description(OperStatus) if OperStatus != None else None

            iface_metrics.append(iface)
        
        iface_metrics.sort(key=lambda x: x['Index'])
        return iface_metrics

    @property
    def get_ifLastChange(self) -> list[dict]:
        """
        Interface Last Change
        """
        if_root_oid = ".1.3.6.1.2.1.2.2.1"
        iface_indices = self.walk_oid(f"{if_root_oid}.1")

        if not iface_indices:
            return None

        iface_metrics = []
        for oid, id in iface_indices:
            iface = {}
            iface['Index'] = int(id)

            # The name of the interface.
            descr = self.get_oid(f"{if_root_oid}.2.{id}")
            iface['descr'] = str(descr) if descr else None

            # The value of sysUpTime at the time the interface entered its current operational state.
            LastChange = int(self.get_oid(f"{if_root_oid}.9.{id}"))
            iface['LastChange'] = LastChange if LastChange != None else None

            iface_metrics.append(iface)
        
        iface_metrics.sort(key=lambda x: x['Index'])
        return iface_metrics

    @property
    def get_ifIOOctets(self) -> list[dict]:
        """
        Interface I/O Octets (Bytes)
        """
        if_root_oid = ".1.3.6.1.2.1.2.2.1"
        iface_indices = self.walk_oid(f"{if_root_oid}.1")

        if not iface_indices:
            return None

        iface_metrics = []
        for oid, id in iface_indices:
            iface = {}
            iface['Index'] = int(id)

            # The name of the interface.
            descr = self.get_oid(f"{if_root_oid}.2.{id}")
            iface['descr'] = str(descr) if descr else None

            # The total number of octets received on the interface, including framing characters.
            InOctets = int(self.get_oid(f"{if_root_oid}.10.{id}"))
            iface['InOctets'] = int(InOctets) if InOctets != None else None

            # The total number of octets transmitted out of the interface, including framing characters.
            OutOctets = int(self.get_oid(f"{if_root_oid}.16.{id}"))
            iface['OutOctets'] = int(OutOctets) if OutOctets != None else None

            iface_metrics.append(iface)
        
        iface_metrics.sort(key=lambda x: x['Index'])
        return iface_metrics

    @property
    def get_ifIOErrors(self) -> list[dict]:
        """
        Interface I/O Errors
        """
        if_root_oid = ".1.3.6.1.2.1.2.2.1"
        iface_indices = self.walk_oid(f"{if_root_oid}.1")

        if not iface_indices:
            return None

        iface_metrics = []
        for oid, id in iface_indices:
            iface = {}
            iface['Index'] = int(id)

            # The name of the interface.
            descr = self.get_oid(f"{if_root_oid}.2.{id}")
            iface['descr'] = str(descr) if descr else None

            # The number of inbound packets that contained errors preventing them from being deliverable to a higher-layer protocol.
            InErrors = int(self.get_oid(f"{if_root_oid}.14.{id}"))
            iface['InErrors'] = int(InErrors) if InErrors != None else None

            # The number of outbound packets that could not be transmitted because of errors.
            OutErrors = int(self.get_oid(f"{if_root_oid}.20.{id}"))
            iface['OutErrors'] = int(OutErrors) if OutErrors != None else None

            iface_metrics.append(iface)

        iface_metrics.sort(key=lambda x: x['Index'])
        return iface_metrics
    
    @property
    def get_ifIODiscards(self) -> list[dict]:
        """
        Interface Discards
        """
        if_root_oid = ".1.3.6.1.2.1.2.2.1"
        iface_indices = self.walk_oid(f"{if_root_oid}.1")

        if not iface_indices:
            return None

        iface_metrics = []
        for oid, id in iface_indices:
            iface = {}
            iface['Index'] = int(id)

            # The name of the interface.
            descr = self.get_oid(f"{if_root_oid}.2.{id}")
            iface['descr'] = str(descr) if descr else None

            # The number of inbound packets which were chosen to be discarded even though no errors had been detected to prevent their being delivered.
            InDiscards = int(self.get_oid(f"{if_root_oid}.13.{id}"))
            iface['InDiscards'] = int(InDiscards) if InDiscards != None else None

            # The number of outbound packets which were chosen to be discarded even though no errors had been detected to prevent their being transmitted.
            OutDiscards = int(self.get_oid(f"{if_root_oid}.19.{id}"))
            iface['OutDiscards'] = int(OutDiscards) if OutDiscards != None else None

            iface_metrics.append(iface)
        
        iface_metrics.sort(key=lambda x: x['Index'])
        return iface_metrics

    @property
    def get_ifUnknownProtos(self) -> list[dict]:
        """
        Interface Unknown Protocols
        """
        if_root_oid = ".1.3.6.1.2.1.2.2.1"
        iface_indices = self.walk_oid(f"{if_root_oid}.1")

        if not iface_indices:
            return None

        iface_metrics = []
        for oid, id in iface_indices:
            iface = {}
            iface['Index'] = int(id)

            # The name of the interface.
            descr = self.get_oid(f"{if_root_oid}.2.{id}")
            iface['descr'] = str(descr) if descr else None

            # The number of packets received via the interface which were discarded because of an unknown or unsupported protocol.
            InUnknownProtos = int(self.get_oid(f"{if_root_oid}.15.{id}"))
            iface['InUnknownProtos'] = int(InUnknownProtos) if InUnknownProtos != None else None

            iface_metrics.append(iface)
        
        iface_metrics.sort(key=lambda x: x['Index'])
        return iface_metrics

    @property
    def get_ifNUcastPkts(self) -> list[dict]:
        """
        Interface Inbound Non-Unicast Packets
        """
        if_root_oid = ".1.3.6.1.2.1.2.2.1"
        iface_indices = self.walk_oid(f"{if_root_oid}.1")

        if not iface_indices:
            return None

        iface_metrics = []
        for oid, id in iface_indices:
            iface = {}
            iface['Index'] = int(id)

            # The name of the interface.
            descr = self.get_oid(f"{if_root_oid}.2.{id}")
            iface['descr'] = str(descr) if descr else None

            # The number of packets, delivered by this sub-layer to a higher (sub-)layer, which were addressed to a multicast address at this sub-layer.
            InNUcastPkts = int(self.get_oid(f"{if_root_oid}.12.{id}"))
            iface['InNUcastPkts'] = int(InNUcastPkts) if InNUcastPkts != None else None

            # The total number of packets that higher-level protocols requested be transmitted to a sub-layer (i.e., the number of packets passed to the MAC service provider).
            OutNUcastPkts = int(self.get_oid(f"{if_root_oid}.18.{id}"))
            iface['OutNUcastPkts'] = int(OutNUcastPkts) if OutNUcastPkts != None else None

            iface_metrics.append(iface)

        iface_metrics.sort(key=lambda x: x['Index'])
        return iface_metrics

    @property
    def get_ifUcastPkts(self) -> list[dict]:
        """
        Interface Inbound Unicast Packets
        """
        if_root_oid = ".1.3.6.1.2.1.2.2.1"
        iface_indices = self.walk_oid(f"{if_root_oid}.1")

        if not iface_indices:
            return None

        iface_metrics = []
        for oid, id in iface_indices:
            iface = {}
            iface['Index'] = int(id)

            # The name of the interface.
            descr = self.get_oid(f"{if_root_oid}.2.{id}")
            iface['descr'] = str(descr) if descr else None

            # The number of packets, delivered by this sub-layer to a higher (sub-)layer, which were not addressed to a multicast or broadcast address at this sub-layer.
            InUcastPkts = int(self.get_oid(f"{if_root_oid}.11.{id}"))
            iface['InUcastPkts'] = int(InUcastPkts) if InUcastPkts != None else None
            
            # The total number of packets that higher-level protocols requested be transmitted to a sub-layer (i.e., the number of packets passed to the MAC service provider).
            OutUcastPkts = int(self.get_oid(f"{if_root_oid}.17.{id}"))
            iface['OutUcastPkts'] = int(OutUcastPkts) if OutUcastPkts != None else None

            iface_metrics.append(iface)

        iface_metrics.sort(key=lambda x: x['Index'])
        return iface_metrics

    @property
    def get_ifOutQLen(self) -> list[dict]:
        """
        The length of the output packet queue (in packets).
        """
        if_root_oid = ".1.3.6.1.2.1.2.2.1"
        iface_indices = self.walk_oid(f"{if_root_oid}.1")

        if not iface_indices:
            return None

        iface_metrics = []
        for oid, id in iface_indices:
            iface = {}
            iface['Index'] = int(id)

            # The name of the interface.
            descr = self.get_oid(f"{if_root_oid}.2.{id}")
            iface['descr'] = str(descr) if descr else None

            # The length of the output packet queue (in packets).
            OutQLen = int(self.get_oid(f"{if_root_oid}.21.{id}"))
            iface['OutQLen'] = int(OutQLen) if OutQLen != None else None

            iface_metrics.append(iface)
        
        iface_metrics.sort(key=lambda x: x['Index'])
        return iface_metrics

    @property
    def get_ifIPAddress(self) -> list[dict]:
        """
        Interface IP Address and Netmask
        """
        # The index value which uniquely identifies the interface to which this entry is applicable.
        ipAdEntIfIndex_oid = "1.3.6.1.2.1.4.20.1.2"
        ipAdEntIfIndex = self.walk_oid(ipAdEntIfIndex_oid)

        if not ipAdEntIfIndex:
            return None

        ipaddr_list = []
        ipAdEntNetMask_oid = "1.3.6.1.2.1.4.20.1.3"
        for ip in ipAdEntIfIndex:
            
            ipaddr = {}
            # The index value which uniquely identifies the interface to which this entry is applicable.
            ipaddr['ifIndex'] = int(ip[1])
            # The name of the interface.
            ipaddr['descr'] = str(self.get_oid(f".1.3.6.1.2.1.2.2.1.2.{ipaddr['ifIndex']}")) if ipaddr['ifIndex'] != None else None
            # The IP address to which this entry's information pertains.
            ipaddr['ipAddress'] = str(ip[0][len(ipAdEntIfIndex_oid)+1:]) if ip[0] != None else None
            # The subnet mask associated with the IP address of this entry.
            ipaddr['netmask'] = str(self.get_oid(f"{ipAdEntNetMask_oid}.{ipaddr['ipAddress']}")) if ipaddr['ipAddress'] != None else None

            ipaddr_list.append(ipaddr)

        # Sort by interface index
        ipaddr_list.sort(key=lambda x: x['ifIndex'])
        return ipaddr_list
 