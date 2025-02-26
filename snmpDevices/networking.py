from .snmp import snmpRead
from .snmpMibMapping import ( 
    get_iftype_description,
    get_ifOperStatus_description,
    get_ifAdminStatus_description
)

class ifaceMetrics(snmpRead):
    """
    Interface Metrics Class ISO/IEC 8802-3 (Ethernet)
    """

    def __init__(self,ip: str,port: int = 161,snmpv: int = 1,community: str = None,user: str = None,authkey: str = None,privkey: str = None):
        super().__init__(ip, port, snmpv, community, user, authkey, privkey)
        
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
    def get_ifAlias(self) -> list[dict]:
        """
        Interface Alias (Description)
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
            if_alias = str(self.get_oid(f".1.3.6.1.2.1.31.1.1.1.18.{id}"))
            iface['Alias'] = str(if_alias) if if_alias != None else None

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
            ipaddr['Index'] = int(ip[1])
            # The name of the interface.
            descr = self.get_oid(f".1.3.6.1.2.1.2.2.1.2.{ipaddr['Index']}")
            ipaddr['descr'] = str(descr) if descr != None else None
            # The IP address to which this entry's information pertains.
            ipaddr['ipAddress'] = str(ip[0][len(ipAdEntIfIndex_oid)+1:]) if ip[0] != None else None
            # The subnet mask associated with the IP address of this entry.
            ipaddr['netmask'] = str(self.get_oid(f"{ipAdEntNetMask_oid}.{ipaddr['ipAddress']}")) if ipaddr['ipAddress'] != None else None

            ipaddr_list.append(ipaddr)

        # Sort by interface index
        ipaddr_list.sort(key=lambda x: x['Index'])
        return ipaddr_list