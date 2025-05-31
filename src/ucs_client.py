import os
import subprocess
from ucsmsdk.ucschandle import UcsHandle
from ucsmsdk.mometa.compute.ComputeRackUnit import ComputeRackUnit


class UCSClient:
    def __init__(self, ucs_ip=None, username=None, password=None):
        self.ucs_ip = ucs_ip
        self.username = username
        self.password = password
        self.handle = None
        
    def connect(self):
        if not all([self.ucs_ip, self.username, self.password]):
            raise ValueError("UCS IP, username, and password must be provided")
            
        self.handle = UcsHandle(self.ucs_ip, self.username, self.password)
        self.handle.login()
        
    def get_all_servers(self):
        if not self.handle:
            raise RuntimeError("Not connected to UCS. Call connect() first.")
            
        servers = self.handle.query_classid("computeRackUnit")
        return servers

    def get_ucs_info_for_node(self, node, servers):
        print(f"Processing node: {node}")

        for server in servers:
            domain = server.dn.split("/")[0]
            rack_id = server.pn_dn.split("-")[-1] if hasattr(server, 'pn_dn') else ""             
            
            if node in server.name:
                ucsm_handle = UcsHandle(domain, self.username, self.password)
                ucsm_handle.login()
                try: 
                    server_details = ucsm_handle.query_dn(server.dn)
                    
                    kvm_ip = self._get_kvm_ip(ucsm_handle, server_details)
                    mac_address = self._get_mac_address(ucsm_handle, server_details)
                    
                    ucsm_handle.logout()
                    return mac_address, kvm_ip
                except Exception as e:
                    print(f"Error retrieving data for {node}: {str(e)}")
                finally:
                    ucsm_handle.logout()

    def _get_kvm_ip(self, ucsm_handle, server_details):
        mgmt_interfaces = ucsm_handle.query_children(in_mo=server_details, class_id="mgmtInterface")
        print(f"Management interfaces: {mgmt_interfaces}")
        
        kvm_ip = ""
        for iface in mgmt_interfaces:
            if hasattr(iface, 'ip_address') and iface.ip_address:
                kvm_ip = iface.ip_address
                break
        return kvm_ip

    def _get_mac_address(self, ucsm_handle, server_details):
        adapters = ucsm_handle.query_children(in_mo=server_details, class_id="adaptorUnit")
        
        mac_address = ""
        if adapters:
            vnics = ucsm_handle.query_children(in_mo=adapters[0], class_id="adaptorHostEthIf")
            print(f"vNICs: {vnics}")
            if vnics and hasattr(vnics[0], 'mac'):
                mac_address = vnics[0].mac
        return mac_address