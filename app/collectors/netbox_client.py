import pynetbox
import os
from dotenv import load_dotenv
from typing import List, Dict, Tuple, Any
from app.clients.vault_client import VaultClient

from loguru import logger


class NetboxClient:
    def __init__(self):

        vault = VaultClient()
        secret = vault.get_secret("netbox")
        self.url = secret.get("url", None)
        self.token = secret.get("token", None)

        if not self.url or not self.token:
            raise ValueError("[NetboxClient] Netbox credentials not found in vault")

        self.nb = pynetbox.api(self.url, token=self.token)
        self.nb.http_session.verify = False

    def _get_ip_address_info(self, ip_address):
        """Get IP address object and its information from Netbox."""
        ip_addresses = self.nb.ipam.ip_addresses.filter(address=ip_address)
        ip_addresses = list(ip_addresses)

        if not ip_addresses:
            logger.debug(f"No IP address object found for {ip_address}")
            return None

        return ip_addresses[0]

    def _get_parent_prefix_info(self, ip_address):
        """Get parent prefix/subnet information for an IP address."""
        parent_prefix = self.nb.ipam.prefixes.filter(contains=ip_address)
        parent_prefix = list(parent_prefix)
        if not parent_prefix:
            logger.debug(f"No parent prefix found for IP {ip_address}")
            return None
        return parent_prefix[0]

    def _build_ip_info(self, ip_address: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        ip_address_obj = self._get_ip_address_info(ip_address)
        parent_prefix = self._get_parent_prefix_info(ip_address)

        ip_info = {}
        prefix_info = {}

        if ip_address_obj:
            ip_info = {
                "dns_name": ip_address_obj.dns_name if ip_address_obj else None,
                "description": ip_address_obj.description if ip_address_obj else None,
            }

        if parent_prefix:
            prefix_info = {
                "name": parent_prefix.prefix if parent_prefix else None,
                "description": parent_prefix.description if parent_prefix else None,
                "vlan_id": parent_prefix.vlan.id if parent_prefix.vlan else None,
                "vlan_name": parent_prefix.vlan.name if parent_prefix.vlan else None,
                "vlan_display": (
                    parent_prefix.vlan.display if parent_prefix.vlan else None
                ),
            }

        return ip_info, prefix_info\

    def _get_device_vm_tags(self, device_vm):
        tags = []
        for tag in device_vm.tags:
            tags.append({
                "name": tag.name,
                "color": tag.color,
                "netbox_id": tag.id
                })
        return tags

    def get_all_hosts(self, only_windows=False) -> List[Dict]:
        """
        Get all devices and virtual machines from Netbox.

        Returns:
            List of dictionaries containing host information
        """
        logger.info("[NetBox] Collecting Devices...")
        
        hosts = []

        # Get all devices
        devices = self.nb.dcim.devices.all()
        

        for device in devices:
            
            if not device.primary_ip or not device.id:
                logger.debug(f"[NetBox] Skipping device {device.name} due to missing required fields")
                continue
            
            ip_info, prefix_info = self._build_ip_info(device.primary_ip.address)
            device_tags = self._get_device_vm_tags(device)
            
            manufacturer_name = device.device_type.manufacturer.name if device.device_type.manufacturer else None
            manufacturer_model = device.device_type.model if device.device_type else None

            hosts.append(
                {
                    "name": device.name,
                    "hostname": device.name,
                    "netbox_id": device.id,
                    "url": device.url if device.url else None,
                    "platform_os": device.platform.name if device.platform else None,
                    "ip": device.primary_ip.address if device.primary_ip else None,
                    "is_vm": False,
                    "cluster": None,  # No Cluster for Physical Device
                    "site": device.site.name if device.site else None,
                    "location": device.location.name if device.location else None,
                    "status": device.status.value if device.status else None,
                    "role": device.role.name if device.role else None,
                    "manufacturer": manufacturer_name,
                    "model": manufacturer_model,
                    "ip_info": ip_info,
                    "prefix_info": prefix_info, 
                    "tags": device_tags,
                }
            )
            

        no_physical_devices = len(hosts)
        logger.success(f"[NetBox] Collected {no_physical_devices} physical devices")
        
        # Get all virtual machines
        vms = self.nb.virtualization.virtual_machines.all()
        for vm in vms:
            
            if not vm.primary_ip or not vm.id:
                logger.debug(f"[NetBox] Skipping virtual machine {vm.name} due to missing required fields")
                continue

            ip_info, prefix_info = self._build_ip_info(vm.primary_ip.address)
            vm_tags = self._get_device_vm_tags(vm)

            hosts.append(
                {
                    "name": vm.name,
                    "hostname": vm.name,
                    "netbox_id": vm.id,
                    "url": vm.url if vm.url else None,
                    "platform_os": vm.platform.name if vm.platform else None,
                    "ip": vm.primary_ip.address if vm.primary_ip else None,
                    "is_vm": True,
                    "cluster": vm.cluster.name if vm.cluster else None,
                    "site": vm.site.name if vm.site else None,
                    "location": None, # Virtual Machines don't have a location
                    "status": vm.status.value if vm.status else None,
                    "role": vm.role.name if vm.role else None,
                    "manufacturer": None,  # VM has no manufacturer
                    "model": None,  # VM has no model
                    "ip_info": ip_info,
                    "prefix_info": prefix_info,
                    "tags": vm_tags,
                }
            )
        no_virtual_machines = len(hosts) - no_physical_devices
        logger.success(f"[NetBox] Collected {no_virtual_machines} virtual machines")
        logger.success(f"[NetBox] Collected {len(hosts)} devices in total")

        if only_windows:
            logger.warning("[NetBox] Filtering only Windows devices")
            hosts = [
                host
                for host in hosts
                if host["platform_os"] is not None
                and host["platform_os"].lower().startswith("windows")
            ]
            no_windows_devices = len(hosts)
            logger.success(f"[NetBox] Collected {no_windows_devices} Windows devices")

        return hosts
