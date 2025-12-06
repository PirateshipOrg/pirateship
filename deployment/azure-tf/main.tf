# Copyright (c) Shubham Mishra. All rights reserved.
# Licensed under the MIT License.

resource "random_pet" "rg_name" {
  prefix = var.resource_group_name_prefix
}

resource "azurerm_resource_group" "rg" {
  location = var.resource_group_location
  name     = random_pet.rg_name.id
}

# Create virtual networks
resource "azurerm_virtual_network" "pft_vnet" {
  name                = "pftVnet${count.index}"
  count               = length(var.platform_locations)
  address_space       = ["10.${count.index + 1}.0.0/16"]
  location            = var.platform_locations[count.index]
  resource_group_name = azurerm_resource_group.rg.name
}

# Create subnets
resource "azurerm_subnet" "sevpool_subnet" {
  name                 = "sevpoolSubnet${count.index}"
  count                = length(var.platform_locations)
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.pft_vnet[count.index].name
  address_prefixes     = ["10.${count.index + 1}.1.0/24"]
}

resource "azurerm_subnet" "tdxpool_subnet" {
  name                 = "tdxpoolSubnet${count.index}"
  count                = length(var.platform_locations)
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.pft_vnet[count.index].name
  address_prefixes     = ["10.${count.index + 1}.2.0/24"]
}

resource "azurerm_subnet" "clientpool_subnet" {
  name                 = "clientpoolSubnet${count.index}"
  count                = length(var.platform_locations)
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.pft_vnet[count.index].name
  address_prefixes     = ["10.${count.index + 1}.3.0/24"]
}

resource "azurerm_subnet" "nonteepool_subnet" {
  name                 = "nonteepoolSubnet${count.index}"
  count                = length(var.platform_locations)
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.pft_vnet[count.index].name
  address_prefixes     = ["10.${count.index + 1}.4.0/24"]
}


# Connect all virtual networks together using global peering
resource "azurerm_virtual_network_peering" "peering" {
  count                        = length(local.platform_location_crossproduct_)
  name                         = "peering-${local.platform_location_crossproduct_[count.index][0]}-${local.platform_location_crossproduct_[count.index][1]}"
  resource_group_name          = azurerm_resource_group.rg.name
  virtual_network_name         = element(azurerm_virtual_network.pft_vnet.*.name, local.platform_location_crossproduct_[count.index][0])
  remote_virtual_network_id    = element(azurerm_virtual_network.pft_vnet.*.id, local.platform_location_crossproduct_[count.index][1])
  allow_virtual_network_access = true
  allow_forwarded_traffic      = true

  # `allow_gateway_transit` must be set to false for vnet Global Peering
  allow_gateway_transit = false

}

# Create public IPs
resource "azurerm_public_ip" "sevpool_public_ip" {
  name                = "sevpoolPublicIp_${local.sevpool_ids_flattened_[count.index][0]}_${local.sevpool_ids_flattened_[count.index][1]}"
  count               = length(local.sevpool_ids_flattened_)
  location            = var.platform_locations[local.sevpool_ids_flattened_[count.index][0]]
  resource_group_name = azurerm_resource_group.rg.name
  # allocation_method   = "Dynamic"
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_public_ip" "tdxpool_public_ip" {
  name                = "tdxpoolPublicIp_${local.tdxpool_ids_flattened_[count.index][0]}_${local.tdxpool_ids_flattened_[count.index][1]}"
  count               = length(local.tdxpool_ids_flattened_)
  location            = var.platform_locations[local.tdxpool_ids_flattened_[count.index][0]]
  resource_group_name = azurerm_resource_group.rg.name
  # allocation_method   = "Dynamic"
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_public_ip" "clientpool_public_ip" {
  name                = "clientpoolPublicIp_${local.clientpool_ids_flattened_[count.index][0]}_${local.clientpool_ids_flattened_[count.index][1]}"
  count               = length(local.clientpool_ids_flattened_)
  location            = var.platform_locations[local.clientpool_ids_flattened_[count.index][0]]
  resource_group_name = azurerm_resource_group.rg.name
  # allocation_method   = "Dynamic"
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_public_ip" "nonteepool_public_ip" {
  name                = "nonteepoolPublicIp_${local.nonteepool_ids_flattened_[count.index][0]}_${local.nonteepool_ids_flattened_[count.index][1]}"
  count               = length(local.nonteepool_ids_flattened_)
  location            = var.platform_locations[local.nonteepool_ids_flattened_[count.index][0]]
  resource_group_name = azurerm_resource_group.rg.name
  # allocation_method   = "Dynamic"
  allocation_method   = "Static"
  sku                 = "Standard"
}


# Create Network Security Group and rule
resource "azurerm_network_security_group" "pft_nsg" {
  name                = "pftNetworkSecurityGroup${count.index}"
  count               = length(var.platform_locations)
  location            = var.platform_locations[count.index]
  resource_group_name = azurerm_resource_group.rg.name

  security_rule {
    name                       = "SSH"
    priority                   = 1001
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "K3S"
    priority                   = 1002
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_ranges    = ["6443", "10250", "2379", "2380"]
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "K3SFlannel"
    priority                   = 1003
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Udp"
    source_port_range          = "*"
    destination_port_ranges    = ["8472", "51820", "51821"]
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "PFT"
    priority                   = 1004
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "2000-9000"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

# Create network interface
resource "azurerm_network_interface" "sevpool_nic" {
  name                = "sevpoolNic_${local.sevpool_ids_flattened_[count.index][0]}_${local.sevpool_ids_flattened_[count.index][1]}"
  count               = length(local.sevpool_ids_flattened_)
  location            = var.platform_locations[local.sevpool_ids_flattened_[count.index][0]]
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "sevpool_nic_configuration_${local.sevpool_ids_flattened_[count.index][0]}_${local.sevpool_ids_flattened_[count.index][1]}"
    subnet_id                     = azurerm_subnet.sevpool_subnet[local.sevpool_ids_flattened_[count.index][0]].id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.sevpool_public_ip[count.index].id
  }
}

resource "azurerm_network_interface" "tdxpool_nic" {
  name                = "tdxpoolNic_${local.tdxpool_ids_flattened_[count.index][0]}_${local.tdxpool_ids_flattened_[count.index][1]}"
  count               = length(local.tdxpool_ids_flattened_)
  location            = var.platform_locations[local.tdxpool_ids_flattened_[count.index][0]]
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "tdxpool_nic_configuration_${local.tdxpool_ids_flattened_[count.index][0]}_${local.tdxpool_ids_flattened_[count.index][1]}"
    subnet_id                     = azurerm_subnet.tdxpool_subnet[local.tdxpool_ids_flattened_[count.index][0]].id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.tdxpool_public_ip[count.index].id
  }
}

resource "azurerm_network_interface" "nonteepool_nic" {
  name                = "nonteepoolNic_${local.nonteepool_ids_flattened_[count.index][0]}_${local.nonteepool_ids_flattened_[count.index][1]}"
  count               = length(local.nonteepool_ids_flattened_)
  location            = var.platform_locations[local.nonteepool_ids_flattened_[count.index][0]]
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "nonteepool_nic_configuration_${local.nonteepool_ids_flattened_[count.index][0]}_${local.nonteepool_ids_flattened_[count.index][1]}"
    subnet_id                     = azurerm_subnet.nonteepool_subnet[local.nonteepool_ids_flattened_[count.index][0]].id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.nonteepool_public_ip[count.index].id
  }
}

resource "azurerm_network_interface" "clientpool_nic" {
  name                = "clientpoolNic_${local.clientpool_ids_flattened_[count.index][0]}_${local.clientpool_ids_flattened_[count.index][1]}"
  count               = length(local.clientpool_ids_flattened_)
  location            = var.platform_locations[local.clientpool_ids_flattened_[count.index][0]]
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "clientpool_nic_configuration_${local.clientpool_ids_flattened_[count.index][0]}_${local.clientpool_ids_flattened_[count.index][1]}"
    subnet_id                     = azurerm_subnet.clientpool_subnet[local.clientpool_ids_flattened_[count.index][0]].id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.clientpool_public_ip[count.index].id
  }
}


# Connect the security group to the network interface

resource "azurerm_network_interface_security_group_association" "sevpool_nic_group_assoc" {
  count                     = length(local.sevpool_ids_flattened_)
  network_interface_id      = azurerm_network_interface.sevpool_nic[count.index].id
  network_security_group_id = azurerm_network_security_group.pft_nsg[local.sevpool_ids_flattened_[count.index][0]].id
}

resource "azurerm_network_interface_security_group_association" "tdxpool_nic_group_assoc" {
  count                     = length(local.tdxpool_ids_flattened_)
  network_interface_id      = azurerm_network_interface.tdxpool_nic[count.index].id
  network_security_group_id = azurerm_network_security_group.pft_nsg[local.tdxpool_ids_flattened_[count.index][0]].id
}

resource "azurerm_network_interface_security_group_association" "clientpool_nic_group_assoc" {
  count                     = length(local.clientpool_ids_flattened_)
  network_interface_id      = azurerm_network_interface.clientpool_nic[count.index].id
  network_security_group_id = azurerm_network_security_group.pft_nsg[local.clientpool_ids_flattened_[count.index][0]].id
}

resource "azurerm_network_interface_security_group_association" "nonteepool_nic_group_assoc" {
  count                     = length(local.nonteepool_ids_flattened_)
  network_interface_id      = azurerm_network_interface.nonteepool_nic[count.index].id
  network_security_group_id = azurerm_network_security_group.pft_nsg[local.nonteepool_ids_flattened_[count.index][0]].id
}

# Create managed disk
resource "azurerm_managed_disk" "sevpool_disk" {
  name                 = "sevpoolDataDisk${count.index}"
  count                = length(local.sevpool_ids_flattened_)
  location             = var.platform_locations[local.sevpool_ids_flattened_[count.index][0]]
  resource_group_name  = azurerm_resource_group.rg.name
  storage_account_type = "Premium_LRS"
  disk_size_gb         = 2048 # P40 ssd Gives enough throughput for NIC bottleneck in 7+ machine clusters.
  create_option = "Empty"
}

resource "azurerm_managed_disk" "tdxpool_disk" {
  name                 = "tdxpoolDataDisk${count.index}"
  count                = length(local.tdxpool_ids_flattened_)
  location             = var.platform_locations[local.tdxpool_ids_flattened_[count.index][0]]
  resource_group_name  = azurerm_resource_group.rg.name
  storage_account_type = "Premium_LRS"
  disk_size_gb         = 2048 # P40 ssd Gives enough throughput for NIC bottleneck in 7+ machine clusters.
  create_option = "Empty"
}

resource "azurerm_managed_disk" "nonteepool_disk" {
  name                 = "nonteepoolDataDisk${count.index}"
  count                = length(local.nonteepool_ids_flattened_)
  location             = var.platform_locations[local.nonteepool_ids_flattened_[count.index][0]]
  resource_group_name  = azurerm_resource_group.rg.name
  storage_account_type = "Premium_LRS"
  disk_size_gb         = 2048 # P40 ssd Gives enough throughput for NIC bottleneck in 7+ machine clusters.
  create_option = "Empty"
}

resource "azurerm_managed_disk" "clientpool_disk" {
  name                 = "clientpoolDataDisk${count.index}"
  count                = length(local.clientpool_ids_flattened_)
  location             = var.platform_locations[local.clientpool_ids_flattened_[count.index][0]]
  resource_group_name  = azurerm_resource_group.rg.name
  storage_account_type = "StandardSSD_LRS"
  disk_size_gb         = 4 # Clients do not need much space.
  create_option = "Empty"
}

# Create virtual machine
resource "azurerm_linux_virtual_machine" "sevpool_vm" {
  name                  = "nodepool_vm${count.index}_sev_loc${local.sevpool_ids_flattened_[count.index][0]}_id${local.sevpool_ids_flattened_[count.index][1]}"
  count                 = length(local.sevpool_ids_flattened_)
  location              = var.platform_locations[local.sevpool_ids_flattened_[count.index][0]]
  resource_group_name   = azurerm_resource_group.rg.name
  network_interface_ids = [azurerm_network_interface.sevpool_nic[count.index].id]
  size                  = "Standard_DC16ads_v5"
  # size                  = "Standard_EC16eds_v5"

#   delete_os_disk_on_termination    = true
  # delete_data_disks_on_termination = true
  # priority = "Spot"
  # eviction_policy = "Deallocate"

  os_disk {
    name                 = "sevpool_disk${count.index}"
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
    security_encryption_type = "DiskWithVMGuestState"
  }


  source_image_reference {
    publisher = "canonical"
    offer = "0001-com-ubuntu-confidential-vm-jammy"
    sku = "22_04-lts-cvm"
    version = "latest"
  }

  computer_name  = "sev${count.index}"
  admin_username = var.username
  vtpm_enabled = true
  secure_boot_enabled = true
  # encryption_at_host_enabled = true


  admin_ssh_key {
    username   = var.username
    public_key = azapi_resource_action.ssh_public_key_gen.output.publicKey
  }

  # boot_diagnostics {
  #   storage_account_uri = azurerm_storage_account.psl_diag_storage_account.primary_blob_endpoint
  # }

  custom_data = filebase64("./init.sh")
}

resource "azurerm_virtual_machine_data_disk_attachment" "sevpool_vm_disk_attach" {
  count               = length(local.sevpool_ids_flattened_)
  managed_disk_id     = azurerm_managed_disk.sevpool_disk[count.index].id
  virtual_machine_id  = azurerm_linux_virtual_machine.sevpool_vm[count.index].id
  caching             = "ReadOnly"
  lun = 42
}

resource "azurerm_linux_virtual_machine" "tdxpool_vm" {
  name                  = "nodepool_vm${count.index}_tdx_loc${local.tdxpool_ids_flattened_[count.index][0]}_id${local.tdxpool_ids_flattened_[count.index][1]}"
  count                 = length(local.tdxpool_ids_flattened_)
  location              = var.platform_locations[local.tdxpool_ids_flattened_[count.index][0]]
  resource_group_name   = azurerm_resource_group.rg.name
  network_interface_ids = [azurerm_network_interface.tdxpool_nic[count.index].id]
  size                  = "Standard_DC16eds_v5"

#   delete_os_disk_on_termination    = true
#   delete_data_disks_on_termination = true
  # priority = "Spot"
  # eviction_policy = "Deallocate"

  os_disk {
    name                 = "tdxpool_disk${count.index}"
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
    security_encryption_type = "DiskWithVMGuestState"
  }

  source_image_reference {
    publisher = "canonical"
    offer = "ubuntu-24_04-lts"
    sku = "cvm"
    version = "latest"
  }

  computer_name  = "tdx${count.index}"
  admin_username = var.username
  vtpm_enabled = true
  secure_boot_enabled = true
  # encryption_at_host_enabled = true

  admin_ssh_key {
    username   = var.username
    public_key = azapi_resource_action.ssh_public_key_gen.output.publicKey
  }

  # boot_diagnostics {
  #   storage_account_uri = azurerm_storage_account.psl_diag_storage_account.primary_blob_endpoint
  # }

  custom_data = filebase64("./init.sh")
}

resource "azurerm_virtual_machine_data_disk_attachment" "tdxpool_vm_disk_attach" {
  count               = length(local.tdxpool_ids_flattened_)
  managed_disk_id     = azurerm_managed_disk.tdxpool_disk[count.index].id
  virtual_machine_id  = azurerm_linux_virtual_machine.tdxpool_vm[count.index].id
  caching             = "ReadOnly"
  lun = 42
}


resource "azurerm_linux_virtual_machine" "clientpool_vm" {
  name                  = "clientpool_vm${count.index}_loc${local.clientpool_ids_flattened_[count.index][0]}_id${local.clientpool_ids_flattened_[count.index][1]}"
  count                 = length(local.clientpool_ids_flattened_)
  location              = var.platform_locations[local.clientpool_ids_flattened_[count.index][0]]
  resource_group_name   = azurerm_resource_group.rg.name
  network_interface_ids = [azurerm_network_interface.clientpool_nic[count.index].id]
  size                  = "Standard_D8ds_v6"

#   delete_os_disk_on_termination    = true
#   delete_data_disks_on_termination = true
  # priority = "Spot"
  # eviction_policy = "Deallocate"

  os_disk {
    name                 = "clientpool_disk${count.index}"
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
  }

  # source_image_reference {
  #   publisher = "Canonical"
  #   offer     = "ubuntu-24_04-lts"
  #   sku       = "server"
  #   version   = "latest"
  # }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-focal"
    sku       = "20_04-lts-gen2"
    version   = "20.04.202410020"
  }
  

  computer_name  = "client${count.index}"
  admin_username = var.username

  admin_ssh_key {
    username   = var.username
    public_key = azapi_resource_action.ssh_public_key_gen.output.publicKey
  }

  # boot_diagnostics {
  #   storage_account_uri = azurerm_storage_account.psl_diag_storage_account.primary_blob_endpoint
  # }

  custom_data = filebase64("./init.sh")
}

resource "azurerm_virtual_machine_data_disk_attachment" "clientpool_vm_disk_attach" {
  count               = length(local.clientpool_ids_flattened_)
  managed_disk_id     = azurerm_managed_disk.clientpool_disk[count.index].id
  virtual_machine_id  = azurerm_linux_virtual_machine.clientpool_vm[count.index].id
  caching             = "ReadOnly"
  lun = 42
}

resource "azurerm_linux_virtual_machine" "nonteepool_vm" {
  name                  = "nodepool_vm${count.index}_nontee_loc${local.nonteepool_ids_flattened_[count.index][0]}_id${local.nonteepool_ids_flattened_[count.index][1]}"
  count                 = length(local.nonteepool_ids_flattened_)
  location              = var.platform_locations[local.nonteepool_ids_flattened_[count.index][0]]
  resource_group_name   = azurerm_resource_group.rg.name
  network_interface_ids = [azurerm_network_interface.nonteepool_nic[count.index].id]
  size                  = "Standard_D16ads_v5"

#   delete_os_disk_on_termination    = true
#   delete_data_disks_on_termination = true
  # priority = "Spot"
  # eviction_policy = "Deallocate"

  os_disk {
    name                 = "nonteepool_disk${count.index}"
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "ubuntu-24_04-lts"
    sku       = "server"
    version   = "latest"
  }

  computer_name  = "nontee${count.index}"
  admin_username = var.username

  admin_ssh_key {
    username   = var.username
    public_key = azapi_resource_action.ssh_public_key_gen.output.publicKey
  }

  # boot_diagnostics {
  #   storage_account_uri = azurerm_storage_account.psl_diag_storage_account.primary_blob_endpoint
  # }

  custom_data = filebase64("./init.sh")
}

resource "azurerm_virtual_machine_data_disk_attachment" "nonteepool_vm_disk_attach" {
  count               = length(local.nonteepool_ids_flattened_)
  managed_disk_id     = azurerm_managed_disk.nonteepool_disk[count.index].id
  virtual_machine_id  = azurerm_linux_virtual_machine.nonteepool_vm[count.index].id
  caching             = "ReadOnly"
  lun = 42
}