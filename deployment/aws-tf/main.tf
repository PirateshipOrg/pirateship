# First create a VPC with Internet Gateway
# Allow SSH access and allow all traffic within the VPC

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support = true
  tags = {
    Name = local.vpc_name
    Project = local.project_name
  }
}

resource "aws_internet_gateway" "gateway" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = "${local.vpc_name}-internet-gateway"
    Project = local.project_name
  }
}

resource "aws_route" "route_to_internet" {
    route_table_id = aws_vpc.main.main_route_table_id
    destination_cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gateway.id
}

# Ports

resource "aws_security_group" "psl_sg" {
    name = "${local.project_name}-psl-sg"
    description = "Allow SSH and PSL ports"
    vpc_id = aws_vpc.main.id

    tags = {
        Name = "${local.project_name}-psl-sg"
        Project = local.project_name
    }
}

resource "aws_vpc_security_group_ingress_rule" "allow_ssh" {
    security_group_id = aws_security_group.psl_sg.id
    cidr_ipv4 = "0.0.0.0/0"
    from_port = 22
    to_port = 22
    ip_protocol = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "allow_default_egress" {
    security_group_id = aws_security_group.psl_sg.id
    cidr_ipv4 = "0.0.0.0/0"
    ip_protocol = "all"
}

resource "aws_vpc_security_group_ingress_rule" "allow_all_within_vpc" {
    security_group_id = aws_security_group.psl_sg.id
    cidr_ipv4 = aws_vpc.main.cidr_block
    ip_protocol = "all"
}


# Then create a subnet for each pool

resource "aws_subnet" "sevpool" {
  vpc_id = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"
  tags = {
    Name = local.sevpool_subnet_name
    Project = local.project_name
  }
}

resource "aws_subnet" "storagepool" {
  vpc_id = aws_vpc.main.id
  cidr_block = "10.0.2.0/24"
  tags = {
    Name = local.storagepool_subnet_name
    Project = local.project_name
  }
}

resource "aws_subnet" "clientpool" {
  vpc_id = aws_vpc.main.id
  cidr_block = "10.0.3.0/24"
  tags = {
    Name = local.clientpool_subnet_name
    Project = local.project_name
  }
}

# Generate a key pair for SSH

resource "tls_private_key" "ssh_key" {
    algorithm = "RSA"
    rsa_bits = 4096
}

resource "aws_key_pair" "ssh_key" {
    key_name = local.key_name
    public_key = tls_private_key.ssh_key.public_key_openssh
}


# Now the EC2 instances

data "aws_ami" "ubuntu_24_04" {
  most_recent = true
  owners      = ["099720109477"]

  # Ubuntu AMI ID search
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_instance" "sevpool" {
  ami = data.aws_ami.ubuntu_24_04.id

  # 4xlarge and lower do not have fixed network performance.
  instance_type = "m6a.4xlarge"
  subnet_id = aws_subnet.sevpool.id
  count = var.sevpool_count

  

  associate_public_ip_address = true

  key_name = aws_key_pair.ssh_key.key_name

  security_groups = [aws_security_group.psl_sg.id]

  tags = {
    Name = "${local.sevpool_instance_name}-${count.index}"
    InstanceGroup = local.sevpool_instance_name
    Project = local.project_name
  }

  cpu_options {
    amd_sev_snp = "enabled"
  }

  instance_market_options {
    market_type = "spot"
    spot_options {
      max_price = 1.6 # Set it to the on-demand price. For SEV SNP, they charge 10% higher.
      # This way the chance of getting evicted is lower.
    }
  }

  root_block_device {
    volume_size = 64 # GiB. Disk is not important for worker nodes. Still needed to save logs.
    # This is enough for sensible experiment schedules.
  }

    # Only deploy ebs block device if the flag is set.
    dynamic "ebs_block_device" {
        for_each = var.deploy_ebs_on_sevpool ? [1] : []
        content {
            device_name = "/dev/sdb" # AWS + Ubuntu 24.04 => The name for disk is /dev/nvme1n1; this name doesn't matter.
            volume_type = "gp3"
            volume_size = 1024 # GiB
            delete_on_termination = true
            throughput = 1000 # MiB/s
            iops = 16000 # This is the max for gp3.
        }
}

  user_data_base64 = filebase64("./init.sh")

  # Leave the rest of the config as default.
}

resource "aws_instance" "storagepool" {
  ami = data.aws_ami.ubuntu_24_04.id

  # 4xlarge and lower do not have fixed network performance.
  instance_type = "m6a.4xlarge"
  subnet_id = aws_subnet.storagepool.id
  count = var.storagepool_count

  

  associate_public_ip_address = true

  key_name = aws_key_pair.ssh_key.key_name

  security_groups = [aws_security_group.psl_sg.id]

  tags = {
    Name = "${local.storagepool_instance_name}-${count.index}"
    InstanceGroup = local.storagepool_instance_name
    Project = local.project_name
  }


  instance_market_options {
    market_type = "spot"
    spot_options {
      max_price = 1.6 # Set it to the on-demand price.
      # This way the chance of getting evicted is lower.
    }
  }

  root_block_device {
    volume_size = 64 # GiB. This will only be used for logs.
  }


  ebs_block_device {
    device_name = "/dev/sdb" # AWS + Ubuntu 24.04 => The name for disk is /dev/nvme1n1; this name doesn't matter.
    volume_type = "gp3"
    volume_size = 1024 # GiB
    delete_on_termination = true
    throughput = 1000 # MiB/s
    iops = 16000 # This is the max for gp3.
  }
  user_data_base64 = filebase64("./init.sh")

  # Leave the rest of the config as default.
}

resource "aws_instance" "clientpool" {
  ami = data.aws_ami.ubuntu_24_04.id

  # 4xlarge and lower do not have fixed network performance.
  # Client devices don't need much memory, but they need a compute. (For generating requests and compiling)
  # Because of this, we use the c6a family. Saves cost.
  instance_type = "c6a.4xlarge"
  subnet_id = aws_subnet.clientpool.id
  count = var.clientpool_count

  

  associate_public_ip_address = true

  key_name = aws_key_pair.ssh_key.key_name

  security_groups = [aws_security_group.psl_sg.id]

  tags = {
    Name = "${local.clientpool_instance_name}-${count.index}"
    InstanceGroup = local.clientpool_instance_name
    Project = local.project_name
  }


  instance_market_options {
    market_type = "spot"
    spot_options {
      max_price = 1.6 # Set it to the on-demand price.
      # This way the chance of getting evicted is lower.
    }
  }

  root_block_device {
    volume_size = 64 # GiB. Disk is not important for client nodes. Still needed to save logs.
    # is is enough for sensible experiment schedules.
  }


  
  user_data_base64 = filebase64("./init.sh")

  # Leave the rest of the config as default.
}