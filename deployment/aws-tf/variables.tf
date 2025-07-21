# Resource group in AWS seems to mean something different from Azure
# Hence using the name `project` here.
variable "project_prefix" {
  type = string
  default = "psl"
}

resource "random_pet" "rg_name" {
  prefix = var.project_prefix
}

variable "deploy_ebs_on_sevpool" {
  type = bool
  default = false
}

variable "sevpool_count" {
  type = number
  default = 1
}

variable "storagepool_count" {
  type = number
  default = 1
}

variable "clientpool_count" {
  type = number
  default = 1
}

locals {
  project_name = random_pet.rg_name.id
  vpc_name = "${local.project_name}-vpc"
  key_name = "${local.project_name}-key"
  sevpool_subnet_name = "${local.project_name}-sevpool-subnet"
  storagepool_subnet_name = "${local.project_name}-storagepool-subnet"
  clientpool_subnet_name = "${local.project_name}-clientpool-subnet"
  sevpool_instance_name = "${local.project_name}-sevpool"
  storagepool_instance_name = "${local.project_name}-storagepool"
  clientpool_instance_name = "${local.project_name}-clientpool"

}