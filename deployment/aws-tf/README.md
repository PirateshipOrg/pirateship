This is specific to PSL.

VM categories:
- `sevpool`: AMD SEV-SNP nodes m6a.4xlarge. These will not have too much storage in them, per PSL spec.
- `storagepool`: Nodes with big disks. No TEEs in them.
- `clientpool`: Same config (probably) as the storagepool, but no big disks. Used for clients.


Currently not supporting cross-region deployment.
Everything likely to be in US East (Ohio).

1 VPC with the following private IP configs:
- `sevpool` gets 10.0.1.0/24
- `storagepool` gets 10.0.2.0/24
- `clientpool` gets 10.0.3.0/24
