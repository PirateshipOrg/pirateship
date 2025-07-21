output "cluster_private_key" {
    value = tls_private_key.ssh_key.private_key_pem
    sensitive = true
}

output "cluster_public_key" {
    value = tls_private_key.ssh_key.public_key_pem
}

