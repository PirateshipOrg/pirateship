#!/usr/bin/env python3
# Copyright (c) Shubham Mishra. All rights reserved.
# Licensed under the MIT License.

"""
Generate local config files for a pirateship cluster.

Usage:
    python scripts/gen_local_config.py [OPTIONS]

Generates node configs, client configs, controller config,
TLS certificates, and Ed25519 signing keys into the output directory.
"""

import argparse
import json
import os
import shutil
import sys

# Allow importing sibling modules when run from repo root.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from crypto import gen_keys_and_certs, DEFAULT_CA_NAME

DEFAULT_NUM_NODES = 4
DEFAULT_NUM_CLIENTS = 1
DEFAULT_PORT_BASE = 3000
DEFAULT_OUTPUT_DIR = "configs"

DEFAULT_NODE_CONFIG = {
    "net_config": {
        "name": "",
        "addr": "",
        "tls_cert_path": "",
        "tls_key_path": "",
        "tls_root_ca_cert_path": "",
        "client_max_retry": 10,
        "nodes": {},
    },
    "rpc_config": {
        "allowed_keylist_path": "",
        "signing_priv_key_path": "",
        "recv_buffer_size": 32768,
        "channel_depth": 1000,
    },
    "consensus_config": {
        "node_list": [],
        "liveness_u": 1,
        "learner_list": [],
        "max_backlog_batch_size": 1000,
        "signature_max_delay_blocks": 50,
        "signature_max_delay_ms": 1000,
        "num_crypto_workers": 4,
        "view_timeout_ms": 5000,
        "batch_max_delay_ms": 20,
        "log_storage_config": {
            "RocksDB": {
                "db_path": "",
                "write_buffer_size": 2147483648,
                "max_write_buffer_number": 1,
                "max_write_buffers_to_merge": 1,
            }
        },
        "commit_index_gap_soft": 105,
        "commit_index_gap_hard": 250,
    },
    "app_config": {
        "logger_stats_report_ms": 1000,
        "checkpoint_interval_ms": 1000,
    },
    "evil_config": {
        "simulate_byzantine_behavior": False,
        "byzantine_start_block": 0,
    },
}

DEFAULT_CLIENT_CONFIG = {
    "full_duplex": True,
    "net_config": {
        "name": "",
        "tls_root_ca_cert_path": "",
        "client_max_retry": 10,
        "nodes": {},
    },
    "rpc_config": {
        "signing_priv_key_path": "",
    },
    "workload_config": {
        "num_clients": 50,
        "duration": 60,
        "max_concurrent_requests": 32,
        "request_config": "Blanks",
    },
}

DEFAULT_CONTROLLER_CONFIG = {
    "net_config": {
        "name": "controller",
        "tls_root_ca_cert_path": "",
        "client_max_retry": 10,
        "nodes": {},
    },
    "rpc_config": {
        "signing_priv_key_path": "",
    },
    "workload_config": {
        "num_clients": 1,
        "num_requests": 10000000,
    },
}


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate local pirateship cluster configs.",
    )
    parser.add_argument(
        "-n", "--num-nodes", type=int, default=DEFAULT_NUM_NODES,
        help=f"Number of nodes (default: {DEFAULT_NUM_NODES})",
    )
    parser.add_argument(
        "-c", "--num-clients", type=int, default=DEFAULT_NUM_CLIENTS,
        help=f"Number of client configs (default: {DEFAULT_NUM_CLIENTS})",
    )
    parser.add_argument(
        "-p", "--port-base", type=int, default=DEFAULT_PORT_BASE,
        help=f"Base port; node i listens on port_base + i (default: {DEFAULT_PORT_BASE})",
    )
    parser.add_argument(
        "-o", "--output-dir", type=str, default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory for configs (default: {DEFAULT_OUTPUT_DIR})",
    )
    parser.add_argument(
        "--host", type=str, default="127.0.0.1",
        help="IP address for inter-node communication (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--clean", action="store_true",
        help="Remove output directory before generating",
    )
    return parser.parse_args()


def generate(args):
    output_dir = args.output_dir
    num_nodes = args.num_nodes
    num_clients = args.num_clients
    port_base = args.port_base
    host = args.host

    if args.clean and os.path.exists(output_dir):
        shutil.rmtree(output_dir)

    os.makedirs(output_dir, exist_ok=True)

    # Build the node address/domain map used by crypto and configs.
    node_names = [f"node{i}" for i in range(1, num_nodes + 1)]
    node_list_for_crypto = {}
    nodes_map = {}
    for i, name in enumerate(node_names, start=1):
        port = port_base + i
        addr = f"{host}:{port}"
        domain = f"{name}.pft.org"
        node_list_for_crypto[name] = (addr, domain)
        nodes_map[name] = {"addr": addr, "domain": domain}

    # Generate all crypto material (TLS certs + Ed25519 signing keys).
    participants = gen_keys_and_certs(
        node_list_for_crypto, DEFAULT_CA_NAME, num_clients, output_dir,
    )
    print("Generated crypto for:", participants)

    # Paths are relative to repo root so binaries can find them from the
    # working directory they are launched from.
    def rel(filename):
        return os.path.join(output_dir, filename)

    ca_cert = rel(f"{DEFAULT_CA_NAME}_root_cert.pem")
    keylist = rel("signing_pub_keys.keylist")

    # --- Node configs ---
    for i, name in enumerate(node_names, start=1):
        port = port_base + i
        cfg = json.loads(json.dumps(DEFAULT_NODE_CONFIG))  # deep copy

        cfg["net_config"]["name"] = name
        cfg["net_config"]["addr"] = f"0.0.0.0:{port}"
        cfg["net_config"]["tls_cert_path"] = rel(f"{name}_tls_cert.pem")
        cfg["net_config"]["tls_key_path"] = rel(f"{name}_tls_privkey.pem")
        cfg["net_config"]["tls_root_ca_cert_path"] = ca_cert
        cfg["net_config"]["nodes"] = dict(nodes_map)

        cfg["rpc_config"]["allowed_keylist_path"] = keylist
        cfg["rpc_config"]["signing_priv_key_path"] = rel(f"{name}_signing_privkey.pem")

        cfg["consensus_config"]["node_list"] = list(node_names)
        cfg["consensus_config"]["log_storage_config"]["RocksDB"]["db_path"] = f"/tmp/testdb{i}"

        path = os.path.join(output_dir, f"{name}_config.json")
        with open(path, "w") as f:
            json.dump(cfg, f, indent=4)
        print(f"  wrote {path}")

    # --- Client configs ---
    for ci in range(1, num_clients + 1):
        client_name = f"client{ci}"
        cfg = json.loads(json.dumps(DEFAULT_CLIENT_CONFIG))

        cfg["net_config"]["name"] = client_name
        cfg["net_config"]["tls_root_ca_cert_path"] = ca_cert
        cfg["net_config"]["nodes"] = dict(nodes_map)
        cfg["rpc_config"]["signing_priv_key_path"] = rel(f"{client_name}_signing_privkey.pem")

        path = os.path.join(output_dir, f"{client_name}_config.json")
        with open(path, "w") as f:
            json.dump(cfg, f, indent=4)
        print(f"  wrote {path}")

    # --- Controller config ---
    cfg = json.loads(json.dumps(DEFAULT_CONTROLLER_CONFIG))
    cfg["net_config"]["tls_root_ca_cert_path"] = ca_cert
    cfg["net_config"]["nodes"] = dict(nodes_map)
    cfg["rpc_config"]["signing_priv_key_path"] = rel("controller_signing_privkey.pem")

    path = os.path.join(output_dir, "controller_config.json")
    with open(path, "w") as f:
        json.dump(cfg, f, indent=4)
    print(f"  wrote {path}")

    print(f"\nDone. {num_nodes} node + {num_clients} client + 1 controller configs in {output_dir}/")


if __name__ == "__main__":
    generate(parse_args())
