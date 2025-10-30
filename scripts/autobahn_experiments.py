from copy import deepcopy
import json
from experiments import PirateShipExperiment, copy_file_from_remote_public_ip
import os
import subprocess
from typing import List

# The following is ported from autobahn/benchmark/benchmark/config.py

from json import dump, load
from collections import OrderedDict, defaultdict

from deployment import Deployment
from ssh_utils import run_remote_public_ip


class ConfigError(Exception):
    pass


class Key:
    def __init__(self, name, secret):
        self.name = name
        self.secret = secret

    @classmethod
    def from_file(cls, filename):
        assert isinstance(filename, str)
        with open(filename, 'r') as f:
            data = load(f)
        return cls(data['name'], data['secret'])


class Committee:
    ''' The committee looks as follows:
        "authorities: {
            "name": {
                "stake": 1,
                "consensus: {
                    "consensus_to_consensus": x.x.x.x:x,
                },
                "primary: {
                    "primary_to_primary": x.x.x.x:x,
                    "worker_to_primary": x.x.x.x:x,
                },
                "workers": {
                    "0": {
                        "primary_to_worker": x.x.x.x:x,
                        "worker_to_worker": x.x.x.x:x,
                        "transactions": x.x.x.x:x
                    },
                    ...
                }
            },
            ...
        }
    '''

    def __init__(self, addresses, base_port):
        ''' The `addresses` field looks as follows:
            { 
                "name": ["host", "host", ...],
                ...
            }
        '''
        assert isinstance(addresses, OrderedDict)
        assert all(isinstance(x, str) for x in addresses.keys())
        assert all(
            isinstance(x, list) and len(x) > 1 for x in addresses.values()
        )
        assert all(
            isinstance(x, str) for y in addresses.values() for x in y
        )
        assert len({len(x) for x in addresses.values()}) == 1
        assert isinstance(base_port, int) and base_port > 1024

        port = base_port
        self.json = {'authorities': OrderedDict()}

        for name, hosts in addresses.items():
            host = hosts.pop(0)
            consensus_addr = {
                'consensus_to_consensus': f'{host}:{port}',
            }
            port += 1

            primary_addr = {
                'primary_to_primary': f'{host}:{port}',
                'worker_to_primary': f'{host}:{port + 1}'
            }
            port += 2

            workers_addr = OrderedDict()
            for j, host in enumerate(hosts):
                workers_addr[j] = {
                    'primary_to_worker': f'{host}:{port}',
                    'transactions': f'{host}:{port + 1}',
                    'worker_to_worker': f'{host}:{port + 2}',
                }
                port += 3

            self.json['authorities'][name] = {
                'stake': 1,
                'consensus': consensus_addr,
                'primary': primary_addr,
                'workers': workers_addr
            }

    def primary_addresses(self, faults=0):
        ''' Returns an ordered list of primaries' addresses. '''
        assert faults < self.size()
        addresses = []
        good_nodes = self.size() - faults
        for authority in list(self.json['authorities'].values())[:good_nodes]:
            addresses += [authority['primary']['primary_to_primary']]
        return addresses

    def workers_addresses(self, faults=0):
        ''' Returns an ordered list of list of workers' addresses. '''
        assert faults < self.size()
        addresses = []
        good_nodes = self.size() - faults
        for authority in list(self.json['authorities'].values())[:good_nodes]:
            authority_addresses = []
            for id, worker in authority['workers'].items():
                authority_addresses += [(id, worker['transactions'])]
            addresses.append(authority_addresses)
        return addresses

    def ips(self, name=None):
        ''' Returns all the ips associated with an authority (in any order). '''
        if name is None:
            names = list(self.json['authorities'].keys())
        else:
            names = [name]

        ips = set()
        for name in names:
            addresses = self.json['authorities'][name]['consensus']
            ips.add(self.ip(addresses['consensus_to_consensus']))

            addresses = self.json['authorities'][name]['primary']
            ips.add(self.ip(addresses['primary_to_primary']))
            ips.add(self.ip(addresses['worker_to_primary']))

            for worker in self.json['authorities'][name]['workers'].values():
                ips.add(self.ip(worker['primary_to_worker']))
                ips.add(self.ip(worker['worker_to_worker']))
                ips.add(self.ip(worker['transactions']))

        return list(ips)

    def remove_nodes(self, nodes):
        ''' remove the `nodes` last nodes from the committee. '''
        assert nodes < self.size()
        for _ in range(nodes):
            self.json['authorities'].popitem()

    def size(self):
        ''' Returns the number of authorities. '''
        return len(self.json['authorities'])

    def workers(self):
        ''' Returns the total number of workers (all authorities altogether). '''
        return sum(len(x['workers']) for x in self.json['authorities'].values())

    def print(self, filename):
        assert isinstance(filename, str)
        with open(filename, 'w') as f:
            dump(self.json, f, indent=4, sort_keys=True)

    @staticmethod
    def ip(address):
        assert isinstance(address, str)
        return address.split(':')[0]


class LocalCommittee(Committee):
    def __init__(self, names, port, workers):
        assert isinstance(names, list)
        assert all(isinstance(x, str) for x in names)
        assert isinstance(port, int)
        assert isinstance(workers, int) and workers > 0
        addresses = OrderedDict((x, ['127.0.0.1']*(1+workers)) for x in names)
        super().__init__(addresses, port)


class NodeParameters:
    def __init__(self, json):
        inputs = []
        try:
            inputs += [json['timeout_delay']]
            inputs += [json['header_size']]
            inputs += [json['max_header_delay']]
            inputs += [json['gc_depth']]
            inputs += [json['sync_retry_delay']]
            inputs += [json['sync_retry_nodes']]
            inputs += [json['batch_size']]
            inputs += [json['max_batch_delay']]
        except KeyError as e:
            raise ConfigError(f'Malformed parameters: missing key {e}')

        if not all(isinstance(x, int) for x in inputs):
            raise ConfigError('Invalid parameters type')

        self.json = json

    def print(self, filename):
        assert isinstance(filename, str)
        with open(filename, 'w') as f:
            dump(self.json, f, indent=4, sort_keys=True)


class BenchParameters:
    def __init__(self, json):
        try:
            self.faults = int(json['faults'])

            nodes = json['nodes']
            nodes = nodes if isinstance(nodes, list) else [nodes]
            if not nodes or any(x <= 1 for x in nodes):
                raise ConfigError('Missing or invalid number of nodes')
            self.nodes = [int(x) for x in nodes]

            rate = json['rate']
            rate = rate if isinstance(rate, list) else [rate]
            if not rate:
                raise ConfigError('Missing input rate')
            self.rate = [int(x) for x in rate]

            self.workers = int(json['workers'])

            if 'collocate' in json:
                self.collocate = bool(json['collocate'])
            else:
                self.collocate = True

            self.tx_size = int(json['tx_size'])

            self.duration = int(json['duration'])

            self.runs = int(json['runs']) if 'runs' in json else 1
            self.simulate_partition = bool(json['simulate_partition'])

            self.partition_nodes = int(json['partition_nodes'])
            self.partition_start = int(json['partition_start'])
            self.partition_duration = int(json['partition_duration'])
        except KeyError as e:
            raise ConfigError(f'Malformed bench parameters: missing key {e}')

        except ValueError:
            raise ConfigError('Invalid parameters type')

        if min(self.nodes) <= self.faults:
            raise ConfigError('There should be more nodes than faults')


class PlotParameters:
    def __init__(self, json):
        try:
            faults = json['faults']
            faults = faults if isinstance(faults, list) else [faults]
            self.faults = [int(x) for x in faults] if faults else [0]

            nodes = json['nodes']
            nodes = nodes if isinstance(nodes, list) else [nodes]
            if not nodes:
                raise ConfigError('Missing number of nodes')
            self.nodes = [int(x) for x in nodes]

            workers = json['workers']
            workers = workers if isinstance(workers, list) else [workers]
            if not workers:
                raise ConfigError('Missing number of workers')
            self.workers = [int(x) for x in workers]

            if 'collocate' in json:
                self.collocate = bool(json['collocate'])
            else:
                self.collocate = True

            self.tx_size = int(json['tx_size'])

            max_lat = json['max_latency']
            max_lat = max_lat if isinstance(max_lat, list) else [max_lat]
            if not max_lat:
                raise ConfigError('Missing max latency')
            self.max_latency = [int(x) for x in max_lat]

        except KeyError as e:
            raise ConfigError(f'Malformed bench parameters: missing key {e}')

        except ValueError:
            raise ConfigError('Invalid parameters type')

        if len(self.nodes) > 1 and len(self.workers) > 1:
            raise ConfigError(
                'Either the "nodes" or the "workers can be a list (not both)'
            )

    def scalability(self):
        return len(self.workers) > 1
    
# The following is ported from autobahn/benchmark/benchmark/local.py
from os.path import join


class BenchError(Exception):
    def __init__(self, message, error):
        assert isinstance(error, Exception)
        self.message = message
        self.cause = error
        super().__init__(message)


class PathMaker:
    @staticmethod
    def binary_path():
        return join('..', 'target', 'release')

    @staticmethod
    def node_crate_path():
        return join('..', 'node')

    @staticmethod
    def committee_file(path_prefix=""):
        return f'{path_prefix}.committee.json'

    @staticmethod
    def parameters_file(path_prefix=""):
        return f'{path_prefix}.parameters.json'

    @staticmethod
    def key_file(i, path_prefix=""):
        assert isinstance(i, int) and i >= 0
        return f'{path_prefix}.node-{i}.json'

    @staticmethod
    def db_path(i, j=None, path_prefix=""):
        assert isinstance(i, int) and i >= 0
        assert (isinstance(j, int) and i >= 0) or j is None
        worker_id = f'-{j}' if j is not None else ''
        return f'{path_prefix}.db-{i}{worker_id}'

    @staticmethod
    def logs_path():
        return 'logs'

    @staticmethod
    def primary_log_file(i):
        assert isinstance(i, int) and i >= 0
        return join(PathMaker.logs_path(), f'primary-{i}.log')

    @staticmethod
    def worker_log_file(i, j):
        assert isinstance(i, int) and i >= 0
        assert isinstance(j, int) and i >= 0
        return join(PathMaker.logs_path(), f'worker-{i}-{j}.log')

    @staticmethod
    def client_log_file(i, j):
        assert isinstance(i, int) and i >= 0
        assert isinstance(j, int) and i >= 0
        return join(PathMaker.logs_path(), f'client-{i}-{j}.log')

    @staticmethod
    def results_path():
        return 'results'

    @staticmethod
    def result_file(faults, nodes, workers, collocate, rate, tx_size):
        return join(
            PathMaker.results_path(),
            f'bench-{faults}-{nodes}-{workers}-{collocate}-{rate}-{tx_size}.txt'
        )

    @staticmethod
    def plots_path():
        return 'plots'

    @staticmethod
    def agg_file(type, faults, nodes, workers, collocate, rate, tx_size, max_latency=None):
        if max_latency is None:
            name = f'{type}-bench-{faults}-{nodes}-{workers}-{collocate}-{rate}-{tx_size}.txt'
        else:
            name = f'{type}-{max_latency}-bench-{faults}-{nodes}-{workers}-{collocate}-{rate}-{tx_size}.txt'
        return join(PathMaker.plots_path(), name)

    @staticmethod
    def plot_file(name, ext):
        return join(PathMaker.plots_path(), f'{name}.{ext}')


class Color:
    HEADER = '\033[95m'
    OK_BLUE = '\033[94m'
    OK_GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class Print:
    @staticmethod
    def heading(message):
        assert isinstance(message, str)
        print(f'{Color.OK_GREEN}{message}{Color.END}')

    @staticmethod
    def info(message):
        assert isinstance(message, str)
        print(message)

    @staticmethod
    def warn(message):
        assert isinstance(message, str)
        print(f'{Color.BOLD}{Color.WARNING}WARN{Color.END}: {message}')

    @staticmethod
    def error(e):
        assert isinstance(e, BenchError)
        print(f'\n{Color.BOLD}{Color.FAIL}ERROR{Color.END}: {e}\n')
        causes, current_cause = [], e.cause
        while isinstance(current_cause, BenchError):
            causes += [f'  {len(causes)}: {e.cause}\n']
            current_cause = current_cause.cause
        causes += [f'  {len(causes)}: {type(current_cause)}\n']
        causes += [f'  {len(causes)}: {current_cause}\n']
        print(f'Caused by: \n{"".join(causes)}\n')


def progress_bar(iterable, prefix='', suffix='', decimals=1, length=30, fill='█', print_end='\r'):
    total = len(iterable)

    def printProgressBar(iteration):
        formatter = '{0:.'+str(decimals)+'f}'
        percent = formatter.format(100 * (iteration / float(total)))
        filledLength = int(length * iteration // total)
        bar = fill * filledLength + '-' * (length - filledLength)
        print(f'\r{prefix} |{bar}| {percent}% {suffix}', end=print_end)

    printProgressBar(0)
    for i, item in enumerate(iterable):
        yield item
        printProgressBar(i + 1)
    print()

class RemoteCommittee(Committee):
    def __init__(self, names, port, workers, ip_list):
        assert isinstance(names, list)
        assert all(isinstance(x, str) for x in names)
        assert isinstance(port, int)
        assert isinstance(workers, int) and workers > 0
        assert len(names) <= len(ip_list)
 
        addresses = OrderedDict((x, [ip_list[i]]*(1+workers)) for i, x in enumerate(names))
        super().__init__(addresses, port)


def get_default_node_params(num_nodes, repeats, seconds):
    bench_params = {
        'faults': 0, 
        'nodes': num_nodes,
        'workers': 1,
        'rate': 200_000,
        'tx_size': 512,
        'duration': seconds,

        # Unused
        'simulate_partition': False,
        'partition_start': seconds + 100,
        'partition_duration': 0,
        'partition_nodes': 0,
    }
    node_params = {
        'timeout_delay': 1_000,  # ms
        'header_size': 32,  # bytes
        'max_header_delay': 200,  # ms
        'gc_depth': 50,  # rounds
        'sync_retry_delay': 1_000,  # ms
        'sync_retry_nodes': 4,  # number of nodes
        'batch_size': 500_000,  # bytes
        'max_batch_delay': 10,  # ms
        'use_optimistic_tips': False,
        'use_parallel_proposals': True,
        'k': 1,
        'use_fast_path': True,
        'fast_path_timeout': 200,
        'use_ride_share': False,
        'car_timeout': 2000,

        'simulate_asynchrony': False,
        'asynchrony_type': [],

        'asynchrony_start': [], #ms
        'asynchrony_duration': [], #ms
        'affected_nodes': [],
        'egress_penalty': 0, #ms

        'use_fast_sync': True,
        'use_exponential_timeouts': True,
    }

    return bench_params, node_params


class CommandMaker:

    @staticmethod
    def cleanup():
        return (
            f'rm -r .db-* ; rm .*.json ; mkdir -p {PathMaker.results_path()}'
        )

    @staticmethod
    def clean_logs():
        return f'rm -r {PathMaker.logs_path()} ; mkdir -p {PathMaker.logs_path()}'

    @staticmethod
    def compile():
        return 'cd autobahn && cargo build --quiet --release --features benchmark'

    @staticmethod
    def generate_key(filename):
        assert isinstance(filename, str)
        return f'./node generate_keys --filename {filename}'
    
    @staticmethod
    def generate_key_from_target(filename):
        assert isinstance(filename, str)
        return f'./autobahn/target/release/node generate_keys --filename {filename}'

    @staticmethod
    def run_primary(keys, committee, store, parameters, debug=False, binary_name="./node"):
        assert isinstance(keys, str)
        assert isinstance(committee, str)
        assert isinstance(parameters, str)
        assert isinstance(debug, bool)
        v = '-vvv' if debug else '-vv'
        return (f'{binary_name} {v} run --keys {keys} --committee {committee} '
                f'--store {store} --parameters {parameters} primary')

    @staticmethod
    def run_worker(keys, committee, store, parameters, id, debug=False, binary_name="./node"):
        assert isinstance(keys, str)
        assert isinstance(committee, str)
        assert isinstance(parameters, str)
        assert isinstance(debug, bool)
        v = '-vvv' if debug else '-vv'
        return (f'{binary_name} {v} run --keys {keys} --committee {committee} '
                f'--store {store} --parameters {parameters} worker --id {id}')

    @staticmethod
    def run_client(address, size, clients, nodes, binary_name="./benchmark_client"):
        assert isinstance(address, str)
        assert isinstance(size, int) and size > 0
        assert isinstance(clients, int) and clients >= 0
        assert isinstance(nodes, list)
        assert all(isinstance(x, str) for x in nodes)
        nodes = f'--nodes {" ".join(nodes)}' if nodes else ''
        return f'{binary_name} {address} --size {size} --rate {clients} {nodes}'

    @staticmethod
    def kill():
        return 'tmux kill-server'

    @staticmethod
    def alias_binaries(origin):
        assert isinstance(origin, str)
        node, client = join(origin, 'node'), join(origin, 'benchmark_client')
        return f'rm node ; rm benchmark_client ; ln -s {node} . ; ln -s {client} .'

def gen_config(nodes: int, base_port: int, workers: int, node_parameters: NodeParameters, ip_list: List[str], path_prefix):
    # Generate configuration files.
    keys = []
    key_files = [PathMaker.key_file(i, path_prefix=path_prefix) for i in range(nodes)]
    for filename in key_files:
        cmd = CommandMaker.generate_key_from_target(filename).split()
        subprocess.run(cmd, check=True)
        keys += [Key.from_file(filename)]

    names = [x.name for x in keys]
    #print('num workers', self.workers)
    committee = RemoteCommittee(names, base_port, workers, ip_list)
    committee.print(PathMaker.committee_file(path_prefix=path_prefix))

    node_parameters.print(PathMaker.parameters_file(path_prefix=path_prefix))

    return committee

class AutobahnExperiment(PirateShipExperiment):
    def copy_back_build_files(self):
        remote_repo = f"/home/{self.dev_ssh_user}/repo/autobahn"
        TARGET_BINARIES = ["node", "benchmark_client"]

        # Copy the target/release to build directory
        for bin in TARGET_BINARIES:
            copy_file_from_remote_public_ip(f"{remote_repo}/target/release/{bin}", os.path.join(self.local_workdir, "build", bin), self.dev_ssh_user, self.dev_ssh_key, self.dev_vm)


    def bins_already_exist(self):
        TARGET_BINARIES = ["node", "benchmark_client"]
        remote_repo = f"/home/{self.dev_ssh_user}/repo/autobahn"

        res = run_remote_public_ip([
            f"ls {remote_repo}/target/release"
        ], self.dev_ssh_user, self.dev_ssh_key, self.dev_vm, hide=True)

        return any([bin in res[0] for bin in TARGET_BINARIES])
    

    def generate_configs(self, deployment: Deployment, config_dir, log_dir):
        # If config_dir is not empty, assume the configs have already been generated
        if len(os.listdir(config_dir)) > 0:
            print("Skipping config generation for experiment", self.name)
            return
        # Number of nodes in deployment may be < number of nodes in deployment
        # So we reuse nodes.
        # As a default, each deployed node gets its unique port number
        # So there will be no port clash.

        rr_cnt = 0
        nodelist = []
        nodes = {}
        node_configs = {}
        vms = []
        node_list_for_crypto = {}
        if self.node_distribution == "uniform":
            vms = deployment.get_all_node_vms()
        elif self.node_distribution == "sev_only":
            vms = deployment.get_nodes_with_tee("sev")
        elif self.node_distribution == "tdx_only":
            vms = deployment.get_nodes_with_tee("tdx")
        elif self.node_distribution == "nontee_only":
            vms = deployment.get_nodes_with_tee("nontee")
        else:
            vms = deployment.get_wan_setup(self.node_distribution)
        
        self.binary_mapping = defaultdict(list)

        ip_list = []

        for node_num in range(1, self.num_nodes+1):
            port = deployment.node_port_base + node_num
            listen_addr = f"0.0.0.0:{port}"
            name = f"node{node_num}"
            domain = f"{name}.pft.org"

            _vm = vms[rr_cnt % len(vms)]
            self.binary_mapping[_vm].append(name)
            
            private_ip = _vm.private_ip
            rr_cnt += 1
            connect_addr = f"{private_ip}:{port}"

            nodelist.append(name[:])
            nodes[name] = {
                "addr": connect_addr,
                "domain": domain
            }
            ip_list.append(private_ip)

        if self.client_region == -1:
            client_vms = deployment.get_all_client_vms()
        else:
            client_vms = deployment.get_all_client_vms_in_region(self.client_region)

        # if len(client_vms) > 1:
        #     client_vms = [client_vms[0]]


        total_nodes = self.num_nodes
        clients_per_node = self.num_clients // total_nodes
        num_clients_per_vm = [clients_per_node // len(client_vms) for _ in range(len(client_vms))]
        num_clients_per_vm[-1] += (clients_per_node - sum(num_clients_per_vm))

        for client_num in range(len(client_vms)):
            config = deepcopy(self.base_client_config)
            client = "client" + str(client_num + 1)
            self.binary_mapping[client_vms[client_num]].append(client)


        bench_params, node_params = get_default_node_params(self.num_nodes, self.repeats, self.duration)

        # Override default parameters using data provided in base_node_config and base_client_config
        bench_params = {k: self.base_client_config.get(k, v) for k, v in bench_params.items()}
        node_params = {k: self.base_node_config.get(k, v) for k, v in node_params.items()}

        num_workers = bench_params['workers']
        node_params = NodeParameters(node_params)

        if not config_dir.endswith("/"):
            config_dir += "/"

        committee = gen_config(self.num_nodes, deployment.node_port_base, num_workers, node_params, ip_list, config_dir)

        self.committee = committee
        self.num_workers = num_workers
        self.clients_per_vm = num_clients_per_vm
        self.node_params = node_params
        self.bench_params = bench_params

        
    def generate_arbiter_script(self):

        script_base = f"""#!/bin/bash
set -e
set -o xtrace

# This script is generated by the experiment pipeline. DO NOT EDIT.
SSH_CMD="ssh -o StrictHostKeyChecking=no -i {self.dev_ssh_key}"
SCP_CMD="rsync -avz -e 'ssh -o StrictHostKeyChecking=no -i {self.dev_ssh_key}'"

# SSH into each VM and run the binaries
"""
        # Plan the binaries to run
        for repeat_num in range(self.repeats):
            print("Running repeat", repeat_num)
            _script = script_base[:]
            curr_client_count = 0

            for vm, bin_list in self.binary_mapping.items():
                for bin in bin_list:
                    if "node" in bin:
                        binary_name = f"{self.remote_workdir}/build/node"
                        node_num = int(bin.split("node")[1]) - 1
                        config_dir = os.path.join(self.remote_workdir, "configs")
                        if not config_dir.endswith("/"):
                            config_dir += "/"
                        log_dir = os.path.join(self.remote_workdir, "logs")
                        if not log_dir.endswith("/"):
                            log_dir += "/"
                        primary_cmd = CommandMaker.run_primary(
                            PathMaker.key_file(node_num, path_prefix=config_dir),
                            PathMaker.committee_file(path_prefix=config_dir),
                            PathMaker.db_path(node_num, path_prefix=log_dir),
                            PathMaker.parameters_file(path_prefix=config_dir),
                            debug=False,
                            binary_name=binary_name
                        )
                        _script += f"""
$SSH_CMD {self.dev_ssh_user}@{vm.public_ip} '{primary_cmd}' > {self.remote_workdir}/logs/{repeat_num}/primary-{bin}.err 2> {self.remote_workdir}/logs/{repeat_num}/primary-{bin}.log &
PID="$PID $!"
"""
                        worker_cmds = []

                        for worker_num in range(self.num_workers):

                            worker_cmd = CommandMaker.run_worker(
                                PathMaker.key_file(node_num, path_prefix=config_dir),
                                PathMaker.committee_file(path_prefix=config_dir),
                                PathMaker.db_path(node_num, worker_num, path_prefix=log_dir),
                                PathMaker.parameters_file(path_prefix=config_dir),
                                worker_num,
                                debug=False,
                                binary_name=binary_name
                            )
                            worker_cmds.append(worker_cmd)

                        for k, worker_cmd in enumerate(worker_cmds):
                            _script += f"""
$SSH_CMD {self.dev_ssh_user}@{vm.public_ip} '{worker_cmd}' > {self.remote_workdir}/logs/{repeat_num}/worker{k}-{bin}.err 2> {self.remote_workdir}/logs/{repeat_num}/worker{k}-{bin}.log &
PID="$PID $!"
"""
                    
                    elif "client" in bin:
                        binary_name = f"{self.remote_workdir}/build/benchmark_client"
                        num_clients = self.clients_per_vm[curr_client_count]
                        curr_client_count += 1
                        tx_size = self.bench_params['tx_size']
                        node_addrs = self.committee.workers_addresses(0)
                        for i, addresses in enumerate(node_addrs):
                            for (id, addr) in addresses:
                                cmd = CommandMaker.run_client(
                                    addr, tx_size, num_clients,
                                    [x for y in node_addrs for _, x in y],
                                    binary_name=binary_name
                                )
                                _script += f"""
$SSH_CMD {self.dev_ssh_user}@{vm.public_ip} '{cmd}' > {self.remote_workdir}/logs/{repeat_num}/{bin}-{i}-{id}.err 2> {self.remote_workdir}/logs/{repeat_num}/{bin}-{i}-{id}.log &
PID="$PID $!"
"""


              
            _script += f"""
# Sleep for the duration of the experiment
sleep {self.duration}

# Kill the binaries. First with a SIGINT, then with a SIGTERM, then with a SIGKILL
echo -n $PID | xargs -d' ' -I{{}} kill -2 {{}} || true
echo -n $PID | xargs -d' ' -I{{}} kill -15 {{}} || true
echo -n $PID | xargs -d' ' -I{{}} kill -9 {{}} || true
sleep 10

# Kill the binaries in SSHed VMs as well. Calling SIGKILL on the local SSH process might have left them orphaned.
# Make sure not to kill the tmux server.
# Then copy the logs back and delete any db files. Cleanup for the next run.
"""
            for vm, bin_list in self.binary_mapping.items():
                for bin in bin_list:
                    if "node" in bin:
                        binary_name = "node"
                    elif "client" in bin:
                        binary_name = "benchmark" # "benchmark_client" is more than 15 chars and pkill doesn't like that

                # Copy the logs back
                    _script += f"""
$SSH_CMD {self.dev_ssh_user}@{vm.public_ip} 'pkill -9 -c {binary_name}' || true
$SSH_CMD {self.dev_ssh_user}@{vm.public_ip} 'rm -rf {self.remote_workdir}/logs/.db-*' || true
$SCP_CMD {self.dev_ssh_user}@{vm.public_ip}:{self.remote_workdir}/logs/{repeat_num}/ {self.remote_workdir}/logs/{repeat_num}/ || true
"""
                
            _script += f"""
sleep 2
"""
                
            # pkill -9 -c server also kills tmux-server. So we can't run a server on the dev VM.
            # It kills the tmux session and the experiment. And we end up with a lot of orphaned processes.

            with open(os.path.join(self.local_workdir, f"arbiter_{repeat_num}.sh"), "w") as f:
                f.write(_script + "\n\n")




