from collections import defaultdict
import multiprocessing
import shutil
from time import sleep
import time
from typing import List
import tomli
import click
from click_default_group import DefaultGroup
import invoke
from fabric import Connection
from pprint import pprint
import os.path
from dataclasses import dataclass
from copy import deepcopy
from itertools import product
from collections.abc import Callable
import datetime
import json

import tqdm
from crypto import *
from app_experiments import AppExperiment
from ssh_utils import *
from deployment import Deployment
from deployment_aci import AciDeployment
from experiments import BaseExperiment, PirateShipExperiment, NetPerfExperiment
from autobahn_experiments import AutobahnExperiment
from scitt_experiments import ScittExperiment
from ccf_experiments import CCFExperiment
from results import *
import pickle
import re

from shutil import copytree


"""
Each experiment goes through 7 phases:

1. Deploying VMs
2. Copying the working tree to one of the VMs (`coordinator`).
3. Building the code.
4. Actually running the experiment which dumps logs in the respective VMs.
5. Collecting logs in coordinator.
6. Copying the logs back to local.
7. Destroying the VMs.

Step 1 and 7 are usually handled by Terraform. However, they can also be injected manually.
For Step 2, we choose the 1st client VM.
The experiments are usually of the form:

{ set of clients } <----------> { set of nodes }
Hence describing an experiment only needs 3 things: Workload used by clients, Protocol used by nodes, App running on the nodes.
The collected logs can then be used to plot different graphs.

The only exceptions are reconfiguration experiments, which requires an additional coordinator client.
See config.toml for a sample TOML config format.
```
"""


def nested_override(source, diff):
    target = deepcopy(source)
    for k, v in diff.items():
        if not (k in target):  # New key
            target[k] = deepcopy(v)
        elif not (isinstance(target[k], dict)):  # target[k] is not nested
            target[k] = deepcopy(v)
        # v is not nested: Hitting this condition means the dict is malformed (doesn't conform to a schema)
        elif not (isinstance(v, dict)):
            target[k] = deepcopy(v)
        else:  # Nested object
            new_v = nested_override(target[k], v)
            target[k] = new_v

    return target


# Can't handle nested list (ie, list of lists)
# Nested dicts are ok
def flatten_sweeping_params(e):
    work_items = []
    for k, v in e.items():
        if isinstance(v, dict):
            v_cross_product = flatten_sweeping_params(v)
            for _e in v_cross_product:
                work_items.append(nested_override(e, {k: _e}))

    if len(work_items) == 0:
        work_items = [e]

    ret = []
    for _e in work_items:
        list_items = []
        for k, v in _e.items():
            if isinstance(v, list):
                list_items.append(
                    [(k, it) for it in v]
                )
        prod = list(product(*list_items))
        for p in prod:
            override = {}
            for (k, v) in p:
                override[k] = v

            ret.append(nested_override(_e, override))

    return ret


def parse_config(path, workdir=None, existing_experiments=None):
    with open(path, "rb") as f:
        toml_dict = tomli.load(f)

    pprint(toml_dict)

    if workdir is None:
        curr_time = datetime.datetime.now(datetime.timezone.utc).isoformat()
        workdir = os.path.join(toml_dict["workdir"], curr_time)

    # Create Deployment (Terraform, ACI, etc.)
    # TODO(natacha): Add a way for Hybrid deployments (as a way to facilitate ACI + VM testing)
    type = toml_dict["deployment_config"].get("type")
    if (type is None) or  type == "vm":
        # Default to VM deployment
        deployment = Deployment(toml_dict["deployment_config"], workdir)
    else:
        deployment = AciDeployment(toml_dict["deployment_config"], workdir)

    base_node_config = toml_dict["node_config"]
    base_client_config = toml_dict["client_config"]

    experiments = []
    for e in toml_dict["experiments"]:
        node_config = nested_override(
            base_node_config, e.get("node_config", {}))
        client_config = nested_override(
            base_client_config, e.get("client_config", {}))
        controller_must_run = e.get("controller_must_run", False)
        git_hash_override = e.get("git_hash", None)
        experiment_type = e.get("type", "pirateship")
        measure_resources = e.get("measure_resources", False)
        if experiment_type == "pirateship":
            klass = PirateShipExperiment
        elif experiment_type == "netperf":
            klass = NetPerfExperiment
        elif experiment_type == "app":
            klass = AppExperiment
        elif experiment_type == "autobahn":
            klass = AutobahnExperiment
        elif experiment_type == "scitt":
            klass = ScittExperiment
        elif experiment_type == "ccf":
            klass = CCFExperiment
        project_home = toml_dict["project_home"]

        if "sweeping_parameters" in e:
            flats = flatten_sweeping_params(e["sweeping_parameters"])
            # raise Exception(e.get("seq_start", 0))
            seq_start = int(e.get("seq_start", 0))
            for i, params in enumerate(flats):
                _e = nested_override(e, params)
                if "node_config" in _e:
                    _node_config = nested_override(
                        node_config, _e["node_config"])
                else:
                    _node_config = node_config
                
                if "client_config" in _e:
                    _client_config = nested_override(
                        client_config, _e["client_config"])
                else:
                    _client_config = client_config

                experiments.append(klass(
                    os.path.join(_e['name'], str(i + seq_start)),
                    _e['name'], # Group name
                    i + seq_start, # Seq num
                    int(_e["repeats"]),
                    int(_e["duration"]),
                    int(_e["num_nodes"]),
                    int(_e["num_clients"]),
                    _node_config,
                    _client_config,
                    _e.get("node_distribution", "uniform"),
                    _e.get("client_region", -1),    # -1 means use all clients
                    _e.get("build_command", "make"),
                    git_hash_override,
                    project_home,
                    controller_must_run,
                    measure_resources,
                    _e.get("loop_type", "closed"),
                    _e.get("request_rate", 1000.0)
                ))
        else:
            seq_start = int(e.get("seq_start", 0))
            experiments.append(klass(
                os.path.join(e['name'], str(seq_start)),
                e["name"],  # Group name
                seq_start, # Seq num
                int(e["repeats"]),
                int(e["duration"]),
                int(e["num_nodes"]),
                int(e["num_clients"]),
                node_config,
                client_config,
                e.get("node_distribution", "uniform"),
                e.get("client_region", -1),    # -1 means use all clients
                e.get("build_command", "make"),
                git_hash_override,
                project_home,
                controller_must_run,
                measure_resources,
                _e.get("loop_type", "closed"),
                _e.get("request_rate", 1000.0)
            ))

    results = []
    if existing_experiments is not None:
        experiments = existing_experiments
    for r in toml_dict["results"]:
        args = deepcopy(r)
        del args["plotter"]

        results.append(
            Result(r["name"], workdir, r["plotter"], experiments, args)
        )

    return (deployment, experiments, results)


@click.group(cls=DefaultGroup, default='all', default_if_no_args=True, help="Run experiment pipeline (runs all if no subcommand is provided)")
@click.pass_context
def main(ctx):#
    if ctx.invoked_subcommand is None:
        # Run all()
        ctx.invoke(all)


@main.command()
@click.option(
    "-c", "--config", required=True,
    type=click.Path(exists=True, file_okay=True, resolve_path=True)
)
@click.option(
    "-d", "--workdir", required=False,
    type=click.Path(file_okay=False, resolve_path=True),
    default=None
)
def all(config, workdir):
    deployment, experiments, results = parse_config(config, workdir=workdir)

    deployment.deploy()

    cached_git_hash = ""
    cached_diff = ""
    cached_build_cmd = ""
    for experiment in experiments:
        try:
            experiment.deploy(deployment, last_git_hash=cached_git_hash, last_git_diff=cached_diff, last_build_command=cached_build_cmd)
            hash, diff, build_cmd = experiment.get_build_details()
            cached_git_hash = hash
            cached_diff = diff
            cached_build_cmd = build_cmd
        except Exception as e:
            print(f"Error deploying {experiment.name}. Continuing anyway: {e} {os.getcwd()}")
            cached_git_hash = ""
            cached_diff = ""
            cached_build_cmd = ""
            # Force build on the next try


    deployment.copy_all_to_remote_public_ip()

    script_lines = []
    force_redo_results = False
    for experiment in experiments:
        _lines, available_remotely = experiment.run_plan()
        script_lines.extend(_lines)
        force_redo_results = force_redo_results or (available_remotely > 0)

    force_redo_results = force_redo_results or (len(script_lines) > 0)

    if len(script_lines) > 0:
        deployment.run_job_in_dev_vm(script_lines)

    deployment.sync_local_to_dev_vm()

    for experiment in experiments:
        experiment.save_if_done()

    for result in results:
        result.update_experiments(experiments)
        if force_redo_results:
            result.kwargs["force_parse"] = True
            print("Forcing parse")
            
        result.output()

    


@main.command()
@click.option(
    "-c", "--config", required=True,
    type=click.Path(exists=True, file_okay=True, resolve_path=True)
)
@click.option(
    "-d", "--workdir", required=True,
    type=click.Path(file_okay=False, resolve_path=True)
)
def teardown(config, workdir):
    # Search for the pickle file
    pickle_path = os.path.join(workdir, "deployment", "deployment.pkl")
    if os.path.exists(pickle_path):
        with open(pickle_path, "rb") as f:
            deployment = pickle.load(f)
            assert isinstance(deployment, Deployment)
    else:
        # Get deployment from the config if the pickle file doesn't exist
        deployment, _, _ = parse_config(config, workdir)

    pprint(deployment)
    deployment.teardown()


@main.command()
@click.option(
    "-c", "--config", required=True,
    type=click.Path(exists=True, file_okay=True, resolve_path=True)
)
@click.option(
    "-d", "--workdir", required=True,
    type=click.Path(file_okay=False, resolve_path=True)
)
@click.option(
    "-n", "--name", required=False,
    type=str,
    default=None
)
def ssh(config, workdir, name):
    # Search for the pickle file
    pickle_path = os.path.join(workdir, "deployment", "deployment.pkl")
    if os.path.exists(pickle_path):
        with open(pickle_path, "rb") as f:
            deployment = pickle.load(f)
            assert isinstance(deployment, Deployment)
    else:
        # Get deployment from the config if the pickle file doesn't exist
        deployment, _, _ = parse_config(config, workdir)

    if name is None:
        target_node = deployment.dev_vm
    else:
        for node in deployment.nodelist:
            if node.name == name:
                target_node = node
                break
        else:
            raise ValueError(f"Node {name} not found")

    invoke.run(
        f"ssh -i {deployment.ssh_key} {deployment.ssh_user}@{target_node.public_ip}", pty=True)


@main.command()
@click.option(
    "-c", "--config", required=True,
    type=click.Path(exists=True, file_okay=True, resolve_path=True)
)
@click.option(
    "-d", "--workdir", required=True,
    type=click.Path(file_okay=False, resolve_path=True)
)
@click.option(
    "-cmd", "--command", required=True,
    type=str
)
def run_command(config, workdir, command):
    pickle_path = os.path.join(workdir, "deployment", "deployment.pkl")
    if os.path.exists(pickle_path):
        with open(pickle_path, "rb") as f:
            deployment = pickle.load(f)
            assert isinstance(deployment, Deployment)
    else:
        # Get deployment from the config if the pickle file doesn't exist
        deployment, _, _ = parse_config(config, workdir)

    print(f"Running command on {len(deployment.nodelist)} nodes")

    for node in deployment.nodelist:
        print(f"Running command on {node.name}")
        try:
            run_remote_public_ip([command], deployment.ssh_user,
                                deployment.ssh_key, node, hide=False)
        except Exception as e:
            pass


@main.command()
@click.option(
    "-c", "--config", required=True,
    type=click.Path(exists=True, file_okay=True, resolve_path=True)
)
@click.option(
    "-d", "--workdir", required=False,
    type=click.Path(file_okay=False, resolve_path=False),
    default=None
)
def deploy(config, workdir):
    deployment, _, _ = parse_config(config, workdir)
    pprint(deployment)
    deployment.deploy()
    print("Deployment done. Working directory:", deployment.workdir)


@main.command()
@click.option(
    "-c", "--config", required=True,
    type=click.Path(exists=True, file_okay=True, resolve_path=True)
)
@click.option(
    "-d", "--workdir", required=True,
    type=click.Path(file_okay=False, resolve_path=True)
)
def deploy_experiments(config, workdir):
    # Try to get deployment from the pickle file
    pickle_path = os.path.join(workdir, "deployment", "deployment.pkl")
    with open(pickle_path, "rb") as f:
        deployment = pickle.load(f)
        assert isinstance(deployment, Deployment)

    # Try to get experiments from the pickle file
    experiments = []
    for root, _, files in os.walk(os.path.join(workdir, "experiments")):
        for f in files:
            if f == "experiment.pkl":
                with open(os.path.join(root, f), "rb") as f:
                    experiment = pickle.load(f)
                    assert isinstance(experiment, BaseExperiment)
                    experiments.append(experiment)

    if len(experiments) == 0:
        _, experiments, _ = parse_config(config, workdir=workdir)

    cached_git_hash = ""
    cached_diff = ""
    cached_build_cmd = ""

    must_reset_quota = False
    if isinstance(deployment, AciDeployment) and deployment.local:
        deployment.lift_dev_cpu_quota()
        must_reset_quota = True

    for experiment in experiments:
        try:
            experiment.deploy(deployment, last_git_hash=cached_git_hash, last_git_diff=cached_diff, last_build_command=cached_build_cmd)
            hash, diff, build_cmd = experiment.get_build_details()
            cached_git_hash = hash
            cached_diff = diff
            cached_build_cmd = build_cmd
        except Exception as e:
            print(f"Error deploying {experiment.name}. Continuing anyway: {e} {os.getcwd()}")
            cached_git_hash = ""
            cached_diff = ""
            cached_build_cmd = ""
            # Force build on the next try


    # Copy over the entire directory to all nodes
    deployment.copy_all_to_remote_public_ip()

    if must_reset_quota:
        deployment.reset_cpu_quota()

@main.command()
@click.option(
    "-c", "--config", required=True,
    type=click.Path(exists=True, file_okay=True, resolve_path=True)
)
@click.option(
    "-d", "--workdir", required=True,
    type=click.Path(file_okay=False, resolve_path=True)
)
@click.option(
    "-n", "--name", required=False,
    type=str,
    default=None
)
def run_experiments(config, workdir, name):
    # Try to get deployment from the pickle file
    pickle_path = os.path.join(workdir, "deployment", "deployment.pkl")
    with open(pickle_path, "rb") as f:
        deployment = pickle.load(f)
        assert isinstance(deployment, Deployment)

    # Find all experiments pickle files recursively in workdir/experiments
    experiments = []
    for root, _, files in os.walk(os.path.join(workdir, "experiments")):
        for f in files:
            if f == "experiment.pkl":
                with open(os.path.join(root, f), "rb") as f:
                    experiment = pickle.load(f)
                    assert isinstance(experiment, BaseExperiment)
                    experiments.append(experiment)

    script_lines = []
    for experiment in experiments:
        _script, _ = experiment.run_plan()
        script_lines.extend(_script)

    if len(script_lines) > 0:
        deployment.run_job_in_dev_vm(script_lines)

    deployment.sync_local_to_dev_vm()

    for experiment in experiments:
        experiment.save_if_done()


@main.command()
@click.option(
    "-c", "--config", required=True,
    type=click.Path(exists=True, file_okay=True, resolve_path=True)
)
@click.option(
    "-d", "--workdir", required=True,
    type=click.Path(file_okay=False, resolve_path=True)
)
def status(config, workdir):
    # Try to get deployment from the pickle file
    pickle_path = os.path.join(workdir, "deployment", "deployment.pkl")
    with open(pickle_path, "rb") as f:
        deployment = pickle.load(f)
        assert isinstance(deployment, Deployment)

    print(deployment)

    # Get the status.txt from remote to find the current running job.
    try:
        status = run_remote_public_ip([
            "cat status.txt"
        ], deployment.ssh_user, deployment.ssh_key, deployment.dev_vm)[0]
        fname = status.split("\n")[0].strip().split(" ")[1]
        print("Current running job:", fname)
    except Exception as e:
        print("No job running")
        return

    # Read the job file
    num_cmds = 0
    job_path = os.path.join(workdir, "jobs", fname)
    try:
        with open(job_path) as f:
            job_lines = f.readlines()
            for line in job_lines:
                if line.startswith("sh"):
                    num_cmds += 1

        deployment.wait_till_end(num_cmds)
    except Exception as e:
        print("Error reading job file:", job_path, e)


@main.command()
@click.option(
    "-c", "--config", required=True,
    type=click.Path(exists=True, file_okay=True, resolve_path=True)
)
@click.option(
    "-d", "--workdir", required=True,
    type=click.Path(file_okay=False, resolve_path=True)
)
def sync_local(config, workdir):
    # Try to get deployment from the pickle file
    pickle_path = os.path.join(workdir, "deployment", "deployment.pkl")
    with open(pickle_path, "rb") as f:
        deployment = pickle.load(f)
        assert isinstance(deployment, Deployment)

    print(deployment)

    deployment.sync_local_to_dev_vm()


@main.command()
@click.option(
    "-c", "--config", required=True,
    type=click.Path(exists=True, file_okay=True, resolve_path=True)
)
@click.option(
    "-d", "--workdir", required=True,
    type=click.Path(file_okay=False, resolve_path=True)
)
def clean_dev(config, workdir):
    # Try to get deployment from the pickle file
    pickle_path = os.path.join(workdir, "deployment", "deployment.pkl")
    with open(pickle_path, "rb") as f:
        deployment = pickle.load(f)
        assert isinstance(deployment, Deployment)

    print(deployment)

    deployment.clean_dev_vm()



@main.command()
@click.option(
    "-c", "--config", required=True,
    type=click.Path(exists=True, file_okay=True, resolve_path=True)
)
@click.option(
    "-d", "--workdir", required=True,
    type=click.Path(file_okay=False, resolve_path=True)
)
def clean_logs(config, workdir):
    # Try to get deployment from the pickle file
    pickle_path = os.path.join(workdir, "deployment", "deployment.pkl")
    with open(pickle_path, "rb") as f:
        deployment = pickle.load(f)
        assert isinstance(deployment, Deployment)

    print(deployment)

    # Clean dev first
    print("Cleaning remote")
    deployment.clean_dev_vm()

    # Now clean all experiment logs
    for root, dirs, files in os.walk(os.path.join(workdir, "experiments")):
        if "logs" in dirs:
            logs_path = os.path.join(root, "logs")
            print("Cleaning", logs_path)
            shutil.rmtree(logs_path)
            os.makedirs(logs_path, exist_ok=True)

        # Delete the stale pkl file
        if "experiment.pkl" in files:
            os.remove(os.path.join(root, "experiment.pkl"))
        
        if "experiment_pristine.pkl" in files:
            with open(os.path.join(root, "experiment_pristine.pkl"), "rb") as f:
                experiment = pickle.load(f)
                assert isinstance(experiment, BaseExperiment)
            
            with open(os.path.join(root, "experiment.pkl"), "wb") as f:
                pickle.dump(experiment, f)
    


@main.command()
@click.option(
    "-c", "--config", required=True,
    type=click.Path(exists=True, file_okay=True, resolve_path=True)
)
@click.option(
    "-d", "--workdir", required=True,
    type=click.Path(file_okay=False, resolve_path=True)
)
@click.option(
    "--extra", is_flag=True, default=False,
)
def results(config, workdir, extra):
    # Try to get deployment from the pickle file
    pickle_path = os.path.join(workdir, "deployment", "deployment.pkl")
    with open(pickle_path, "rb") as f:
        deployment = pickle.load(f)
        assert isinstance(deployment, Deployment)

    # Find all experiments pickle files recursively in workdir/experiments
    experiments = []
    for root, _, files in os.walk(os.path.join(workdir, "experiments")):
        for f in files:
            if f == "experiment.pkl":
                with open(os.path.join(root, f), "rb") as f:
                    experiment = pickle.load(f)
                    assert isinstance(experiment, BaseExperiment)
                    experiments.append(experiment)

    script_lines = []
    force_redo_results = False
    for experiment in experiments:
        _script, available_remotely = experiment.run_plan()
        script_lines.extend(_script)
        force_redo_results = force_redo_results or (available_remotely > 0)

    force_redo_results = force_redo_results or (len(script_lines) > 0)

    if len(script_lines) > 0:
        deployment.run_job_in_dev_vm(script_lines)

    # deployment.sync_local_to_dev_vm()

    _, _, results = parse_config(config, workdir=workdir, existing_experiments=experiments)
    for result in results:
        if force_redo_results:
            result.kwargs["force_parse"] = True
            print("Forcing parse")
            
        result.output()

@main.command()
@click.option(
    "-c", "--config", required=True,
    type=click.Path(exists=True, file_okay=True, resolve_path=True)
)
@click.option(
    "-d", "--workdir", required=True,
    type=click.Path(file_okay=False, resolve_path=True)
)
def reuse_deployment(config, workdir):
    deployment, _, _ = parse_config(config, workdir=None) # Force create a new directory

    # Copy over the deployment directory from workdir to the new directory
    new_workdir = deployment.workdir
    copytree(
        os.path.join(workdir, "deployment"),
        os.path.join(new_workdir, "deployment"),
        dirs_exist_ok=True
    )

    # Remove the deployment.pkl and txt file
    os.remove(os.path.join(new_workdir, "deployment", "deployment.pkl"))
    os.remove(os.path.join(new_workdir, "deployment", "deployment.txt"))

    # Deploy the deployment; this should not trigger anything new if the same deployment config is reused.
    # Since the state in deployment should tell that the deployment is already done.

    deployment.deploy()

    print("New Working Directory", new_workdir)

if __name__ == "__main__":
    main()
