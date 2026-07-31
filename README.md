# Pirateship SOSP 2026 Artifacts

This branch (`sosp-artifact`) acts as a snapshot to reproduce the graphs in our SOSP submission, while the main development continues in `main`.

# [Update Jul 30 2026] Bastion access

Access to our deployment of 7 consensus nodes and 3 client nodes is now possible through a Bastion VM.
Please provide the authors with a public key to be added to the VM.
Then SSH into `azureuser@20.59.110.203`. The repo is hosted at `/mnt/pirateship/`.
We recommend opening the repo in VS Code (or its derivatives) with SSH tunneling to have a better visualization of the directory organization.

## Running experiments against a fixed deployment

For ease of running experiments, we have pre-configured the working directory for each of the claims (see "Artifact Claims" below).
This skips the necessity of running of running `deploy` and `teardown` phases for all experiments (see "Running Experiments" below.)

Following commands will run the experiment for each claim.

```bash
# Make sure you are in the right repo and Python environment
cd /mnt/pirateship
source .venv/bin/activate

# Claim 1
python3 scripts deploy-experiments -c claims/01-overhead.toml -d deployment_artifacts/2026-07-31T01\:13\:27.832021+00\:00/
python3 scripts run-experiments -c claims/01-overhead.toml -d deployment_artifacts/2026-07-31T01\:13\:27.832021+00\:00/
python3 scripts results -c claims/01-overhead.toml -d deployment_artifacts/2026-07-31T01\:13\:27.832021+00\:00/
python3 scripts clean-dev -c claims/01-overhead.toml -d deployment_artifacts/2026-07-31T01\:13\:27.832021+00\:00/


# Claim 2
python3 scripts deploy-experiments -c claims/02-equivocation.toml -d deployment_artifacts/2026-07-31T02\:20\:32.872167+00\:00/
python3 scripts run-experiments -c claims/02-equivocation.toml -d deployment_artifacts/2026-07-31T02\:20\:32.872167+00\:00/
python3 scripts results -c claims/02-equivocation.toml -d deployment_artifacts/2026-07-31T02\:20\:32.872167+00\:00/
python3 scripts clean-dev -c claims/02-equivocation.toml -d deployment_artifacts/2026-07-31T02\:20\:32.872167+00\:00/


# Claim 3
python3 scripts deploy-experiments -c claims/03-fastpath.toml -d deployment_artifacts/2026-07-31T02\:33\:39.968105+00\:00/
python3 scripts run-experiments -c claims/03-fastpath.toml -d deployment_artifacts/2026-07-31T02\:33\:39.968105+00\:00/
python3 scripts results -c claims/03-fastpath.toml -d deployment_artifacts/2026-07-31T02\:33\:39.968105+00\:00/
python3 scripts clean-dev -c claims/03-fastpath.toml -d deployment_artifacts/2026-07-31T02\:33\:39.968105+00\:00/

# Claim 4
python3 scripts deploy-experiments -c claims/04-application.toml -d deployment_artifacts/2026-07-31T03\:03\:13.560921+00\:00/
python3 scripts run-experiments -c claims/04-application.toml -d deployment_artifacts/2026-07-31T03\:03\:13.560921+00\:00/
python3 scripts results -c claims/04-application.toml -d deployment_artifacts/2026-07-31T03\:03\:13.560921+00\:00/
python3 scripts clean-dev -c claims/04-application.toml -d deployment_artifacts/2026-07-31T03\:03\:13.560921+00\:00/


# Clean up experiment logs for next re-run
rm -r deployment_artifacts/2026-07-31T01\:13\:27.832021+00\:00/experiments
rm -r deployment_artifacts/2026-07-31T02\:20\:32.872167+00\:00/experiments
rm -r deployment_artifacts/2026-07-31T02\:33\:39.968105+00\:00/experiments
rm -r deployment_artifacts/2026-07-31T03\:03\:13.560921+00\:00/experiments
```

## Observing logs: What to expect

The logging in the scripts is intentionally kept very verbose.
You may observe error lines occassionally, which in most cases are benign and the script will automatically move forward.

A successful `deploy-experiments` command will end in an rsync output like the following:
```text
<!-- snip -->
Copying deployment_artifacts/2026-07-31T01:13:27.832021+00:00 to 10 nodes
Copied to nodepool_vm0_sev_loc0_id0 Output (truncated):
 sent 244,950,480 bytes  received 19,413 bytes  28,819,987.41 bytes/sec
total size is 740,287,945  speedup is 3.02
Copied to nodepool_vm6_sev_loc0_id6 Output (truncated):
 sent 244,950,480 bytes  received 19,413 bytes  28,819,987.41 bytes/sec
total size is 740,287,945  speedup is 3.02
<!-- snip -->
```

A successful `run-experiments` results in a progress bar at the screen while the experiments are running.
Once finished, you will see logs for copying the logs from all nodes back like the following:
```text
Experiment ended
receiving incremental file list
experiments/autobahn/0/logs/0/client1-0-0.err
experiments/autobahn/0/logs/0/client1-0-0.log
experiments/autobahn/0/logs/0/client1-0-0.metrics
experiments/autobahn/0/logs/0/client1-1-0.err
experiments/autobahn/0/logs/0/client1-1-0.log
experiments/autobahn/0/logs/0/client1-1-0.metrics
<!-- snip -->
```

Similarly, `results` command will also produce a lot of output, however the end result would be a pdf file with the graph at `<workdir>/results/`.


# Setup

Running the experiments requires access to Azure. Please contact the authors to have your email added to our development Azure account.

Install [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/?view=azure-cli-latest). Then run:
```bash
az login # Login using the email provided with the authors.
```

Install [Terraform](https://developer.hashicorp.com/terraform/install). Terraform handles all VM deployment and teardown necessary for the experiments.


Clone the repo locally with the submodules and switch to the `sosp-artifact` branch:

```bash
git clone --recurse-submodules git@github.com:PirateshipOrg/pirateship.git
git checkout sosp-artifact
```

Besides these, you will need Python and rsync to run the scripts.
Setup your Python environment:

```bash
virtualenv .venv
source .venv/bin/activate
pip install -r scripts/requirements.txt
```


## Running Experiments

Our experiments are end-to-end encoded in TOML files similar to the ones in `experiments/`.
The steps to run each experiment is the same few Python commands invoked from the repo itself.
While the exact experiments to run are described below ("Artifact Claims" section), we summarize the common steps below.
We denote the generic path to the TOML file as `<path/to/experiment/toml>`
and the working directory where the log files and results are stored as `<workdir>`.
> Note: `<workdir>` is autogenerated with a path resembling `deployment_artifacts/<timestamp>`.

Refer to additional details about running our experiment infrastructure [here](scripts/README.md).

> WARNING: The following steps take a lot of time! Please be patient.

```bash
# Make sure you are in the right Python environment
source .venv/bin/activate

# To start an experiment, we first deploy the necessary VMs.
python3 scripts deploy -c <path/to/experiment/toml>

# This deploys the VMs and sets up a directory to store log files and SSH keys.
# The directory typically is named `deployment_artifacts/<timestamp>`
# We will call this directory <workdir>.

# Wait for up to 5 minutes after running deploy for all VMs to be deployed properly.

# Next, we build the binaries and setup the experiments in all the VMs.
python3 scripts deploy-experiments -c <path/to/experiment/toml> -d <workdir>

# We run the experiments next.
python3 scripts run-experiments -c <path/to/experiment/toml> -d <workdir> 


# This will download all the logs from the experiments after the experiments end.
# We plot the graphs next.
python3 scripts results -c <path/to/experiment/toml> -d <workdir>

# The plots will be available in <workdir>/results/

# IMPORTANT: Don't forget to teardown the VMs after the experiment is done.
python3 scripts teardown -c <path/to/experiment/toml> -d <workdir>
```



# Artifact Claims

We arrange our main results into 4 claims and provide experiment TOML file for each in `claims/` located at the root of the repo.
For each TOML file, repeat the "Running Experiments" section above to generate the results.
For a more comprehensive set of experiment configs, see the `experiments/` directory.


## Claim 1: Pirateship imposes minimal overhead over existing CFT and BFT protocols.

Please run an experiment with `claims/01-overhead.toml` for this.
This runs Pirateship against signed_raft, engraft, autobahn and hotstuff with loads near saturation,
and creates a subset of Fig 5a.

For clarity, we give the concrete commands (following "Running Experiments" section above):

```bash
source .venv/bin/activate
python3 scripts deploy -c claims/01-overhead.toml
python3 scripts deploy-experiments -c claims/01-overhead.toml -d <workdir>
python3 scripts run-experiments -c claims/01-overhead.toml -d <workdir> 
python3 scripts results -c claims/01-overhead.toml -d <workdir>
python3 scripts teardown -c claims/01-overhead.toml -d <workdir>
```


## Claim 2: Pirateship can automatically detect and recover from equivocation.

Please run an experiment with `claims/02-equivocation.toml` for this.
This replicates Fig 6b, which plots the throughput of a selected node over time.

If you can't see the negative spike in throughput, change `results.target_node` to any other node.
The experiment makes the leader in view 1 (node1) to equivocate and create two branches.
Half the nodes receive branch 1 and the other half branch 2.
The new leader in view 2 (node2) has equal probability of selecting one of these.
Hence only half of the nodes need to rollback and therefore have a negative throughput spike.


## Claim 3: Pirateship's fast path creates latency benefits. Commit and Audit have the same throughput.

Please run an experiment with `claims/03-fastpath.toml` for this.
This runs Pirateship with and without fast path audits and compares the latency of commit, fast path audit and slow path audit.
It will replicate Fig 6a.


## Claim 4: Applications can effectively use the asynchronous auditing capability.

Please run an experiment with `claims/04-application.toml` for this.
This runs the banking application that forces transactions above a given money threshold to wait for audits,
and then plots the average response times vs the threshold.
It replicates Fig 7b.




> Note: The multi-platform experiment, as described in the paper, requires very specific Azure quotas in the regions described in the paper, and incurs very high network egress costs. Similarly, running the Code Transparency Service requires access to Azure Confidential Containers. We have not been able to re-acquire the quotas for these requirements with our current Azure account.
