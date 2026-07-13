# Pirateship SOSP 2026 Artifacts

This branch (`sosp-artifact`) acts as a snapshot to reproduce the graphs in our SOSP submission, while the main development continues in `main`.

# Setup

Running the experiments requires access to Azure. Please contact the authors to have your email added to our development Azure account.

Install [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/?view=azure-cli-latest). Then run:
```bash
az login # Login using the email provided with the authors.
```

Install [Terraform](https://developer.hashicorp.com/terraform/install). Terraform handles all VM deployment and teardown necessary for the experiments.


Clone the repo locally with the submodules:

```bash
git clone --recurse-submodules git@github.com:PirateshipOrg/pirateship.git
```

Setup your Python environment:

```bash
virtualenv .venv
source .venv/bin/activate
pip install -r scripts/requirements.txt
```


## Running Experiments

Our experiments are end-to-end encoded in TOML files similar to the ones in `experiments/`.
Below we summarize the common steps to run each experiment.
Refer to additional details about running our experiment infrastructure [here](scripts/README.md).

> WARNING: The following steps take a lot of time! Please be patient.

```bash
# To start an experiment, we first deploy the necessary VMs.
python3 scripts deploy -c path/to/experiment/toml

# This deploys the VMs and sets up a directory to store log files and SSH keys.
# The directory typically is named `deployment_artifacts/<timestamp>`
# We will call this directory <workdir>.

# Wait for up to 5 minutes after running deploy for all VMs to be deployed properly.

# Next, we build the binaries and setup the experiments in all the VMs.
python3 scripts deploy-experiments -c path/to/experiment/toml -d <workdir>

# We run the experiments next.
python3 scripts run-experiments -c path/to/experiment/toml -d <workdir> 


# This will download all the logs from the experiments after the experiments end.
# We plot the graphs next.
python3 scripts results -c path/to/experiment/toml -d <workdir>

# The plots will be available in <workdir>/results/

# IMPORTANT: Don't forget to teardown the VMs after the experiment is done.
python3 scripts teardown -c path/to/experiment/toml -d <workdir>
```



# Artifact Claims

We arrange our main results into 4 claims and provide experiment TOML file for each in `claims/`.
For each TOML file, repeat the "Running Experiments" section above to generate the results.
For a more comprehensive set of experiment configs, see the `experiments/` directory.


## Claim 1: Pirateship imposes minimal overhead over existing CFT and BFT protocols.

Please run an experiment with `claims/01-overhead.toml` for this.
This runs Pirateship against signed_raft, engraft, autobahn and hotstuff with loads near saturation,
and creates a subset of Fig 5a.


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




> Note: The multi-platform experiment, as described in the paper, requires very specific Azure quotas in the regions described in the paper, and incurs very high network egress costs. Similarly, running the Code Transparency Service requires access to Azure Confidential Containers. We have not been able to make arrangements for these requirements with our current Azure account.
