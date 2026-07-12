# Pirateship SOSP 2026 Artifacts

This branch (`sosp-artifact`) acts as a snapshot to reproduce the graphs in our SOSP submission, while the main development continues in `main`.

# Setup

Running the experiments requires access to Azure. Please contact the authors to have your email added to our development Azure account.

Install [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/?view=azure-cli-latest). Then run:
```bash
az login # Login using the email provided with the authors.
```

Install [Terraform](https://developer.hashicorp.com/terraform/install)


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
```



# Artifact Claims

We arrange our main results into 4 claims and provide scripts and configs to run the experiments for each in `claims/`.
For a more comprehensive set of experiment configs, see the `experiments/` directory.


## Claim 1:


## Claim 2:


## Claim 3:


## Claim 4:

> Note: The multi-platform experiment, as described in the paper, requires very specific Azure quotas in the regions described in the paper, and incurs very high network egress costs. Similarly, running the Code Transparency Service requires access to Azure Confidential Containers. We have not been able to make arrangements for these requirements with our current Azure account.
