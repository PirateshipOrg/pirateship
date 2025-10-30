#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import time
from pyscitt.client import Client
import os
import requests

HOST = os.getenv("SCITT_HOST", "https://localhost:4001")
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
COSE_FILE = os.path.join(SCRIPT_DIR, "../../benches/assets/claim.cose")
POLICY_FILE = os.path.join(SCRIPT_DIR, "../../benches/assets/policy.js")
CLIENT_WAIT_TIME = 0.01

client = Client(HOST, development=True, wait_time=CLIENT_WAIT_TIME)

with open(POLICY_FILE, "rb") as f:
    policy_content = f.read()
    response = requests.post(f"{HOST}/policy", data=policy_content, headers={"Content-Type": "application/text"}, verify=False)
    if response.status_code != 200:
        raise Exception(f"Failed to set policy: {response.status_code} {response.text}")

with open(COSE_FILE, "rb") as f:
    signed_statement = f.read()

client.submit_signed_statement_and_wait(signed_statement)
