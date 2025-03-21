# Zap Orchestration

This directory contains the necessary components to orchestrate ZAP to scan against a target.
The example orchestration script is in zap-orchestration.py and if you want to modify this example you can do so by modifying the python script.

## Running

* Run the bodgeit application somewhere reachable by your laptop (not `localhost`, since smithy runs in containers, it won't find something running only on localhost).

* Adjust the url of the vulnerable target in `zap-orchestration.py`
