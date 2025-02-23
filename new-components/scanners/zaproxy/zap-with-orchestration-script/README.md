# Zap Orchestration

This directory contains the necessary components to orchestrate ZAP to scan against a target.
The example orchestration script is in zap-orchestration.py and if you want to modify this example you can do so by modifying the python script.

## Example Running
Here's how to run a simple PoC for this script dockerfile:


* First build the image with: `docker build -t zap-with-orchestration .`
* To run this example safely we need a docker network which we can create by running `docker network create zap-demo`
* Then, we need an example vulnerable application, the example script is meant to work against a container of the `bodgeit` vulnerable application running locally. Let's start the container with `docker run --network zap-demo --name bodgeit.com captainfoobar/bodgeit`
* Last, run the example `docker run -ti -v \`pwd\`:/scratch --network zap-demo zap-with-orchestration:latest`
Monitor the example and after a few minutes you should see a sarif file containing the results in you local directory
