#!/bin/bash

"$@"

# Capture the exit code
exit_code=$?

if [ $exit_code -eq 1 ]; then
    echo "scan completed, vulnerabilities found"
    exit 0
elif [ $exit_code -eq 2 ]; then
    echo "scan failed to complete, check the logs for errors"
    exit 1
elif [ $exit_code -eq 3 ]; then
    echo "scan completed, no supported projects detected"
    exit 0
else
    exit $exit_code
fi
