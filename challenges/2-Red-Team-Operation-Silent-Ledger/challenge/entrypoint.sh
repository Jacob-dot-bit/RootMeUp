#!/bin/bash
set -e

# Generate SSH host keys on first boot
ssh-keygen -A >/dev/null 2>&1
mkdir -p /run/sshd
mkdir -p /run/meridian

# Start the internal cron daemon (drives the F4 privesc vector)
cron

# Start the internal fleet orchestrator (drives the F8 vector)
python3 /opt/meridian/orchestrator.py &

# Foreground SSH daemon keeps the container alive.
# (kept as a plain foreground call, not `exec`, so bash stays PID 1
#  and can reap the cron/orchestrator children)
/usr/sbin/sshd -D -e
