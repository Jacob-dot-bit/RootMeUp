#!/bin/bash
# Meridian nightly cleanup - purge stale temp files
# Owner: root  Group: svc_backup (group-writable on purpose: svc_backup
# is supposed to be able to tweak the retention policy without bugging IT)
find /tmp -type f -mtime +7 -delete 2>/dev/null
