#!/bin/bash
# Script to copy debug script to tracer and run it

set -e

SESSION_ID="${1:-0xd2020000031cefe3}"

echo "==================================================================="
echo "Running File Size Debug on tracer.corp.netapp.com"
echo "Session ID: $SESSION_ID"
echo "==================================================================="
echo ""

# Copy debug script to tracer and run it
echo "📤 Copying debug script and running..."
echo ""
scp debug_file_sizes.py jtownsen@tracer.corp.netapp.com:/tmp/debug_file_sizes.py && \
ssh jtownsen@tracer.corp.netapp.com "cd /srv/tracer/current && docker compose exec -T smbreplay /opt/venv/bin/python /tmp/debug_file_sizes.py $SESSION_ID"

echo ""
echo "==================================================================="
echo "Debug complete!"
echo "==================================================================="
