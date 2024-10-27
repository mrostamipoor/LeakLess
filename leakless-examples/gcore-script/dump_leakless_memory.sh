#!/bin/bash


# Name of the process to look for
PROCESS_NAME="leakless"

# Find the PIDs of the 'leakless' process that involve HTTP in their command arguments
PIDS=$(ps aux | grep "$PROCESS_NAME" | grep -i "http" | grep -v "grep" | awk '{print $2}')

# Check if the process is running
if [ -z "$PIDS" ]; then
    echo "No 'leakless' process involving HTTP is running."
    exit 1
fi

echo "Found 'leakless' process(es) involving HTTP with PIDs: $PIDS"

# Create the core dump directory if it doesn't exist
DUMP_DIR="./core_dumps"
mkdir -p "$DUMP_DIR"

# Get the current timestamp formatted as "YYYYMMDD_HHMMSS_N" (YearMonthDay_HourMinuteSecond_Nanoseconds)
TIMESTAMP=$(date +"%Y%m%d_%H%M%S_%N")

# Iterate over each PID and generate a core dump
for PID in $PIDS; do
    DUMP_FILE="$DUMP_DIR/leakless_http_core_${PID}_$TIMESTAMP.dump"
    echo "Dumping memory of process $PID to $DUMP_FILE"
    
    # Generate the core dump using gcore
    sudo gcore -o "$DUMP_FILE" "$PID"
    
    if [ $? -eq 0 ]; then
        echo "Memory dump for process $PID successful. Dump file created: $DUMP_FILE"
    else
        echo "Failed to dump memory for process $PID"
    fi
done