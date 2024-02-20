import os
import signal
import subprocess
import shlex
import time

BINARY_PATH = os.environ.get("ENGINE_DIR", "") + "/build/main"
CONF_FILE = os.environ.get("CONF_FILE", "")

def send_interrupt_signal(pid):
    """
    Sends an interrupt signal (SIGINT) to a specified process.
    """
    try:
        os.kill(pid, signal.SIGINT)
        print(f"Interrupt signal sent to the process with PID {pid}")
    except ProcessLookupError:
        print(f"Could not find the process with PID {pid}")

def before_all(context):
    """
    Executes actions before the start of all scenarios.
    """
    # Command to execute the binary in the background
    command = f"{BINARY_PATH} --config {CONF_FILE} server -l error --api_timeout 1000 start"

    # Split the command into a list of arguments using shlex
    args = shlex.split(command)

    # Execute the process in the background with subprocess.Popen
    process = subprocess.Popen(args)

    # Wait for a moment to ensure the process has started
    time.sleep(2)

    # Get the PID of the process and store it in the context
    context.pid = process.pid

def after_all(context):
    """
    Executes actions after the completion of all scenarios.
    """
    # Send an interrupt signal to the background process using the stored PID
    send_interrupt_signal(context.pid)
    time.sleep(2)
