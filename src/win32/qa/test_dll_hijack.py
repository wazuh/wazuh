import pytest
import subprocess
import os
import csv
import pathlib
import time

EXE_PATH = 'C:\\executables'
PROCMON_PATH = 'C:\\ProcessMonitor\\Procmon64.exe'
PROCMON_PML_LOGS = 'C:\\procMonLogs.pml'
PROCMON_CSV_OUTPUT = 'C:\\procMonFilteredLogs.csv'
PROCMON_CONFIG = 'ProcmonDLLNotFoundConfiguration.pmc'
# Only folders protected by administrator privileges should be added to the list
WHITE_LIST_PATH = ('C:\\Windows\\System32\\', 'C:\\Windows\\SysWOW64\\', 'C:\\Windows\\WinSxS\\')
EXE_TIMEOUT = 60

def generate_csv_logs(exe_path):
    # Delete previous logs if they exist
    try:
        os.remove(PROCMON_PML_LOGS)
    except OSError:
        pass

    try:
        os.remove(PROCMON_CSV_OUTPUT)
    except OSError:
        pass

    try:
        commands_no_wait = [f"{PROCMON_PATH} /terminate",
                            f"{PROCMON_PATH} /quiet /minimized /accepteula /nofilter /backingfile {PROCMON_PML_LOGS}"]

        for command in commands_no_wait:
            print(f"Running '{command}'")
            subprocess.Popen(command)
            # Giving the command time to execute
            time.sleep(5)

        commands_wait = [f"{PROCMON_PATH} /waitforidle",
                         f"{exe_path}",
                         f"{PROCMON_PATH} /terminate",
                         f"{PROCMON_PATH} /Quiet /Minimized /AcceptEula /LoadConfig {PROCMON_CONFIG} /Openlog {PROCMON_PML_LOGS} /SaveApplyFilter /SaveAs {PROCMON_CSV_OUTPUT}"]

        for command in commands_wait:
            print(f"Running '{command}'")
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=f"{EXE_PATH}")
            try:
                stdout, stderr = process.communicate(timeout=EXE_TIMEOUT)
            except subprocess.TimeoutExpired:
                print("Timeout expired.")
                process.kill()
                stdout, stderr = process.communicate()
                pytest.fail(f"Error while executing '{command}'. Return code: {process.returncode}.\nStdout:\n{stdout.decode()}\nStderr:\n{stderr.decode()}")

    except Exception as e:
        pytest.fail(f"Error while getting the CSV logs for '{exe_path}' with Process Monitor: {e}.")

@pytest.fixture(name='current_exe', scope='module', params=list(map(str, list(pathlib.Path(EXE_PATH).glob('*.exe')))))
def get_exe_path(request):
    return request.param

def test_dll_not_found(current_exe):
    # Generate .csv output
    generate_csv_logs(current_exe)

    # Save .csv file for later analysis
    exe_name = current_exe.split('\\')[-1]
    os.system(f"copy {PROCMON_CSV_OUTPUT} {EXE_PATH}\\{exe_name}.csv")

    # Read .csv file
    with open(PROCMON_CSV_OUTPUT) as csv_file:
        csv_reader = csv.DictReader(csv_file, delimiter=',')
        # Checking if CSV file contains data
        rows = list(csv_reader)
        if not rows:
            pytest.fail("Process Monitor didn't capture any event.")

        for row in rows:
            if (not row['Process Name'] in current_exe ):
                continue
            print("Checking row: " + str(row))
            if (row['Path'].startswith(WHITE_LIST_PATH)):
                continue
            pytest.fail(f"Process '{row['Process Name']}' is vulnerable to DLL hijacking due to '{row['Path']}'.")
