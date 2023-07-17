import os
import shuffle

def pytest_sessionfinish():
    """Remove the log file created by the tested functions."""
    if os.path.exists(shuffle.LOG_FILE):
        os.remove(shuffle.LOG_FILE)
