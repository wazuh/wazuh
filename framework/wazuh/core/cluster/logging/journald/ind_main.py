from logging import getLogger, INFO
from multiprocessing import Process
from os import getpid
from systemd import journal

logger = getLogger('test')
logger.addHandler(journal.JournalHandler(SYSLOG_IDENTIFIER='test_unit'))
logger.setLevel(INFO)


def f():
    logger.info(getpid())


if __name__ == '__main__':
    processes = [Process(target=f) for _ in range(5)]
    for process in processes:
        process.start()

    for process in processes:
        process.join()
