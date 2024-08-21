from logging import basicConfig, getLogger, INFO
from multiprocessing import Process
from os import getpid
from signal import pause
from sys import stderr

basicConfig(stream=stderr)
logger = getLogger('test')
logger.setLevel(INFO)


def f():
    logger.info(getpid())
    pause()


if __name__ == '__main__':
    processes = [Process(target=f) for _ in range(5)]
    for process in processes:
        process.start()
    
    pause()
