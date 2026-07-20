from setuptools import setup, find_packages

setup(
    name='evtx2xml',
    version='0.1.0',
    packages=find_packages(),
    install_requires=[
        'evtx==0.8.2',
        'requests==2.32.3',
    ],
    entry_points={
        'console_scripts': [
            'evtx2xml=evtx2xml.evtx_to_xml:main',
        ],
    },
    url='https://github.com/wazuh/wazuh',
    author='Wazuh  Inc.',
    description='A tool to convert EVTX files to XML',
)
