# Syscollector Testing Tool
## Index
1. [Purpose](#purpose)
2. [Compile Wazuh](#compile-wazuh)
3. [How to use the tool](#how-to-use-the-tool)

## Purpose
The Syscollector Testing Tool was created to test and validate the data obtained by the module's execution. This tool works as a black box where an user will be able execute it and analyze the output data as desired.

## Compile Wazuh
In order compile the solution on a specific wazuh target, the project needs to be built either in release or debug mode.
```
make TARGET=server|agent <DEBUG=1>
```

## How to use the tool
In order to run the `syscollector_test_tool` (located in `src/wazuh_modules/syscollector/build/bin` folder) utility the only step to be followed is just to execute the tool (without parameters):
```
./syscollector_test_tool
```

The information output will vary based on the Operating System the tool is being executed.
A brief example could be similar to the following one:

```
Syscollector started.
sync output payload:
{"component":"syscollector_hwinfo","data":{"begin":" ","checksum":"3db55e04fee8f5aa7419d8b9d4d1617a3b8fd2ef","end":" ","id":1612989513},"type":"integrity_check_global"}
sync output payload:
{"component":"syscollector_osinfo","data":{"begin":"Ubuntu","checksum":"0c240d543ff8a7b79b5c2d0c4e2e29ca373ed307","end":"Ubuntu","id":1612989513},"type":"integrity_check_global"}
sync output payload:
{"component":"syscollector_network_iface","data":{"begin":"337c5c4e7d7cd33351bef413cfc2d6303f13e83e","checksum":"2c2e4ad6d01264dc57b2b3039e49a96ca1509330","end":"d131e91c2db8ceb58409fc3bb90aaeb4d1e4ec91","id":1612989513},"type":"integrity_check_global"}
sync output payload:
{"component":"syscollector_network_protocol","data":{"begin":"0e1a576f6770c94e91a84fa0edfd614c6dc12a97","checksum":"2378bf6ee268515ac6cad0945e4a34be8dd631d5","end":"db5cc5ed93bcde1022fcc50aa26b9de65c1f15e2","id":1612989513},"type":"integrity_check_global"}
sync output payload:
{"component":"syscollector_network_address","data":{"begin":"2ccf6b2db44e65a68d86a6b9ef6f17a80a907569","checksum":"d41fee050466607400a5f290ed9b894029db85fc","end":"e9981f5ab4c34df5aa88d243e53b1d4426a0516b","id":1612989513},"type":"integrity_check_global"}
sync output payload:
{"component":"syscollector_packages","data":{"begin":"003015c0ebad681afe5d952aefdd4b4594c5582f","checksum":"d7f1fddc385a2b2ed217d4e4f69d8dea91c59b3b","end":"fff4269c511fbd018de2f99a51418cb7df642b5d","id":1612989513},"type":"integrity_check_global"}
sync output payload:
{"component":"syscollector_hotfixes","data":{"id":1612989513},"type":"integrity_clear"}
sync output payload:
{"component":"syscollector_ports","data":{"begin":"0314f72c149cf5039a8b5600bfd37c84cc7ec864","checksum":"5e7653d32d990ee20d8721c5d364031d81a24ea9","end":"e4275099e8eda9a6361665b27d166208ac573609","id":1612989513},"type":"integrity_check_global"}
sync output payload:
{"component":"syscollector_processes","data":{"begin":"1","checksum":"57e84d8e1c7b05489f68e5e013db408f5ef2abbd","end":"984","id":1612989513},"type":"integrity_check_global"}
```
