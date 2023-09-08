# WiFiDirectLegacyAP

Python port of https://github.com/microsoft/windows-classic-samples/tree/main/Samples/WiFiDirectLegacyAP

Creates a WiFi local access point other devices can join. 

The access point hardware adapter needs WiFiDirect support (common) but not hosted network support (extremely uncommon).

Note the internet connection on the access point, if any, is not shared with the clients, therefore the access point is not shut down when there's no internet connection (which happens on regular Windows 10 access points unless a certain registry setting is set).

See https://github.com/govert/WiFiDirectLegacyAPDemo and https://learn.microsoft.com/en-us/windows-hardware/drivers/partnerapps/wi-fi-direct for more information

## Features
- Parses winrt MIDL files
- Generates Python code from winrt MIDL files
- Generates Pythonic accessors for event handlers in winrt objects
- Generates Pythonic constructors for winrt activatables and statics
- Creates a local access point using winrt WiFiDirect APIs

## Requirements
- WiFiDirect supported WiFi hardware (most)
- Windows 10
- Python 2.7
- comtypes

## Usage

1. Fill _out\ssid_password.txt with two lines containing the ssid and the password or run without and it will use the default autogenerated ssid and password which will be output to the standard output
1. Run WiFiLegacyAP.py
```bat
C:\Users\atejada\Documents\works\python\wifidirectlegacyap>WiFiDirectLegacyAP.py
2023-09-07 18:28:27,428 WARNING:WiFiDirectLegacyAP.py(1765):[46788] winrt_wifi: Error reading _out\ssid_password.txt, will use random ssid and password
Sleeping forever, ssid 'DIRECT-THXXXXXXXXPJUY' password 'MJMx0OJf' press ctrl+c to finish
Connection completed WiFiDirect#XX:XX:XX:XX:XX:XX_LegacyPendingRequest
Disconnected WiFiDirect#XX:XX:XX:XX:XX:XX_LegacyPendingRequest
...
```
## Related Projects
- https://github.com/govert/WiFiDirectLegacyAPDemo
- https://github.com/gerfen/WiFiDirectLegacyAPCSharp
- https://github.com/zig13/WifiDirectLegacySurplex
- https://github.com/spieglt/wifidirect-legacy-ap

## TODO
- More code cleanup (remove tests, add type hinting, add more pythonic attributes)
- Console implementation
- Iterator implementation
- Proper support for winrt templated interfaces