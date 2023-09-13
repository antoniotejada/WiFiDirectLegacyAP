#!/usr/bin/env python
"""
Port to Python of

https://github.com/microsoft/Windows-classic-samples/tree/main/Samples/WiFiDirectLegacyAP

https://download.microsoft.com/download/7/8/7/787469FC-99B4-4726-9932-945111BDC809/WiFiDirectLegacyAPDemo_v1.0.zip

## Other ports

https://github.com/gerfen/WiFiDirectLegacyAPCSharp
https://github.com/zig13/WifiDirectLegacySurplex
https://github.com/spieglt/wifidirect-legacy-ap
https://github.com/govert/WiFiDirectLegacyAPDemo


## PyWinRt / python winsdk

https://github.com/pywinrt/python-winsdk/blob/main/pywinrt/winsdk/src/_winrt.cpp
https://github.com/pywinrt/python-winsdk

## pythonnet

https://pythonnet.github.io/pythonnet/python.html

## rotypes

https://github.com/ArknightsAutoHelper/ArknightsAutoHelper/tree/master/rotypes

## comtypes

https://github.com/enthought/comtypes
https://pythonhosted.org/comtypes/
https://pythonhosted.org/comtypes/server.html
https://github.com/shanewholloway/comtypes
https://svn.python.org/projects/ctypes/tags/comtypes-0.3.2/docs/com_interfaces.html
https://gist.github.com/olafhartong/980e9cd51925ff06a5a3fdfb24fb96c2 list of clsids

## ctypes

https://github.com/python/cpython/blob/main/Lib/ctypes/wintypes.py
https://docs.python.org/2.7/library/ctypes.html
https://stackoverflow.com/questions/53311519/python-3-7-passing-parameters-to-dll-using-ctypes

## comtypes examples

https://stackoverflow.com/questions/57149456/how-to-implement-windows-10-ivirtualdesktopmanager-interface-in-python
https://github.com/DanEdens/Virtual_Desktops_Plugin/blob/master/Virtualdesktops/__int__.py
https://stackoverflow.com/questions/48986244/access-com-methods-from-python
https://github.com/Qirky/PyKinectTk/blob/master/PyKinectTk/utils/PyKinect2/PyKinectV2.py


## winrt/winsdk reference/sources

https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/winrt/inspectable.idl
https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/winrt/roapi.h#L237
https://raw.githubusercontent.com/tpn/winsdk-10/master/Include/10.0.16299.0/winrt/windows.foundation.h

https://learn.microsoft.com/en-us/cpp/cppcx/wrl/how-to-activate-and-use-a-windows-runtime-component-using-wrl?view=msvc-170

https://stackoverflow.com/questions/16466641/how-to-declare-and-link-to-roinitialize-rouninitialize-rogetactivationfactory-an
https://stackoverflow.com/questions/71607881/using-wrl-to-access-winrt-where-do-you-find-the-right-names-to-use-for-the-clas
https://stackoverflow.com/questions/71595142/using-wrl-to-access-winrt-i-cannot-get-activateinstance-to-work

https://learn.microsoft.com/en-us/windows/win32/api/roapi/nf-roapi-rogetactivationfactory
https://learn.microsoft.com/en-us/windows/win32/api/roapi/nf-roapi-roactivateinstance
https://learn.microsoft.com/en-gb/cpp/cppcx/wrl/hstring-class?view=msvc-170&viewFallbackFrom=vs-2017
https://learn.microsoft.com/en-us/uwp/cpp-ref-for-winrt/hstring
https://learn.microsoft.com/en-us/windows/win32/api/winstring/nf-winstring-windowscreatestring
https://learn.microsoft.com/en-us/windows/win32/winrt/hstring

## winrt metadata

### winmd files

https://stackoverflow.com/questions/54375771/how-to-read-a-winmd-winrt-metadata-file
https://github.com/microsoft/winmd/tree/master
https://learn.microsoft.com/en-us/windows/win32/api/rometadataresolution/nf-rometadataresolution-rogetmetadatafile

### idl files

Some idl are missing from winrt (windows.foundation.collections.idl), mingw seems to have all of them
    pacman -S mingw-w64-i686-headers-git

https://packages.msys2.org/package/mingw-w64-i686-headers-git?repo=mingw32
https://github.com/MicrosoftDocs/winrt-related/blob/docs/winrt-related-src/midl-3/synthesizing-interfaces.md

## winrt wifidirect

https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/winrt/windows.devices.wifidirect.h
https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/winrt/windows.devices.wifidirect.idl

https://learn.microsoft.com/en-us/windows/win32/nativewifi/using-the-wi-fi-direct-api
https://github.com/microsoft/Windows-universal-samples/tree/main/Samples/WiFiDirect/cpp
https://github.com/Microsoft/Windows-universal-samples/tree/main/Samples/WiFiDirectServices
https://learn.microsoft.com/en-us/samples/microsoft/windows-universal-samples/wifidirect/
https://learn.microsoft.com/en-us/uwp/api/windows.devices.wifidirect.wifidirectlegacysettings?view=winrt-22621

## Uncategorized links

https://stackoverflow.com/questions/8043924/windows-wlanapi-and-python-ctypes
https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlanenuminterfaces
https://github.com/microsoft/Windows-classic-samples/issues/82
https://learn.microsoft.com/en-us/windows-hardware/drivers/partnerapps/wi-fi-direct

https://stackoverflow.com/questions/40286987/discover-wifi-direct-services-windows-android

https://gist.github.com/lala7573/3f7a209195f4d1e45747

## Procedure to manually translate interfaces from midl/C++ to comtypes

1. Get the line from 

        https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/WiFiDirectLegacyAP/cpp/WlanHostedNetworkWinRT.cpp

    eg 
            Microsoft::WRL::ComPtr<ABI::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisementPublisher> _publisher;
        hr = Windows::Foundation::ActivateInstance(HStringReference(RuntimeClass_Windows_Devices_WiFiDirect_WiFiDirectAdvertisementPublisher).Get(), &_publisher);

1. Get the GUID and interface definition from 

    https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/winrt/windows.devices.wifidirect.idl

        [contract(Windows.Foundation.UniversalApiContract, 1.0)]
        [exclusiveto(Windows.Devices.WiFiDirect.WiFiDirectAdvertisementPublisher)]
        [uuid(B35A2D1A-9B1F-45D9-925A-694D66DF68EF)]
        interface IWiFiDirectAdvertisementPublisher : IInspectable
        {
            [propget] HRESULT Advertisement([out] [retval] Windows.Devices.WiFiDirect.WiFiDirectAdvertisement** value);
            [propget] HRESULT Status([out] [retval] Windows.Devices.WiFiDirect.WiFiDirectAdvertisementPublisherStatus* value);
            [eventadd] HRESULT StatusChanged([in] Windows.Foundation.TypedEventHandler<Windows.Devices.WiFiDirect.WiFiDirectAdvertisementPublisher*, Windows.Devices.WiFiDirect.WiFiDirectAdvertisementPublisherStatusChangedEventArgs*>* handler, [out] [retval] EventRegistrationToken* token);
            [eventremove] HRESULT StatusChanged([in] EventRegistrationToken token);
            HRESULT Start();
            HRESULT Stop();
        }
        https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/winrt/windows.devices.wifidirect.idl#L264C1-L276C1

1. Implement

"""

import ctypes
from ctypes import wintypes
import datetime
import json
import logging
import os
import re
import string
import sys
import time

def class_name(o):
    return o.__class__.__name__

class LineHandler(logging.StreamHandler):
    """
    Split lines in multiple records, fill in %(className)s
    """
    def __init__(self):
        super(LineHandler, self).__init__()

    def emit(self, record):
        # Find out class name, _getframe is supposed to be faster than inspect,
        # but less portable
        # caller_locals = inspect.stack()[6][0].f_locals
        caller_locals = sys._getframe(6).f_locals
        clsname = ""
        zelf = caller_locals.get("self", None)
        if (zelf is not None):
            clsname = class_name(zelf) + "."
            zelf = None
        caller_locals = None
        
        # Indent all lines but the first one
        indent = ""
        text = record.getMessage()
        messages = text.split('\n')
        for message in messages:
            r = record
            r.msg = "%s%s" % (indent, message)
            r.className = clsname
            r.args = None
            super(LineHandler, self).emit(r)
            indent = "    " 

def setup_logger(logger):
    """
    Setup the logger with a line break handler
    """
    logging_format = "%(asctime).23s %(levelname)s:%(filename)s(%(lineno)d):[%(thread)d] %(className)s%(funcName)s: %(message)s"

    logger_handler = LineHandler()
    logger_handler.setFormatter(logging.Formatter(logging_format))
    logger.addHandler(logger_handler) 

    return logger

comtypes_logger = logging.getLogger("comtypes")
setup_logger(comtypes_logger)
comtypes_logger.setLevel(logging.DEBUG)
# XXX Quick fix for duplicate output, investigate
#     See https://stackoverflow.com/questions/19561058/duplicate-output-in-simple-python-logging-configuration/19561320#19561320
comtypes_logger.propagate = False

# Note all interface files use the logger object from wrtcommon since they
# import * and don't create its own
wrtc_logger = logging.getLogger("wrtcommon")
setup_logger(wrtc_logger)
wrtc_logger.setLevel(logging.DEBUG)
wrtc_logger.propagate = False

logger = logging.getLogger(__name__)
setup_logger(logger)
logger.setLevel(logging.DEBUG)

def parse_interface_or_enum(f, namespaces):
    """
    Supported formats
    
    [contract(Windows.Foundation.UniversalApiContract, 1.0)]
    [exclusiveto(Windows.Devices.Enumeration.DeviceInformation)]
    [uuid(ABA0FB95-4398-489D-8E44-E6130927011F)]
    interface IDeviceInformation : IInspectable
    {
        [propget] HRESULT Id([out] [retval] HSTRING* value);
        [propget] HRESULT Name([out] [retval] HSTRING* value);
        [propget] HRESULT IsEnabled([out] [retval] boolean* value);
        [propget] HRESULT IsDefault([out] [retval] boolean* value);
        [propget] HRESULT EnclosureLocation([out] [retval] Windows.Devices.Enumeration.EnclosureLocation** value);
        [propget] HRESULT Properties([out] [retval] Windows.Foundation.Collections.IMapView<HSTRING, IInspectable*>** value);
        HRESULT Update([in] Windows.Devices.Enumeration.DeviceInformationUpdate* updateInfo);
        HRESULT GetThumbnailAsync([out] [retval] Windows.Foundation.IAsyncOperation<Windows.Devices.Enumeration.DeviceThumbnail*>** asyncOp);
        HRESULT GetGlyphThumbnailAsync([out] [retval] Windows.Foundation.IAsyncOperation<Windows.Devices.Enumeration.DeviceThumbnail*>** asyncOp);
    }
    
    
    [uuid(72DEAAA8-72EB-4DAE-8A28-8513355D2777)]
    [version(0x06030000)]
    interface IWiFiDirectDevice : IInspectable
        requires
            Windows.Foundation.IClosable
    {
        [propget] HRESULT ConnectionStatus([out] [retval] Windows.Devices.WiFiDirect.WiFiDirectConnectionStatus* value);
        [propget] HRESULT DeviceId([out] [retval] HSTRING* value);
        [eventadd] HRESULT ConnectionStatusChanged([in] Windows.Foundation.TypedEventHandler<Windows.Devices.WiFiDirect.WiFiDirectDevice*, IInspectable*>* handler, [out] [retval] EventRegistrationToken* token);
        [eventremove] HRESULT ConnectionStatusChanged([in] EventRegistrationToken token);
        HRESULT GetConnectionEndpointPairs([out] [retval] Windows.Foundation.Collections.IVectorView<Windows.Networking.EndpointPair*>** value);
    }

    enum WiFiDirectError
    {
        Success           = 0,
        RadioNotAvailable = 1,
        ResourceInUse     = 2
    };

    [activatable(Windows.Foundation.UniversalApiContract, 1.0)]
    [contract(Windows.Foundation.UniversalApiContract, 1.0)]
    [marshaling_behavior(agile)]
    [static(Windows.Devices.WiFiDirect.IWiFiDirectConnectionParametersStatics, Windows.Foundation.UniversalApiContract, 2.0)]
    runtimeclass WiFiDirectConnectionParameters
    {
        [default] interface Windows.Devices.WiFiDirect.IWiFiDirectConnectionParameters;
        [contract(Windows.Foundation.UniversalApiContract, 2.0)] interface Windows.Devices.WiFiDirect.IWiFiDirectConnectionParameters2;
        [contract(Windows.Foundation.UniversalApiContract, 2.0)] interface Windows.Devices.Enumeration.IDevicePairingSettings;
    }

    [
        contract(Windows.Foundation.FoundationContract, 1.0),
        uuid(6a79e863-4300-459a-9966-cbb660963ee1)
    ]
    interface IIterator<T> : IInspectable
    {
        [propget] HRESULT Current([out, retval] T *value);
        [propget] HRESULT HasCurrent([out, retval] BOOL *value);
        HRESULT MoveNext([out, retval] BOOL *value);
        HRESULT GetMany([in] UINT32 items_size, [out] T *items, [out, retval] UINT32 *value);
    }

    """
    def array_to_guid(a):
        assert len(a) == 11, "Unexpected length %d" % len(a)
        
        data1, data2, data3, data4 = a[0], a[1], a[2], a[3:]

        s = "%08X-%04X-%04X-%s-%s" % (
            data1,
            data2,
            data3,
            # https://devblogs.microsoft.com/oldnewthing/20220928-00/?p=107221
            string.join(["%02X" % b for b in data4[:2]], ""),
            string.join(["%02X" % b for b in data4[2:]], ""),
        )
        logger.info("array_to_guid %s %s", a, s)

        return s

    inside_braces = False
    interface = None
    enum = None
    runtime_class = None
    expecting_brace = False
    lines = []
    for l in f:
        print "l", repr(l)
        l = l.strip()
        if (l == ""):
            continue
        
        elif (expecting_brace and (l == "{")):
            inside_braces = True
            lines.append(l)
        
        # This needs to work for both } (interface) and }; (enum)
        elif (expecting_brace and (l.startswith("}"))):
            inside_braces = False
            lines.append(l)
            lines = []
            expecting_brace = False
            break

        elif (l == "{"):
            # Unexpected brace, must be a namespace
            print namespaces
            continue

        elif (l == "}"):
            # Unexpected brace, must be a namespace or a declare
            print "popping namespace", namespaces
            namespaces.pop()
            print "popped namespace", namespaces
            continue

        elif (inside_braces and (enum is not None)):
            m = re.match(r"\s*(?P<name>\w+)\s*=\s*(?P<value>(0x)?\d+),?", l)
            if (m is not None):
                lines.append(l)
                value = m.group("value")
                value =  int(value, 16) if (value.startswith("0x")) else int(value)
                enum_values[m.group("name")] = value

        elif (inside_braces and (runtime_class is not None)):
            # [default] interface Windows.Devices.WiFiDirect.IWiFiDirectConnectionParameters;
            # XXX Missing non-default interfaces, eg
            #   runtimeclass WiFiDirectConnectionRequest
            #   {
            #      [default] interface Windows.Devices.WiFiDirect.IWiFiDirectConnectionRequest;
            #      interface Windows.Foundation.IClosable;
            #   }
            #   Should interfaces be a list of flag,name?
            m = re.match(r"\s*\[\s*default\s*\]\s*interface\s+([^;]*);", l)
            if (m is not None):
                lines.append(l)
                runtime_class["default"] = m.group(1)

        elif (inside_braces and (interface is not None)):
            # Python standard library regular expressions are not powerful
            # enough to match nested syntax like templated types, do a pre-parse
            # of the line removing spaces from inside angles so the regular
            # expressions patterns for analyzing argument types don't need to
            # care about nested angles and commas and can just look at
            # whitespace

            # XXX This could also remove whitespace before and after dot, but
            #     the idl files being parsed don't generate those
            ll = ""
            lines.append(l)
            nested_angles = 0
            for c in l:
                if (c == "<"):
                    nested_angles += 1
                    ll += "<"
                    
                elif (c == ">"):
                    nested_angles -= 1
                    ll += ">"
                
                elif ((c in string.whitespace) and (nested_angles > 0)):
                    # Remove whitespace inside nested angles
                    pass

                else:
                    ll += c

            l = ll
            print "ll", repr(ll)
                    
            # XXX Add support for method split in two lines, eg Split() in
            #     collections.idl needs that (for now the .idl is modified so
            #     the lines are merged)
            m = re.match(r"""
                # XXX Allow multiple return flags, for now ignore [deprecated] 
                #     and [default_overload]
                (\[\s*deprecated\s*\(\s*[^)]*\)\s*\]\s*)?
                (\[\s*default_overload\s*\]\s*)?
                (\[\s*(?P<method_flag>eventadd|eventremove|propget|propput|overload\s*\(\s*[^)]*\))\s*\])?\s*
                (?P<return_type>[a-zA-Z0-9_.*<>,]+)\s* (?P<method_name>\w+)\s*
                \(\s*
                    (?P<all_params>(
                        (?P<all_param_flags>(\[\s*
                            (
                                out|
                                retval|
                                in|
                                optional|
                                range\([^)]*\)|
                                size_is\([^)]*\)|
                                (\s*,\s*)?
                            )+\s*
                        \]\s*)*)
                        (?P<param_type>[a-zA-Z0-9_.*<>,]+)(?P<param_type_stars>(\s|[*])+)
                        (?P<param_name>\w+)\s*
                        ,?
                        \s*
                    )*)
                \s*\)\s*;\s*
                """, 
                l, 
                re.VERBOSE
            )
            assert m is not None
            if (m is not None):
                print m.groupdict()
                try:
                    methods = interface["methods"]

                except:
                    methods = []
                    interface["methods"] = methods

                params = []
                method = {
                    "flag": m.group("method_flag"),
                    "return": m.group("return_type"),
                    "name": m.group("method_name"),
                    "params": params,
                }
            
                for mm in re.finditer(r"""
                        (?P<all_param_flags>(\[\s*
                            (
                                out|
                                retval|
                                in|
                                optional|
                                range\([^)]*\)|
                                size_is\([^)]*\)|
                                (\s*,\s*)?
                            )+\s*
                        \]\s*)*)
                        (?P<param_type>[a-zA-Z0-9_.*<>,]+)(?P<param_type_stars>(\s|[*])+)
                        (?P<param_name>\w+)\s*
                        ,?
                        \s*
                    """, 
                    m.group("all_params"), 
                    re.VERBOSE
                ):
                    print mm.groupdict()
                    flags = []
                    param = {
                        "type": mm.group("param_type") + ("*" * mm.group("param_type_stars").count("*")),
                        "name" : mm.group("param_name"),
                        "flags" : flags,
                    }
                    params.append(param)
                    all_param_flags = mm.group("all_param_flags")
                    all_param_flags = re.split(r"[[\],]", all_param_flags)
                    all_param_flags = filter(lambda s: s.strip() != "", all_param_flags)
                    print all_param_flags
                    flags.extend(all_param_flags)
                    
                methods.append(method)
                
        else:
            # XXX Cleanup all these into a single regexp?
            # XXX Have a single path interface initialization
            # XXX Have a single path runtime_class initialization
            m = re.match(r"\s*\[?\s*uuid\(\s*([^)]*)\s*\)\s*\]?\s*", l)
            if (m is not None):
                print "uuid", m.group(1)
                if (interface is None):
                    interface = {}
                    lines = []
                uuid = m.group(1)
                # Support both array of ints and dash-separated hex data 
                ll = uuid.split(",")
                if (len(ll) > 1):
                    uuid = array_to_guid([int(s) for s in ll])
                interface.update({ "uuid": uuid })
                lines.append(l)
                continue

            m = re.match(r"\s*\[?\s*exclusiveto\(\s*([^)]*)\s*\)\s*\]?\s*", l)
            if (m is not None):
                print "exclusiveto", m.group(1)
                if (interface is None):
                    interface = {}
                    lines = []
                interface.update({ "exclusiveto": m.group(1) })
                lines.append(l)
                continue
        
            m = re.match(r"\s*\[?\s*activatable\(\s*([^)]*)\s*\)\s*\]?\s*", l)
            if (m is not None):
                print "activatable", m.group(1)
                if (runtime_class is None):
                    runtime_class = {}
                    lines = []
                runtime_class.update({ "activatable": True })
                lines.append(l)
                continue
        
            m = re.match(r"\s*\[?\s*static\(\s*([^)]*)\s*\)\s*\]?\s*", l)
            if (m is not None):
                print "static", m.group(1)
                if (runtime_class is None):
                    runtime_class = {}
                    lines = []
                runtime_class.update({ "statics": runtime_class.get("statics", []) + [m.group(1).split(",")[0]] })
                lines.append(l)
                continue


            # Note the brace may not come if this is a forward declaration ended
            # by ";"
            m = re.match(r"\s*runtimeclass\s+(\w+)", l)
            if ((m is not None) and (not l.endswith(";"))):
                print "runtimeclass", m.group(1)
                if (runtime_class is None):
                    runtime_class = {}
                    lines = []
                runtime_class.update({ 
                    "name": string.join(filter(lambda n: n is not None, namespaces), ".") + "." + m.group(1), 
                    "type": "runtimeclass" ,
                    "lines": lines,
                })

                lines.append(l)
                expecting_brace = True
                continue

            m = re.match(r"\s*namespace\s+(\w+)\s*[{]?\s*", l)
            if (m is not None):
                print "pushing namespace", m.group(1), namespaces
                namespaces.append(m.group(1))
                print "pushed namespace", namespaces
                continue

            m = re.match(r"\s*declare\s*", l)
            if (m is not None):
                print "declare", namespaces
                # Insert declare as None namespaces so it can be popped when 
                # finding a declare closing brace
                print "pushing namespace"
                namespaces.append(None)
                print "pushed namespace", namespaces
                continue

            # XXX Trim intermediate spaces inside angles like it's done with
            #     types?
            m = re.match(r"\s*interface\s+(?P<interface_name>(\w|[< ,>])+)\s*:\s*(?P<parent_name>\w+)\s*", l)
            if (m is not None):
                print "interface name", m.group("interface_name"), "parent name", m.group("parent_name")
                interface.update({
                    "parent": m.group("parent_name"),
                    # XXX For now do strip on the name since there's no proper
                    #     space removal inside angles (and this is still not
                    #     removing them)
                    "name": m.group("interface_name").strip(),
                    "lines": lines,
                    "type": "interface",
                })
                lines.append(l)
                expecting_brace = True
                continue

            # XXX Missing delegates

            m = re.match(r"\s*enum\s+(?P<enum_name>\w+)\s*", l)
            if (m is not None):
                print "enum name", m.group("enum_name")
                lines = []
                enum_values = {}
                enum = {
                    "name": m.group("enum_name"),
                    "lines": lines,
                    "type": "enum",
                    "values": enum_values,
                }
                lines.append(l)
                expecting_brace = True
                continue

            print "unmatched line", repr(l)
            assert not inside_braces or ((interface is None) and (enum is None) and (runtime_class is None))

    if (runtime_class is not None):
        return runtime_class

    elif (interface is not None):
        return interface

    else:
        return enum

def parse_idl_file(filepath):
    with open(filepath, "r") as f:
        entries = {}
        namespaces = []
        while (True):
            entry = parse_interface_or_enum(f, namespaces)
            if (entry is None):
                break
            entries[entry["name"]] = entry

    return entries

class CodeGen(object):
    def __init__(self, f=None, indent_char=" ", indent_size=4):
        super(CodeGen, self).__init__()
        self.f = f
        self.indent = ""
        self.ind = 0
        self.lines = []
        self.indent_char = indent_char
        self.indent_size = indent_size

    def push_indent(self):
        self.ind += 1
        self.calculate_indent()

    def pop_indent(self):
        assert self.ind > 0
        self.ind -= 1
        self.calculate_indent()

    def append_line(self, line):
        line = line.rstrip()
        line = "%s%s\n" % (self.indent, line)
        if (self.f is None):
            self.lines.append(line)

        else:
            # XXX Allow a cached mode or have append() batch lines in case of
            #     list input?
            self.f.write(line)

    def calculate_indent(self):
        self.indent = self.indent_char * self.indent_size * self.ind

    def reset_indent(self):
        self.ind = 0
        self.calculate_indent()

    def get_lines(self):
        return self.lines
        
    def append(self, lines, *args):
        #type(list(string)|string)
        
        if (not isinstance(lines, list)):
            lines = lines % args
            lines = lines.splitlines()
            # splitlines will return empty list on empty string, convert to list
            # with empty string
            if (len(lines) == 0):
                lines = [""]

        # XXX Should this allow a list of strings with some strings having lines
        #     inside?

        # Autodetect the base indent, if the first line is empty eg coming from
        # g.append("""
        #   some indented code
        # """)
        # skip the first line completely (don't ignore on single lines in case
        # it's coming from a single separator line)
        if ((len(lines) > 1) and (lines[0].strip() == "")):
            lines = lines[1:]
        base_indent = len(lines[0]) - len(lines[0].lstrip())
        for line in lines:
            self.append_line(line[base_indent:])

def generate_python_enum(g, enum):
    """
    class TrustLevel(ENUM):
        BaseTrust = 0
        PartialTrust = BaseTrust + 1
        FullTrust = PartialTrust + 1
    """
    g.append("class %s(ENUM):", enum["name"])
    g.push_indent()
    g.append(['"""'] + enum["lines"] + ['"""'])
    
    sorted_names = sorted(enum["values"], cmp= lambda a, b: cmp(enum["values"][a], enum["values"][b]))
    for name in sorted_names:
        value = enum["values"][name]
        # XXX Missing escaping other keywords?
        # XXX Use straight enumname_enumvalue ints instead of class to avoid
        #     having to escape?
        if (name in ["None"]):
            name = name + "_"
        g.append("%s = %d", name, value)

    g.append("")

def generate_python_runtime_class(g, runtime_class, type_mappings):
    """
    class WiFiDirectPublisher(comtypes.COMObject):
        def __new__(cls):
            return activate_instance(cls)
    """
    type_name = convert_type_name(runtime_class["name"], type_mappings)
    default_interface = runtime_class.get("default", None)
    if (default_interface is None):
        # Some runtimeclasses eg KeyCredentialManager are empty, ignore
        return

    interface_name = convert_type_name(default_interface, type_mappings)
    g.append("class %s(%s):", type_name, interface_name)

    g.push_indent()

    g.append(['"""'] + runtime_class["lines"] + ['"""'])
    if (runtime_class.get("activatable", False)):
        g.append(
            """
            def __new__(cls):
                instance = activate_instance('%s', %s)
                # XXX This calls __init__ to wrap the object just created so the
                #     pythonic methods in the wrapper can be used (eg event 
                #     hooking), do it in activate_instance or find another 
                #     mechanism?
                instance.__init__()
                return instance
            """, 
            runtime_class["name"], interface_name)

    g.pop_indent()
    g.append("")
    
    if (runtime_class.get("statics", [])):
        # Note the runtime class is the device, not the devicestatic
        runtime_class_name = runtime_class["name"]
        for interface_name in runtime_class["statics"]:
            # [static(Windows.Devices.WiFiDirect.IWiFiDirectDeviceStatics, Windows.Foundation.UniversalApiContract, 1.0)]
            interface_name = convert_type_name(interface_name, type_mappings)
            
            # XXX This assumes the static is IInspectable, should it look it up
            #     or should this be deferred to when the static class is
            #     processed and looked up then?
            
            # XXX This is currently prefixing the class with _s to avoid stack
            #     overflow when creating the pointer to the interface, since
            #     __new__ calls activate_static which creates a pointer to the
            #     class which seems to create an instance of the class, maybe
            #     move inside the runtime_class?
            g.append("class %s_s(%s):", interface_name, "IInspectable")
            g.push_indent()
            g.append(
                """
                _iid_ = IID_%s
                def __new__(cls):
                    static = activate_static("%s", %s) 
                    return static
                """, interface_name, runtime_class_name, interface_name
            )
            g.pop_indent()

    

def convert_type_name(type_name, type_mappings):
    name = type_mappings.get(type_name, None)
    if (name is None):
        name = ""
        # XXX pointer nesting inside arbitrary generics is wrong, eg
        #       Windows.Foundation.IAsyncOperation<Windows.Devices.WiFiDirect.WiFiDirectDevice*>**
        #     is mangled as
        #       wintypes.POINTER(wintypes.POINTER(wintypes.POINTER(WindowsFoundationIAsyncOperation__WindowsDevicesWiFiDirectWiFiDirectDevice)))
        #     should be something that expresses
        #       wintypes.POINTER(wintypes.POINTER(WindowsFoundationIAsyncOperation__wintypes.POINTER(WindowsDevicesWiFiDirectWiFiDirectDevice))))
        
        # For consistency, use the same name mangling that Microsoft uses for C
        # in the winrt sdk:
        # - . in namespace converted to __C
        # - < converted to _num_ where num is the number of parameters in the template
        # - , converted to _
        # - types ended in _t
        # Eg
        # typedef ITypedEventHandler<ABI::Windows::Devices::WiFiDirect::WiFiDirectAdvertisementPublisher*,ABI::Windows::Devices::WiFiDirect::WiFiDirectAdvertisementPublisherStatusChangedEventArgs*> 
        # becomes
        # __FITypedEventHandler_2_Windows__CDevices__CWiFiDirect__CWiFiDirectAdvertisementPublisher_Windows__CDevices__CWiFiDirect__CWiFiDirectAdvertisementPublisherStatusChangedEventArgs_t
        param_count_stack = []
        prefix = ""
        for m in re.finditer(r"(\w+|[*<,>.])", type_name):
            token = m.group(1)
            if (token == "*"):
                # Don't put pointers inside template arguments
                if (len(param_count_stack) == 0):
                    name = "wintypes.POINTER(%s)" % name
                # XXX Otherwise needs to add the type to some kind of
                #     declaration block. It also needs to create the declaration
                #     when the template is closed, but for that it also needs to
                #     be able to read templated interfaces, store them and do
                #     the type replacement. For the time being those could be
                #     added manually with the right name mangling

            elif (token == "."):
                #name += "__C"
                # XXX Remove prefixes for the time being, in the future probably
                #     force caller to fill in mappings to remove them or have a
                #     prefix removal set?
                if (prefix != "wintypes"):
                    name = name[:-len(prefix)]
                
            elif (token == "<"):
                name = name + "_%d_"
                param_count_stack.append(1)

            elif (token == ","):
                name = name + "_"
                param_count_stack[-1] += 1
            
            elif (token == ">"):
                i = name.rfind("%d")
                name = name[0:i] + (name[i:] % param_count_stack.pop())

            else:
                # XXX This needs to convert
                prefix = type_mappings.get(m.group(1), m.group(1))
                name = name + prefix

        type_mappings[type_name] = name

    return name


def generate_python_interface(g, interface, type_mappings, generate_header, generate_methods, generate_short_methods = True):
    """
    IID_IInspectable = comtypes.GUID('{AF86E2E0-B12D-4C6A-9C5A-D7AA65101E90}')
    class IInspectable(comtypes.IUnknown):
        _case_insensitive_ = True
        _idlflags_ = []
        _iid_ = IID_IInspectable
        _methods_ = [
            comtypes.COMMETHOD(
                [comtypes.helpstring('Method GetIids')],
                comtypes.HRESULT, 'GetIids',
                (['out'], wintypes.POINTER(wintypes.ULONG), 'iidCount'),
                (['out'], wintypes.POINTER(wintypes.POINTER(comtypes.IID)), 'iids'),
            ),
            comtypes.COMMETHOD(
                [comtypes.helpstring('Method GetRuntimeClassName')],
                comtypes.HRESULT, 'GetRuntimeClassName',
                (['out'], wintypes.POINTER(HSTRING), 'className'),
            ),
            comtypes.COMMETHOD(
                [comtypes.helpstring('Method GetTrustLevel')],
                comtypes.HRESULT, 'GetTrustLevel',
                (['out'], wintypes.POINTER(TrustLevel), 'trustLevel'),
            ),
        ]
    """
    if ("<" in interface["name"]):
        # templated interface names don't generate code, ignore
        # XXX Change at parse time type from "interface" to "template" or
        #     "templated interface"?
        
        # XXX Code using templated interfaces needs to read the templated
        #     interface, generate the appropriate python code with the mangled
        #     interface name, and replace the instantiation with the mangled
        #     name
        if (generate_header):
            template_name = interface["name"]
            # XXX This assumes there's no template overload depending on the
            #     number of parameters
            template_name = template_name[0:template_name.find("<")]
            assert template_name not in type_mappings, "Duplicated template %r" % template_name
            # XXX This needs proper handling when this dict is found instead of
            #     a string in convert_type_name
            ## type_mappings[template_name] = interface
        return

    if (generate_header):
        g.append("IID_%s = comtypes.GUID('{%s}')", interface["name"], interface["uuid"])
        g.append("class %s(%s):", interface["name"], convert_type_name(interface["parent"], type_mappings))

        g.push_indent()
        g.append(['"""'] + interface["lines"] + ['"""'])
        # XXX These two don't seem to be needed, remove?
        #g.append("_case_insensitive_ = True")
        #g.append("_idlflags_ = []")
        g.append("_iid_ = IID_%s", interface["name"])
        for method in interface.get("methods", []):
            is_async_operation_handler = (
                (method["flag"] == "propput") and 
                (len(method["params"]) > 0) and 
                method["params"][0]["type"].startswith("IAsyncOperationCompletedHandler")
            )
            if ((method["flag"] != "eventadd") and not is_async_operation_handler):
                continue

            if (is_async_operation_handler):
                typed_event_handler_name = convert_type_name(method["params"][0]["type"], type_mappings).split("(")[1].split(")")[0]
                _, _, first_arg_type = typed_event_handler_name.split("_")
                second_arg_type = "AsyncStatus"

                g.append("""
                    def __init__(self):
                        self._OnCompletedFn = None
                        self._OnCompletedHandler = None
                        self._OnCompletedHandlerClass = None
                    
                    @property
                    def OnCompleted(self):
                        logger.info("")
                        # type:()->FWiFiDirectAdvertisementPublisher_WiFiDirectAdvertisementPublisherCompletedEventArgs
                        return self._OnCompletedFn
                    
                    @OnCompleted.setter
                    def OnCompleted(self, fn):
                        logger.info("")
                        # type:(FWiFiDirectAdvertisementPublisher_WiFiDirectAdvertisementPublisherCompletedEventArgs) -> None
                        if (self._OnCompletedHandler is not None):
                            self._OnCompletedHandler = None
                            self._OnCompletedHandlerClass = None
                            # XXX Does setting a null handler remove it?
                            # XXX Does this need to point to the right interface?
                            handler = wintypes.POINTER(IAsyncOperationCompletedHandler_1_WiFiDirectDevice)()
                    
                        if (fn is not None):
                            self._OnCompletedHandlerClass = make_typed_event_handler_class(
                                IAsyncOperationCompletedHandler_1_WiFiDirectDevice,
                                wintypes.POINTER(IAsyncOperation_1_WiFiDirectDevice),
                                AsyncStatus,
                                fn
                            )
                            self._OnCompletedHandler = self._OnCompletedHandlerClass()
                    
                            handler = self._OnCompletedHandler.QueryInterface(self._OnCompletedHandlerClass._event_handler_interface_)
                    
                        self._IAsyncOperation_1_WiFiDirectDevice__com__set_Completed(handler)
                        self._OnCompletedFn = fn
                    """.replace("IAsyncOperationCompletedHandler_1_WiFiDirectDevice", typed_event_handler_name)
                    .replace("wintypes.POINTER(WiFiDirectDevice)", "wintypes.POINTER(%s)" % first_arg_type)
                    .replace("AsyncStatus", "%s" % second_arg_type)
                    .replace("IAsyncOperation_1_WiFiDirectDevice", interface["name"])
                    .replace("Completed", method["name"])
                )

            else:
                # Convert to type name, but remove the pointer
                # XXX This assumes it's a typedeventhandler
                typed_event_handler_name = convert_type_name(method["params"][0]["type"], type_mappings).split("(")[1].split(")")[0]
                _, _, first_arg_type, second_arg_type = typed_event_handler_name.split("_")


                g.append("""
                    def __init__(self):
                        self._OnStatusChangedFn = None
                        self._OnStatusChangedToken = None
                        self._OnStatusChangedHandler = None
                        self._OnStatusChangedHandlerClass = None
                        
                    @property
                    def OnStatusChanged(self):
                        logger.info("")
                        # type:()->FWiFiDirectAdvertisementPublisher_WiFiDirectAdvertisementPublisherStatusChangedEventArgs
                        return self._OnStatusChangedFn

                    @OnStatusChanged.setter
                    def OnStatusChanged(self, fn):
                        logger.info("")
                        # type:(FWiFiDirectAdvertisementPublisher_WiFiDirectAdvertisementPublisherStatusChangedEventArgs) -> None
                        if (self._OnStatusChangedToken is not None):
                            self._IWiFiDirectAdvertisementPublisher__com_remove_StatusChanged(self._OnStatusChangedToken)
                            self._OnStatusChangedToken = None
                            self._OnStatusChangedHandler = None
                            self._OnStatusChangedHandlerClass = None
                        
                        if (fn is not None):
                            self._OnStatusChangedHandlerClass = make_typed_event_handler_class(
                                TypedEventHandler_2_WiFiDirectAdvertisementPublisher_WiFiDirectAdvertisementPublisherStatusChangedEventArgs,
                                wintypes.POINTER(IWiFiDirectAdvertisementPublisher), 
                                wintypes.POINTER(IWiFiDirectAdvertisementPublisherStatusChangedEventArgs),
                                fn
                            )
                            self._OnStatusChangedHandler = self._OnStatusChangedHandlerClass()

                            self._OnStatusChangedToken = EventRegistrationToken()
                            handler = self._OnStatusChangedHandler.QueryInterface(self._OnStatusChangedHandlerClass._event_handler_interface_)
                            self._IWiFiDirectAdvertisementPublisher__com_add_StatusChanged(
                                handler, 
                                ctypes.byref(self._OnStatusChangedToken)
                            )
                        self._OnStatusChangedFn = fn
                    """.replace("TypedEventHandler_2_WiFiDirectAdvertisementPublisher_WiFiDirectAdvertisementPublisherStatusChangedEventArgs", typed_event_handler_name)
                    .replace("wintypes.POINTER(IWiFiDirectAdvertisementPublisher)", "wintypes.POINTER(%s)" % first_arg_type)
                    .replace("wintypes.POINTER(IWiFiDirectAdvertisementPublisherStatusChangedEventArgs)", "wintypes.POINTER(%s)" % second_arg_type)
                    .replace("IWiFiDirectAdvertisementPublisher", interface["name"])
                    .replace("StatusChanged", method["name"])
                    
                )

        # Write the methods once the class has been defined so parameters can refer
        # to the class if necessary
        g.pop_indent()

    # XXX Note comtypes needs a _methods_ class variable even if it's empty or
    #     things fail if emtpy _methods_ are removed, investigate?
    if (generate_methods):
        g.append("%s._methods_ = [" % interface["name"])
        g.push_indent()

        for method in interface.get("methods", []):
            is_async_operation_handler = (
                (method["flag"] == "propput") and 
                (len(method["params"]) > 0) and 
                method["params"][0]["type"].startswith("IAsyncOperationCompletedHandler")
            )
            
            method_name = method["name"] 
            if (method["flag"] == "eventadd"):
                method_name = "add_" + method_name
            elif (method["flag"] == "eventremove"):
                method_name = "remove_" + method_name
            g.append("# [%s] %s %s(%s)", 
                method["flag"],
                method["return"], 
                method["name"], 
                string.join(["%s %s %s" % (
                    string.join(["[%s]" % flag for flag in param["flags"]], " "),
                    param["type"], 
                    param["name"]) for param in method["params"]], ",")
            )
            g.append("comtypes.COMMETHOD(")
            g.push_indent()

            # g.append("[comtypes.helpstring('Method %s')],", method["name"])
            flag = "[]"
            if (method["flag"] is not None):
                flag = "['%s']" % method["flag"]
            g.append("%s, %s, '%s',", flag, convert_type_name(method["return"], type_mappings), method_name)

            for param in method["params"]:
                # (['out'], wintypes.POINTER(TrustLevel), 'trustLevel'),
                flags = []
                for flag in param["flags"]:
                    flags.append("'%s'" % flag)

                type_name = convert_type_name(param["type"], type_mappings)
                g.append("([%s], %s, '%s'),", string.join(flags, ","), type_name, param["name"])

            g.pop_indent()
            g.append("),")

        g.pop_indent()
        g.append("]")

    g.append("")


def generate_python(g, objs, type_mappings):
    for obj in objs.itervalues():
        if (obj["type"] == "enum"):
            g.reset_indent()
            generate_python_enum(g, obj)
    
    # Declare interfaces first, then runtimeclasses then methods as a 
    # way of "forward" the interface declaration so they can be used in the
    # runtime classes and the runtime classes and the interfaces in the
    # methods

    for obj in objs.itervalues():
        if (obj["type"] == "interface"):
            g.reset_indent()
            generate_python_interface(g, obj, type_mappings, True, False)

    for obj in objs.itervalues():
        if (obj["type"] == "runtimeclass"):
            g.reset_indent()
            generate_python_runtime_class(g, obj, type_mappings)

    for obj in objs.itervalues():
        if (obj["type"] == "interface"):
            g.reset_indent()
            generate_python_interface(g, obj, type_mappings, False, True)
    

def write_python_from_idls():
    type_mappings = {
        "BYTE": "wintypes.BYTE",
        "UINT16" : "wintypes.USHORT",
        "INT16" : "wintypes.SHORT",
        "UINT32" : "wintypes.ULONG",
        "INT32" : "wintypes.LONG",
        "UINT64" : "wintypes.ULARGE_INTEGER",
        "INT64" : "wintypes.LARGE_INTEGER",
        "HRESULT" : "wintypes.HRESULT",
        "boolean" : "wintypes.BOOL",
        "IID" : "comtypes.IID",
        "ULONG" : "wintypes.ULONG",
        "IUnknown" : "comtypes.IUnknown",
    }

    for filenames in [
        #"simple.idl",
        ["wrtbase.idl"],
        #"windows.foundation.collections.idl",
        # XXX Necessary for PasswordCredential Gives error, investigate
        #"windows.security.credentials.idl",
        ["windows.devices.wifidirect.idl", "wifidirect.hacks.idl"],
        #"windows.devices.enumeration.idl",
        #"windows.foundation.idl",
        # XXX This needs empty line and comment support between methods
        # "asyncinfo.idl",
        ] :
        all_entries = {}
        for filename in filenames:
            filepath = filename
            print "parsing %r" % filepath
            entries = parse_idl_file(filepath)
            with open(os.path.join("_out", "idls", os.path.splitext(filename)[0] + ".json"), "w") as f:
                json.dump(entries, f, indent=2, sort_keys=True)
                json.dump(type_mappings, f, indent=2, sort_keys=True)

            all_entries.update(entries)

        entries = all_entries
        filename = filenames[0]
        filepath = os.path.join("_out", os.path.splitext(filename)[0] + ".py")
        #filepath = os.path.splitext(filename)[0] + ".py"
        with open(filepath, "w") as f:
            g = CodeGen(f)
            g.append("# Autogenerated from %s on %s", string.join(filenames, ", "), datetime.datetime.now())
            
            if (filename == "wrtbase.idl"):
                # Don't import wrtcommon since the only thing wrtbase needs is
                # HSTRING and ENUM. This removes a circular dependency between
                # wrtcommon and wrtbase that is not a problem if the imports are
                # placed carefully, but it's not clean
                g.append("""
                from ctypes import wintypes
                import comtypes

                HSTRING = wintypes.HANDLE
                ENUM = wintypes.UINT
                """)
                # Make sure IInspectable and its dependency are generated first
                generate_python(g, {"TrustLevel" : entries["TrustLevel"], "IInspectable" : entries["IInspectable"]}, type_mappings)
                del entries["IInspectable"]
                del entries["TrustLevel"]

            else:
                g.append("from wrtcommon import *")
                g.append("")

            generate_python(g, entries, type_mappings)

def clr_test():
    # XXX This test gives errors, the winrt dlls are not managed dlls so trying
    #     to load them with pythonnet doesn't work, complains about badimage

    sys.path.append(r'C:\Windows\System32')

    #import clr
    #clr.AddReference("Windows.Devices.WiFiDirect")
    #clr.AddReference(r"C:\Windows\System32\Windows.Devices.WiFiDirect.dll")

    from clr import System
    from System import Reflection
    full_filename = R"C:\Windows\System32\Windows.Devices.WiFiDirect.dll"
    full_filename = R"C:\Windows\Microsoft.NET\Framework\v4.0.30319\System.Windows.Forms.dll"
    full_filename = R"C:\Windows\System32\WinMetadata\Windows.Devices.winmd"
    Reflection.Assembly.LoadFile(full_filename) 

    import clr
    clr.AddReference("Windows.Devices.Bluetooth")

def wlanapi_test():
    WlanApi = ctypes.windll.wlanapi

    hClientHandle = wintypes.HANDLE()
    phClientHandle = ctypes.pointer(hClientHandle)
    dwNegotiatedVersion = wintypes.DWORD()
    pdwNegotiatedVersion = ctypes.pointer(dwNegotiatedVersion)
    dwClientVersion = wintypes.DWORD()
    dwClientVersion.value = 2

    rc = WlanApi.WlanOpenHandle(dwClientVersion, None, pdwNegotiatedVersion, phClientHandle)
    print rc

    # https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/ns-wlanapi-wlan_interface_info
    class WLAN_INTERFACE_INFO(ctypes.Structure):
        _fields_ = [
            ('InterfaceGuid', GUID),
            ('strInterfaceDescription', wintypes.WCHAR * 256),
            # https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/ne-wlanapi-wlan_interface_state-r1
            # 0 not ready, 1 connected, 2 ad hoc formed, 3 disconnecting, 
            # 4 disconnected, 5 associating, 6 discovering, 7 authenticating
            ('isState', wintypes.DWORD)
        ]

    class WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
        _fields_ = [
            ('dwNumberOfItems', wintypes.DWORD),
            ('dwIndex', wintypes.DWORD),
            # XXX ctypes doesn't have a way of describing unbounded arrays
            #     not clear the loop below will work if dwNumberOfItems is
            #     greater than 1
            #     https://stackoverflow.com/questions/7015487/ctypes-variable-length-structures
            ('InterfaceInfo', WLAN_INTERFACE_INFO * 1)
        ]

    PWLAN_INTERFACE_INFO_LIST = ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)
    pIfList = PWLAN_INTERFACE_INFO_LIST()
    rc = WlanApi.WlanEnumInterfaces(hClientHandle, None, ctypes.pointer(pIfList))

    print rc
    IfList = pIfList[0]
    print "Num Entries: %d" % IfList.dwNumberOfItems
    for i in xrange(IfList.dwNumberOfItems):
        InterfaceInfo = IfList.InterfaceInfo[i]
        print "guid", InterfaceInfo.InterfaceGuid, "desc", InterfaceInfo.strInterfaceDescription, "state", InterfaceInfo.isState


    C_ENUM = ctypes.c_uint32
    DOT11_MAC_ADDRESS = ctypes.c_byte * 6
    # https://learn.microsoft.com/en-us/windows/win32/nativewifi/dot11-phy-type
    DOT11_PHY_TYPE = C_ENUM

    # https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/ns-wlanapi-wlan_hosted_network_peer_state
    class WLAN_HOSTED_NETWORK_PEER_STATE(ctypes.Structure):
        _fields_ = [
            ('PeerMacAddress', DOT11_MAC_ADDRESS),
            # https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/ne-wlanapi-wlan_hosted_network_peer_auth_state
            ('PeerAuthState', C_ENUM),
        ]

    # https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/ns-wlanapi-wlan_hosted_network_status
    class WLAN_HOSTED_NETWORK_STATUS(ctypes.Structure):
        _fields_ = [
            ('HostedNetworkState', WLAN_HOSTED_NETWORK_PEER_STATE),
            ('IPDeviceID', GUID),
            ('wlanHostedNetworkBSSID', DOT11_MAC_ADDRESS),
            ('dot11PhyType', DOT11_PHY_TYPE),
            ('ulChannelFrequency', ctypes.c_ulong),
            ('dwNumberOfPeers', ctypes.c_uint32),
            ('PeerList', WLAN_HOSTED_NETWORK_PEER_STATE * 1),
        ]

    PWLAN_HOSTED_NETWORK_STATUS = ctypes.POINTER(WLAN_HOSTED_NETWORK_STATUS)

    status = PWLAN_HOSTED_NETWORK_STATUS()
    # https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlanhostednetworkquerystatus
    rc = WlanApi.WlanHostedNetworkQueryStatus(hClientHandle, ctypes.pointer(status), None)

    print status[0].HostedNetworkState.PeerMacAddress[0]

    print rc

    # http://www.rohitab.com/discuss/topic/43819-help-on-hosted-network-with-native-wifi/

    # https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/ne-wlanapi-wlan_hosted_network_reason
    # 12 = wlan_hosted_network_reason_interface_unavailable
    WLAN_HOSTED_NETWORK_REASON = C_ENUM
    # https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlanhostednetworkstartusing
    reason = ctypes.c_uint32()
    rc = WlanApi.WlanHostedNetworkStartUsing(hClientHandle, ctypes.pointer(reason), None)
    print hex(rc), reason

    # https://github.com/dfct/Inssidious/blob/master/InssidiousCore/Controllers/HostedNetworkController.cpp

def com_test():
    class GUID(ctypes.Structure):
        # XXX wintypes.DWORD, wintypes.BYTE and wintypes.DWORD show as negative in
        #     %x, not clear why, use ctypes.c_uXXX instead, investigate
        _fields_ = [("Data1", ctypes.c_uint32),
                    ("Data2", ctypes.c_uint16),
                    ("Data3", ctypes.c_uint16),
                    ("Data4", ctypes.c_uint8 * 8)]

        def __str__(self):
            # See https://learn.microsoft.com/en-us/windows/win32/api/guiddef/ns-guiddef-guid
            return "%08X-%04X-%04X-%s-%s" % (
                self.Data1,
                self.Data2,
                self.Data3,
                # https://devblogs.microsoft.com/oldnewthing/20220928-00/?p=107221
                string.join(["%02X" % b for b in self.Data4[:2]], ""),
                string.join(["%02X" % b for b in self.Data4[2:]], ""),
                )

    def str_to_guid(s):
        s = s.trim()
        if (s.startswith("{")):
            s = s[1:-1].trim()
        assert len(s) == 8 + 4 + 4 + 8*2 + 4, "Unexpected len %d" % len(s)
        l = s.split("-")
        assert len(l) == 5, "Unexpected number of dashes %d" % len(s)
        l[3] = l[3] + l.pop()
        
        data = (
            int(l[0], 16), 
            int(l[1], 16),
            int(l[2], 16),
            tuple(int(l[3][i*2:i*2+2], 16) for i in xrange(len(l[3])/2))
        )

        guid = GUID(*data)
        print "in", s, "out", str(guid)

        return guid

    # See https://stackoverflow.com/questions/48986244/access-com-methods-from-python
    ole32=ctypes.WinDLL('Ole32.dll')
    
    hr = ole32.CoInitialize(None)
    print "CoInitialize", hr

    IID_IWiFiDirectAdvertisementPublisher = "B35A2D1A-9B1F-45D9-925A-694D66DF68EF"
    clsid = str_to_guid(IID_IWiFiDirectAdvertisementPublisher)
    drv = ctypes.c_void_p(None)
    hr = ole32.CoCreateInstance(ctypes.byref(clsid), 0, 1, ctypes.byref(clsid), ctypes.byref(drv))

def winrt_test():
    """
    Python port of 
    https://learn.microsoft.com/en-us/cpp/cppcx/wrl/how-to-activate-and-use-a-windows-runtime-component-using-wrl?view=msvc-170
    """
    # XXX Setting the threaded mode fails inside vscode debugger, looks like COM
    #     is already initialized as single threaded in the debugger thread?
    import os
    if (os.environ.get('VSCODE_PID', None) is not None):
        print("Running in VS Code")

    else:
        # Set multithreaded flag before comtypes is loaded in this thread,
        # otherwise will set single threaded and can't be changed after the fact
        sys.coinit_flags = 0
    
    import comtypes

    # Note this is redundant since it's done by comtypes when imported in this
    # thread
    #hr = comtypes.CoInitializeEx(0)
    #print "CoInitializeEx", hr

    combase=ctypes.WinDLL('combase.dll')
    # See https://stackoverflow.com/questions/16466641/how-to-declare-and-link-to-roinitialize-rouninitialize-rogetactivationfactory-an
    # https://learn.microsoft.com/en-us/windows/win32/api/roapi/nf-roapi-roinitialize
    RO_INIT_SINGLETHREADED = 0
    RO_INIT_MULTITHREADED = 1
    hr = combase.RoInitialize(RO_INIT_MULTITHREADED)
    #hr = combase.RoInitialize(RO_INIT_SINGLETHREADED)
    print "RoInitialize", hex(hr)

    # https://learn.microsoft.com/en-us/windows/win32/api/roapi/nf-roapi-roactivateinstance
    # https://learn.microsoft.com/en-us/cpp/cppcx/wrl/how-to-activate-and-use-a-windows-runtime-component-using-wrl?view=msvc-170
    # https://raw.githubusercontent.com/tpn/winsdk-10/master/Include/10.0.16299.0/winrt/windows.foundation.h
    RuntimeClass_Windows_Foundation_Uri = u"Windows.Foundation.Uri"
    # https://learn.microsoft.com/en-us/windows/win32/api/winstring/nf-winstring-windowscreatestring
    hstr = wintypes.HANDLE(None)
    hr = combase.WindowsCreateString(RuntimeClass_Windows_Foundation_Uri, len(RuntimeClass_Windows_Foundation_Uri), ctypes.byref(hstr))
    print "WindowsCreateString", hex(hr), hex(hstr.value)

    # See https://github.com/shanewholloway/comtypes/blob/master/docs/com_interfaces.txt
    # See https://github.com/enthought/comtypes/blob/main/comtypes/client/dynamic.py

    """
    https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/winrt/inspectable.idl
    [
    object,
    uuid(AF86E2E0-B12D-4c6a-9C5A-D7AA65101E90),
    pointer_default(unique)
    ]
    interface IInspectable : IUnknown
    {
        HRESULT GetIids(
            [out] ULONG * iidCount,
            [out, size_is(,*iidCount)] IID ** iids);

        HRESULT GetRuntimeClassName( [out] HSTRING * className);

        HRESULT GetTrustLevel([out] TrustLevel * trustLevel);
    }
    """
    # See https://stackoverflow.com/questions/57149456/how-to-implement-windows-10-ivirtualdesktopmanager-interface-in-python
    IID_IInspectable = comtypes.GUID('{AF86E2E0-B12D-4C6A-9C5A-D7AA65101E90}')
    ENUM = wintypes.UINT
    class TrustLevel(ENUM):
        BaseTrust = 0
        PartialTrust = BaseTrust + 1
        FullTrust = PartialTrust + 1
    HSTRING = wintypes.HANDLE
    class IInspectable(comtypes.IUnknown):
        _case_insensitive_ = True
        _idlflags_ = []
        _iid_ = IID_IInspectable
        _methods_ = [
            comtypes.COMMETHOD(
                [comtypes.helpstring('Method GetIids')],
                comtypes.HRESULT,
                'GetIids',
                (['out'], wintypes.POINTER(wintypes.ULONG), 'iidCount'),
                (['out'], wintypes.POINTER(wintypes.POINTER(comtypes.IID)), 'iids'),
            ),
            comtypes.COMMETHOD(
                [comtypes.helpstring('Method GetRuntimeClassName')],
                comtypes.HRESULT,
                'GetRuntimeClassName',
                (['out'], wintypes.POINTER(HSTRING), 'className'),
            ),
            comtypes.COMMETHOD(
                [comtypes.helpstring('Method GetTrustLevel')],
                comtypes.HRESULT,
                'GetTrustLevel',
                (['out'], wintypes.POINTER(TrustLevel), 'trustLevel'),
            ),
        ]


    """
    https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/winrt/windows.foundation.idl
    [contract(Windows.Foundation.UniversalApiContract, 1.0)]
        [exclusiveto(Windows.Foundation.Uri)]
        [uuid(9E365E57-48B2-4160-956F-C7385120BBFC)]
        interface IUriRuntimeClass : IInspectable
        {
            [propget] HRESULT AbsoluteUri([out] [retval] HSTRING* value);
            [propget] HRESULT DisplayUri([out] [retval] HSTRING* value);
            [propget] HRESULT Domain([out] [retval] HSTRING* value);
            [propget] HRESULT Extension([out] [retval] HSTRING* value);
            [propget] HRESULT Fragment([out] [retval] HSTRING* value);
            [propget] HRESULT Host([out] [retval] HSTRING* value);
            [propget] HRESULT Password([out] [retval] HSTRING* value);
            [propget] HRESULT Path([out] [retval] HSTRING* value);
            [propget] HRESULT Query([out] [retval] HSTRING* value);
            [propget] HRESULT QueryParsed([out] [retval] Windows.Foundation.WwwFormUrlDecoder** ppWwwFormUrlDecoder);
            [propget] HRESULT RawUri([out] [retval] HSTRING* value);
            [propget] HRESULT SchemeName([out] [retval] HSTRING* value);
            [propget] HRESULT UserName([out] [retval] HSTRING* value);
            [propget] HRESULT Port([out] [retval] INT32* value);
            [propget] HRESULT Suspicious([out] [retval] boolean* value);
            HRESULT Equals([in] Windows.Foundation.Uri* pUri, [out] [retval] boolean* value);
            HRESULT CombineUri([in] HSTRING relativeUri, [out] [retval] Windows.Foundation.Uri** instance);
        }
    """
    # See https://stackoverflow.com/questions/57149456/how-to-implement-windows-10-ivirtualdesktopmanager-interface-in-python
    IID_IUriRuntimeClass = comtypes.GUID("{9E365E57-48B2-4160-956F-C7385120BBFC}")
    class IUriRuntimeClass(IInspectable):
        _iid_ = IID_IUriRuntimeClass
        _case_insensitive_ = True
        _idlflags_ = []
        _methods_ = [
            comtypes.COMMETHOD(
                ['propget'], wintypes.HRESULT, "AbsoluteUri",
                ( ['out', 'retval'], wintypes.POINTER(HSTRING), "value" ) ),

            comtypes.COMMETHOD(
                ['propget'], wintypes.HRESULT, "DisplayUri",
                ( ['out', 'retval'], wintypes.POINTER(HSTRING), "value" ) ),

            comtypes.COMMETHOD(
                ['propget'], wintypes.HRESULT, "Domain",
                ( ['out', 'retval'], wintypes.POINTER(HSTRING), "value" ) ),
        ]

    """
    https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/winrt/windows.foundation.idl
    [contract(Windows.Foundation.UniversalApiContract, 1.0)]
        [exclusiveto(Windows.Foundation.Uri)]
        [uuid(44A9796F-723E-4FDF-A218-033E75B0C084)]
        interface IUriRuntimeClassFactory : IInspectable
        {
            HRESULT CreateUri([in] HSTRING uri, [out] [retval] Windows.Foundation.Uri** instance);
            HRESULT CreateWithRelativeUri([in] HSTRING baseUri, [in] HSTRING relativeUri, [out] [retval] Windows.Foundation.Uri** instance);
        }
    """
    IID_IUriRuntimeClassFactory = comtypes.GUID("{44A9796F-723E-4FDF-A218-033E75B0C084}")
    class IUriRuntimeClassFactory(IInspectable):
        _iid_ = IID_IUriRuntimeClassFactory
        _case_insensitive_ = True
        _idlflags_ = []
        _methods_ = [
            comtypes.COMMETHOD(
                [], wintypes.HRESULT, "CreateUri",
                ( ['in'], wintypes.HANDLE, "uri"),
                ( ['out', 'retval'], wintypes.POINTER(wintypes.POINTER(IUriRuntimeClass)), "instance" ) ),

            comtypes.COMMETHOD(
                [], wintypes.HRESULT, "CreateWithRelativeUri",
                ( ['in'], wintypes.HANDLE, "baseUri"),
                ( ['in'], wintypes.HANDLE, "relativeUri"),
                ( ['out', 'retval'], wintypes.POINTER(wintypes.POINTER(IUriRuntimeClass)), "instance" ) )

            ]

    #print comtypes.GUID.from_progid("Windows.Foundation.Uri")
    factory = wintypes.POINTER(IUriRuntimeClassFactory)()
    hr = combase.RoGetActivationFactory(hstr, ctypes.byref(IID_IUriRuntimeClassFactory), ctypes.byref(factory))
    print "RoGetActivationFactory", hex(hr)
    
    #factory = comtypes.cast(factory, wintypes.POINTER(IUriRuntimeClassFactory))

    hr = combase.WindowsDeleteString(hstr)
    print "WindowsDeleteString", hex(hr)

    #hstr = wintypes.HANDLE(None)
    #hr = factory.GetRuntimeClassName(ctypes.byref(hstr))
    #hr = factory.GetRuntimeClassName(ctypes.byref(hstr))
    #print "GetRuntimeClassName", hex(hr)

    hstr = wintypes.HANDLE(None)
    url = u"http://www.microsoft.com"
    hr = combase.WindowsCreateString(url, len(url), ctypes.byref(hstr))
    print "WindowsCreateString", hex(hr), hex(hstr.value)
    
    uri = ctypes.POINTER(IUriRuntimeClass)()
    #iface = wintypes.POINTER(IUriRuntimeClassFactory)()
    #iface = factory.QueryInterface(IUriRuntimeClassFactory)
    #print "QueryInterface", hex(hr)
    
    # XXX For some reason, can't call the friendly name 
    #           hr = factory.CreateUri(hstr, ctypes.byref(uri)) 
    #     because it's implemented as an instance method and passes self as 
    #     argument, which causes the error 
    #           call takes exactly 2 arguments (3 given)
    #     call the internal methods that don't pass self as argument instead
    
    hr = factory._IUriRuntimeClassFactory__com_CreateUri(hstr, ctypes.byref(uri))
    print "CreateUri", hex(hr)

    hr = combase.WindowsDeleteString(hstr)
    print "WindowsDeleteString", hex(hr)

    hr = uri._IUriRuntimeClass__com__get_Domain(ctypes.byref(hstr))
    print "Domain", hex(hr)

    length = wintypes.UINT()
    p = combase.WindowsGetStringRawBuffer(hstr, ctypes.byref(length))
    print "WindowsGetStringRawBuffer", length, repr(ctypes.c_wchar_p(p))

    # Calling the property on the instance also works
    hstr = uri.Domain
    length = wintypes.UINT()
    p = combase.WindowsGetStringRawBuffer(hstr, ctypes.byref(length))
    print "WindowsGetStringRawBuffer", length, repr(ctypes.c_wchar_p(p))

    hr = combase.WindowsDeleteString(hstr)
    print "WindowsDeleteString", hex(hr)

def winrt_wifi():
    # XXX Setting the threaded mode fails inside vscode debugger, looks like COM
    #     is already initialized as single threaded in the debugger thread?
    # XXX There used to be a VSCODE_PID but looks like sometimes this is not set, 
    #     check any VSCODE_ env vars
    vscode_envs = [k for k in os.environ if "VSCODE_" in k]
    logger.info("vscode_envs %r", sorted(vscode_envs))
    running_under_vscode = (len(vscode_envs) > 1)
    if (running_under_vscode):
        logger.info("Running in VS Code")

    else:
        # Set multithreaded flag before comtypes is loaded in this thread,
        # otherwise will set single threaded and can't be changed after the fact
        sys.coinit_flags = 0
    import comtypes

    from wifidirect import HString, WiFiDirectAdvertisementPublisherStatus, \
        WiFiDirectConnectionStatus, WiFiDirectConnectionRequest, AsyncStatus, \
        IWiFiDirectDeviceStatics_s, WiFiDirectConnectionListener, \
        WiFiDirectAdvertisementPublisher

    # Note this is redundant since it's done by comtypes when imported in this
    # thread
    #hr = comtypes.CoInitializeEx(0)
    #print "CoInitializeEx", hr

    combase=ctypes.WinDLL('combase.dll')
    # See https://stackoverflow.com/questions/16466641/how-to-declare-and-link-to-roinitialize-rouninitialize-rogetactivationfactory-an
    # https://learn.microsoft.com/en-us/windows/win32/api/roapi/nf-roapi-roinitialize
    RO_INIT_SINGLETHREADED = 0
    RO_INIT_MULTITHREADED = 1
    hr = combase.RoInitialize(RO_INIT_MULTITHREADED)
    #hr = combase.RoInitialize(RO_INIT_SINGLETHREADED)
    logger.info("RoInitialize %r", hex(hr))

    connected_devices = {}
    # Python 2.7 doesn't have nonlocal to allow nested functions overwriting
    # outer scope variables, use a member variable inside a class instead of a
    # straight object
    # See https://stackoverflow.com/questions/8447947/is-it-possible-to-modify-a-variable-in-python-that-is-in-an-outer-enclosing-b
    class nonlocal: pass
    nonlocal.connection_listener = None

    def on_publisher_status_changed(sender, args):
        #type:(IWiFiDirectAdvertisementPublisher, IWiFiDirectAdvertisementPublisherStatusChangedEventArgs) -> comtypes.HRESULT
        logger.info("sender %r args %s", sender, args)
        # XXX Fix the wrapper so it returns the ENUM value directly
        if (args.Status.value == WiFiDirectAdvertisementPublisherStatus.Created):
            logger.info("Created")
        
        elif (args.Status.value == WiFiDirectAdvertisementPublisherStatus.Started):
            logger.info("Started")
            nonlocal.connection_listener = start_listener()

        elif (args.Status.value == WiFiDirectAdvertisementPublisherStatus.Stopped):
            logger.info("Stopped")

        else:
            logger.info("Unhandled status %d", args.Status.value)

        return comtypes.hresult.S_OK

    def on_connection_status_changed(sender, args):
        logger.info("sender %r args %r", sender, args)

        # hr = sender->get_ConnectionStatus(&status);
        status = sender.ConnectionStatus

        if (status.value == WiFiDirectConnectionStatus.Connected):
            logger.info("Connected")
            print "Connected", HString(sender.DeviceId)
        
        elif (status.value == WiFiDirectConnectionStatus.Disconnected):
            logger.info("Disconnected")
            print "Disconnected", HString(sender.DeviceId)

            # hr = sender->get_DeviceId(deviceId.GetAddressOf());
            deviceId = str(HString(sender.DeviceId))
            logger.info("DeviceId %s", deviceId)

            # auto itDevice = _connectedDevices.find(deviceId.GetRawBuffer(nullptr));
            # auto itToken = _connectedDeviceStatusChangedTokens.find(deviceId.GetRawBuffer(nullptr));
            # if (itToken != _connectedDeviceStatusChangedTokens.end())
            # {
            #    if (itDevice != _connectedDevices.end())
            #    {
            #        itDevice->second->remove_ConnectionStatusChanged(itToken->second);
            #    }
            #    _connectedDeviceStatusChangedTokens.erase(itToken);
            # }
            # if (itDevice != _connectedDevices.end())
            # {
            #    _connectedDevices.erase(itDevice);
            # }
            wfdDevice = connected_devices.pop(deviceId)
            wfdDevice.OnConnectionStatusChanged = None

        return comtypes.hresult.S_OK

    def on_connection_completed(sender, args):
        logger.info("sender %r args %s", sender, args)

        logger.info("status %s", args.value)

        if (args.value == AsyncStatus.Completed):
            logger.info("Completed")
            
            # hr = pHandler->GetResults(wfdDevice.GetAddressOf());
            wfdDevice = sender.GetResults()
            deviceId = str(HString(wfdDevice.DeviceId))
            logger.info("Device Id %s", deviceId)
            print "Connection completed", HString(wfdDevice.DeviceId)

            # XXX Missing Implementing
            # hr = wfdDevice->GetConnectionEndpointPairs(endpointPairs.GetAddressOf());
            # hr = endpointPairs->GetAt(0, endpointPair.GetAddressOf());
            # hr = endpointPair->get_RemoteHostName(remoteHostName.GetAddressOf());
            # hr = remoteHostName->get_DisplayName(remoteHostNameDisplay.GetAddressOf());

            # EventRegistrationToken statusChangedToken;
            # hr = wfdDevice->add_ConnectionStatusChanged(Callback<ConnectionStatusChangedHandler>([this](IWiFiDirectDevice* sender, IInspectable*) -> HRESULT
            wfdDevice.OnConnectionStatusChanged = on_connection_status_changed

            # hr = wfdDevice->get_DeviceId(deviceId.GetAddressOf());
            # _connectedDevices.insert(std::make_pair(deviceId.GetRawBuffer(nullptr), wfdDevice));
            # _connectedDeviceStatusChangedTokens.insert(std::make_pair(deviceId.GetRawBuffer(nullptr), statusChangedToken));
            connected_devices[deviceId] = wfdDevice

        elif (args.value == AsyncStatus.Started):
            logger.info("Started")
            
        elif (args.value == AsyncStatus.Canceled):
            logger.info("Canceled")

        elif (args.value == AsyncStatus.Error):
            logger.info("Error")

        return comtypes.hresult.S_OK

    def on_connection_requested(sender, args):
        #type:(IWiFiDirectAdvertisementPublisher, IWiFiDirectAdvertisementPublisherStatusChangedEventArgs) -> comtypes.HRESULT
        logger.info("sender %r args %s", sender, args)

        # hr = args->GetConnectionRequest(request.GetAddressOf());
        # hr = request->get_DeviceInformation(deviceInformation.GetAddressOf());
        connection_request = wintypes.POINTER(WiFiDirectConnectionRequest)()
        # XXX Fix comtypes passing self which forces to use the classmethod
        args._IWiFiDirectConnectionRequestedEventArgs__com_GetConnectionRequest(ctypes.byref(connection_request))
        device_information = connection_request.DeviceInformation

        logger.info("device id %s", HString(device_information.Id))
        
        # hr = GetActivationFactory(HStringReference(RuntimeClass_Windows_Devices_WiFiDirect_WiFiDirectDevice).Get(), &wfdStatics);
        wfd_statics = IWiFiDirectDeviceStatics_s()
        # hr = deviceInformation->get_Id(deviceId.GetAddressOf());
        # hr = wfdStatics->FromIdAsync(deviceId.Get(), &asyncAction);
        async_action = wfd_statics.FromIdAsync(device_information.Id)
        # hr = asyncAction->put_Completed(Callback<FromIdAsyncHandler>([this](IAsyncOperation<WiFiDirectDevice*>* pHandler, AsyncStatus status) -> HRESULT
        async_action.OnCompleted = on_connection_completed

        return comtypes.hresult.S_OK

    def start_listener():
        logger.info("")
        # hr = Windows::Foundation::ActivateInstance(HStringReference(RuntimeClass_Windows_Devices_WiFiDirect_WiFiDirectConnectionListener).Get(), &_connectionListener);
        listener = WiFiDirectConnectionListener()
        # hr = _connectionListener->add_ConnectionRequested(
        #   Callback<ConnectionRequestedHandler>([this](IWiFiDirectConnectionListener* sender, IWiFiDirectConnectionRequestedEventArgs* args) -> HRESULT
        listener.OnConnectionRequested = on_connection_requested

        # Local variable going out of scope will call __del__ and cause Release(),
        # AddRef to counter that
        # XXX Is there a way so comtypes doesn't Release local variables when they
        #     are returned from the function? Does this also happen if local var is
        #     set to None? (can't do here since it's the return value, though)
        listener.AddRef()

        return listener

    # hr = Windows::Foundation::ActivateInstance(HStringReference(RuntimeClass_Windows_Devices_WiFiDirect_WiFiDirectAdvertisementPublisher).Get(), &_publisher);
    publisher = WiFiDirectAdvertisementPublisher()

    # hr = _publisher->add_StatusChanged(
    #   Callback<StatusChangedHandler>([this](IWiFiDirectAdvertisementPublisher* sender, IWiFiDirectAdvertisementPublisherStatusChangedEventArgs* args) -> HRESULT
    publisher.OnStatusChanged = on_publisher_status_changed
    # hr = _advertisement->put_IsAutonomousGroupOwnerEnabled(true);
    publisher.Advertisement.IsAutonomousGroupOwnerEnabled = True
    # hr = _publisher->get_Advertisement(_advertisement.GetAddressOf());
    # hr = _advertisement->get_LegacySettings(_legacySettings.GetAddressOf());
    # hr = _legacySettings->put_IsEnabled(true);
    legacy_settings = publisher.Advertisement.LegacySettings
    legacy_settings.IsEnabled = True

    ssid = None
    password = None
    config_filepath = os.path.join("_out", "ssid_password.txt")
    try:
        with open(config_filepath, "r") as f:
            ssid, password = [HString(line.strip()) for line in f.readlines()]
            
    except:
        logger.warn("Error reading %s, will use random ssid and password", config_filepath)

    # hr = _legacySettings->put_Ssid(hstrSSID.Get());
    if (ssid is None):
        ssid = HString(legacy_settings.Ssid)
        
    else:
        legacy_settings.Ssid = ssid

    # hr = _legacySettings->get_Passphrase(passwordCredential.GetAddressOf());
    # hr = passwordCredential->put_Password(hstrPassphrase.Get());
    if (password is None):
        password = HString(legacy_settings.Passphrase.Password)
        
    else:
        legacy_settings.Passphrase.Password = password
        
    logger.info("Starting publisher")
    # hr = _publisher->Start();
    # This causes a QueryInterface for ITypedEventHandler {DE73CBA7-370D-550C-B23A-53DD0B4E480D}
    # on AsyncOperationHandler
    # This asks for
    # - INoMarshall {ECC8691B-C1DB-4DC0-855E-65F6C551AF49}, should E_NOINTERFACE
    # - ??????      {00000039-0000-0000-C000-000000000046}, should E_NOINTERFACE
    # - IdentityUnmarshal {0000001B-0000-0000-C000-000000000046}, should E_NOINTERFACE
    # - IAgileObject {94EA2B94-E9CC-49E0-C0FF-EE64CA8F5B90}, should S_OK
    # And once publisher.Start() is called it asks for
    # - ITypedEventHandler {DE73CBA7-370D-550C-B23A-53DD0B4E480D}
    publisher.Start()
    logger.info("Started publisher")

    try:
        print "Sleeping forever, ssid '%s' password '%s' press ctrl+c to finish" % (ssid, password)
        while (True):
            time.sleep(50)

    finally:
        logger.info("Stopping publisher")
        publisher.Stop()
        # XXX There's no cleanup needed as long as objects are not extra
        #     AddRef'd and references are eventually del'ed since __del__ will
        #     uninstall the respective handlers. Should this set some event
        #     handlers to None explicitly for cleanliness? (right now __del__
        #     may be called eg after the logger has been torn down so any
        #     logging there fails with None accesses)
        if (nonlocal.connection_listener is not None):
            logger.info("Resetting OnConnectionRequested")
            nonlocal.connection_listener.OnConnectionRequested = None
        logger.info("Resetting OnStatusChanged")
        publisher.OnStatusChanged = None
            
        logger.info("Done")
    
    
if (__name__ == "__main__"):
    log_level = logging.WARNING
    #log_level = logging.DEBUG

    comtypes_logger.setLevel(log_level)
    wrtc_logger.setLevel(log_level)
    logger.setLevel(log_level)
    
    if ((len(sys.argv) > 1) and ("build" in sys.argv[1])):
        # Note there's no import wrtcommon or import wrtbase in the code
        # generation path, which avoids dependencies on files that haven't been
        # generated yet (wrtcommon.py depends on wrtbase.py which is generated
        # from wrtbase.idl in the code generation path)
        write_python_from_idls()

    else:
        winrt_wifi()

