#!/usr/bin/env python
"""

https://stackoverflow.com/questions/8043924/windows-wlanapi-and-python-ctypes
https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlanenuminterfaces
https://github.com/microsoft/windows-classic-samples/tree/main/Samples/WiFiDirectLegacyAP
https://github.com/gerfen/WiFiDirectLegacyAPCSharp
https://github.com/microsoft/Windows-classic-samples/issues/82
https://github.com/govert/WiFiDirectLegacyAPDemo
https://github.com/zig13/WifiDirectLegacySurplex/tree/main
https://learn.microsoft.com/en-us/samples/microsoft/windows-universal-samples/wifidirect/
https://learn.microsoft.com/en-us/windows-hardware/drivers/partnerapps/wi-fi-direct
https://download.microsoft.com/download/7/8/7/787469FC-99B4-4726-9932-945111BDC809/WiFiDirectLegacyAPDemo_v1.0.zip


https://stackoverflow.com/questions/40286987/discover-wifi-direct-services-windows-android
https://github.com/Microsoft/Windows-universal-samples/tree/main/Samples/WiFiDirectServices
https://github.com/Microsoft/Windows-universal-samples/tree/main/Samples/WiFiDirect


https://gist.github.com/lala7573/3f7a209195f4d1e45747



https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/winrt/windows.devices.wifidirect.h
https://github.com/pywinrt/python-winsdk/blob/main/pywinrt/winsdk/windows/devices/wifidirect/services/__init__.pyi
https://stackoverflow.com/questions/48986244/access-com-methods-from-python
https://stackoverflow.com/questions/57149456/how-to-implement-windows-10-ivirtualdesktopmanager-interface-in-python

"""
import datetime
import logging
import os
import sys

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

logger = logging.getLogger(__name__)
setup_logger(logger)
logger.setLevel(logging.DEBUG)
#logger.setLevel(logging.WARNING)
#logger.setLevel(logging.INFO)

import ctypes
from ctypes import wintypes

import string
import re

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

    Unsupported formats:

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
            m = re.match(r"\s*(?P<name>\w+)\s*=\s*(?P<value>\d+),?", l)
            if (m is not None):
                lines.append(l)
                enum_values[m.group("name")] = int(m.group("value"))

        elif (inside_braces and (runtime_class is not None)):
            # [default] interface Windows.Devices.WiFiDirect.IWiFiDirectConnectionParameters;
            m = re.match(r"\s*\[\s*default\s*\]\s*interface\s+([^;]*);", l)
            if (m is not None):
                lines.append(l)
                runtime_class["default"] = m.group(1)

        elif (inside_braces and (interface is not None)):
            # Regular regular expressions are not powerful enough to match
            # nested syntax like templated types, do a pre-parse of the line
            # removing spaces from inside angles so the regular expressions
            # patterns for analyzing argument types don't need to care about
            # nested angles and commas and can just look at whitespace

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
                    
            m = re.match(r"""
                (\[\s*(?P<method_flag>eventadd|eventremove|propget|propput|overload\s*\(\s*[^)]*\))\s*\])?\s*
                (?P<return_type>[a-zA-Z0-9_.*<>,]+)\s*
                (?P<method_name>\w+)\s*
                \(
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
                \)\s*;\s*
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
            m = re.match(r"\s*\[?\s*uuid\(\s*([^)]*)\s*\)\s*\]?\s*", l)
            if (m is not None):
                print "uuid", m.group(1)
                if (interface is None):
                    interface = {}
                    lines = []
                interface.update({ "uuid": m.group(1) })
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

            m = re.match(r"\s*\[\s*exclusiveto\(([^)]*)\)\s*\]\s*", l)
            if (m is not None):
                print "exclusiveto", m.group(1)
                if (interface is None):
                    interface = {}
                    lines = []
                interface.update({ "exclusiveto": m.group(1) })
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

            m = re.match(r"\s*interface\s+(?P<interface_name>(\w|[<,>])+)\s*:\s*(?P<parent_name>\w+)\s*", l)
            if (m is not None):
                print "interface name", m.group("interface_name"), "parent name", m.group("parent_name")
                interface.update({
                    "parent": m.group("parent_name"),
                    "name": m.group("interface_name"),
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
        # use the second line to check the base indent
        base_indent_index = 0
        if ((len(lines) > 1) and (lines[0].strip() == "")):
            base_indent_index = 1
        base_indent = len(lines[base_indent_index]) - len(lines[base_indent_index].lstrip())
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
    if (runtime_class.get("activatable", False)):
        type_name = convert_type_name(runtime_class["name"], type_mappings)
        interface_name = convert_type_name(runtime_class["default"], type_mappings)
        g.append("class %s(%s):", type_name, interface_name)

        g.push_indent()

        g.append(['"""'] + runtime_class["lines"] + ['"""'])
        g.append(
            """
            def __new__(cls):
                return activate_instance('%s', %s)
            """, 
            runtime_class["name"], interface_name)
            
        g.append("")

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
                name += "__C"
                # XXX Remove prefixes for the time being, in the future probably
                #     force caller to fill in mappings to remove them or have a
                #     prefix removal set?
                #name = ""

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
                name = name + type_mappings.get(m.group(1), m.group(1))

        type_mappings[type_name] = name

    return name


def generate_python_interface(g, interface, type_mappings, generate_short_methods = True):
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
    g.append("IID_%s = comtypes.GUID('{%s}')", interface["name"], interface["uuid"])
    g.append("class %s(%s):", interface["name"], interface["parent"])

    g.push_indent()
    g.append(['"""'] + interface["lines"] + ['"""'])
    # XXX These two don't seem to be needed, remove?
    #g.append("_case_insensitive_ = True")
    #g.append("_idlflags_ = []")
    g.append("_iid_ = IID_%s", interface["name"])

    # Write the methods once the class has been defined so parameters can refer
    # to the class if necessary
    g.pop_indent()
    g.append("%s._methods_ = [" % interface["name"])    
    g.push_indent()
    
    for method in interface.get("methods", []):
        g.append("comtypes.COMMETHOD(")
        g.push_indent()

        # g.append("[comtypes.helpstring('Method %s')],", method["name"])
        flag = "[]"
        if (method["flag"] is not None):
            flag = "['%s']" % method["flag"]
        g.append("#%s", method["return"])
        g.append("%s, %s, '%s',", flag, convert_type_name(method["return"], type_mappings), method["name"])

        for param in method["params"]:
            # XXX This should do something about types not declared yet, defer
            #     the creation of the COMMETHOD or such (but won't work for
            #     short methods?)

            # (['out'], wintypes.POINTER(TrustLevel), 'trustLevel'),
            flags = []
            for flag in param["flags"]:
                flags.append("'%s'" % flag)

            type_name = convert_type_name(param["type"], type_mappings)
            g.append("#%s", param["type"])
            g.append("([%s], %s, '%s'),", string.join(flags, ","), type_name, param["name"])

        g.pop_indent()
        g.append("),")

    g.pop_indent()
    g.append("]")
    g.append("")


def write_python(objs, filepath, type_mappings):
    with open(filepath, "w") as f:
        g = CodeGen(f)
        # XXX Move these to some wrttypes.py file
        g.append("""
            # Autogenerated %s %s
            import ctypes
            from ctypes import wintypes
            import logging

            import comtypes
            logger = logging.getLogger(__name__)

            HSTRING = wintypes.HANDLE
            ENUM = wintypes.UINT

            combase=ctypes.WinDLL('combase.dll')

            def check_hresult(hr):
                if (hr not in [comtypes.hresult.S_OK, comtypes.hresult.S_FALSE]):
                    raise comtypes.COMError(hr, comtypes.FormatError(hr),
                                (None, None, 0, None, None))

            class HString(HSTRING):
                def __init__(self, s_or_hstr = None):
                    if (isinstance(s_or_hstr, HSTRING)):
                        super(HString, self).__init__(s_or_hstr.value)

                    else:
                        u = unicode(s_or_hstr)
                        hr = combase.WindowsCreateString(u, len(u), ctypes.byref(self))
                        logger.info("WindowsCreateString 0x%%x 0x%%x", hr, self.value)

                        check_hresult(hr)
                    
                def __str__(self):
                    length = wintypes.UINT()
                    p = combase.WindowsGetStringRawBuffer(self, ctypes.byref(length))
                    logger.info("WindowsGetStringRawBuffer %%r %%r", length, p)

                    return ctypes.wstring_at(p, length.value)

                def __del__(self):
                    hr = combase.WindowsDeleteString(self)
                    logger.info("WindowsDeleteString %%x", hr)
                    
                    check_hresult(hr)

                    self.value = None

            def activate_instance(runtime_class_name, interface):
                inspectable = wintypes.POINTER(IInspectable)()
                hr = combase.RoActivateInstance(
                    HString(runtime_class_name),
                    ctypes.byref(inspectable)
                )
                check_hresult(hr)
                logger.info("RoActivateInstance %%x", hr)
                obj = inspectable.QueryInterface(interface)
                return obj

            class TrustLevel(ENUM):
                BaseTrust = 0
                PartialTrust = BaseTrust + 1
                FullTrust = PartialTrust + 1

            IID_IInspectable = comtypes.GUID('{AF86E2E0-B12D-4C6A-9C5A-D7AA65101E90}')
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

            # See https://learn.microsoft.com/en-us/windows/win32/api/eventtoken/ns-eventtoken-eventregistrationtoken
            class EventRegistrationToken(ctypes.Structure):
                _fields_ = [
                    ('value', ctypes.c_int64),
                ]
            """, os.path.basename(filepath), datetime.datetime.now())
        
        for obj in objs.itervalues():
            if (obj["type"] == "enum"):
                g.reset_indent()
                generate_python_enum(g, obj)
        
        # XXX This should at least generate the interfaces/runtime classes in
        #     order so they are not used before being defined? Another option is
        #     to declare all of them with pass or the _iid_ and then fill in the
        #     methods
        for obj in objs.itervalues():
            if (obj["type"] == "interface"):
                g.reset_indent()
                generate_python_interface(g, obj, type_mappings)
        
        for obj in objs.itervalues():
            if (obj["type"] == "runtimeclass"):
                g.reset_indent()
                generate_python_runtime_class(g, obj, type_mappings)
        

def write_python_from_idls():
    type_mappings = {
        "UINT16" : "wintypes.UINT16",
        "INT16" : "wintypes.INT16",
        "UINT32" : "wintypes.UINT32",
        "INT32" : "wintypes.INT32",
        "UINT64" : "wintypes.UINT64",
        "INT64" : "wintypes.INT64",
        "HRESULT" : "wintypes.HRESULT",
        "boolean" : "wintypes.BOOL",
    }

    for filename in [
        "simple.idl",
        "windows.devices.wifidirect.idl",
        "windows.foundation.idl",
        # XXX Breaks because of using spaces inside <>, needs to support some
        #     level of nesting?
        #     "windows.foundation.collections.idl",
        ] :
        filepath = os.path.join("_out", "idls", filename)
        entries = parse_idl_file(filepath)
        with open(os.path.join("_out", "idls", os.path.splitext(filename)[0] + ".json"), "w") as f:
            import json
            json.dump(entries, f, indent=2, sort_keys=True)

        filepath = os.path.join("_out", os.path.splitext(filename)[0] + ".py")
        write_python(entries, filepath, type_mappings)

class GUID(ctypes.Structure):
    # XXX wintypes.DWORD, wintypes.BYTE and wintypes.DWORD show as negative in
    #     %x, not clear why, use ctypes.c_uXXX instead
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
    """
    Port to Python of

    https://github.com/microsoft/Windows-classic-samples/tree/main/Samples/WiFiDirectLegacyAP

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
    
    winmd files

    https://stackoverflow.com/questions/54375771/how-to-read-a-winmd-winrt-metadata-file
    https://github.com/microsoft/winmd/tree/master
    https://learn.microsoft.com/en-us/windows/win32/api/rometadataresolution/nf-rometadataresolution-rogetmetadatafile

    idl files

    Some idl are missing from winrt (windows.foundation.collections.idl), mingw seems to have all of them
        pacman -S mingw-w64-i686-headers-git

    https://packages.msys2.org/package/mingw-w64-i686-headers-git?repo=mingw32
    https://github.com/MicrosoftDocs/winrt-related/blob/docs/winrt-related-src/midl-3/synthesizing-interfaces.md

    ## winrt wifidirect

    https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/winrt/windows.devices.wifidirect.h
    https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/winrt/windows.devices.wifidirect.idl

    https://learn.microsoft.com/en-us/windows/win32/nativewifi/using-the-wi-fi-direct-api
    https://github.com/microsoft/Windows-universal-samples/tree/main/Samples/WiFiDirect/cpp
    https://learn.microsoft.com/en-us/uwp/api/windows.devices.wifidirect.wifidirectlegacysettings?view=winrt-22621
    

    
    Procedure

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

    def array_to_guid(a):
        assert len(a) == 11, "Unexpected length %d" % len(a)
        
        data1, data2, data3, data4 = a[0], a[1], a[2], a[3:]

        s = "{%08X-%04X-%04X-%s-%s}" % (
            data1,
            data2,
            data3,
            # https://devblogs.microsoft.com/oldnewthing/20220928-00/?p=107221
            string.join(["%02X" % b for b in data4[:2]], ""),
            string.join(["%02X" % b for b in data4[2:]], ""),
        )
        logger.info("array_to_guid %s %s", a, s)

        return comtypes.GUID(s)

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

    ENUM = wintypes.UINT

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
                [comtypes.helpstring('Method GetIids')], comtypes.HRESULT, 'GetIids',
                (['out'], wintypes.POINTER(wintypes.ULONG), 'iidCount'),
                (['out'], wintypes.POINTER(wintypes.POINTER(comtypes.IID)), 'iids'),
            ),
            comtypes.COMMETHOD(
                [comtypes.helpstring('Method GetRuntimeClassName')], comtypes.HRESULT, 'GetRuntimeClassName',
                (['out'], wintypes.POINTER(HSTRING), 'className'),
            ),
            comtypes.COMMETHOD(
                [comtypes.helpstring('Method GetTrustLevel')], comtypes.HRESULT, 'GetTrustLevel',
                (['out'], wintypes.POINTER(TrustLevel), 'trustLevel'),
            ),
        ]



    def check_hresult(hr):
        if (hr not in [comtypes.hresult.S_OK, comtypes.hresult.S_FALSE]):
            raise comtypes.COMError(hr, comtypes.FormatError(hr),
                        (None, None, 0, None, None))

    class HString(HSTRING):
        def __init__(self, s_or_hstr = None):
            if (isinstance(s_or_hstr, HSTRING)):
                super(HString, self).__init__(s_or_hstr.value)

            else:
                u = unicode(s_or_hstr)
                hr = combase.WindowsCreateString(u, len(u), ctypes.byref(self))
                logger.info("WindowsCreateString %r %r", hex(hr), hex(self.value))

                check_hresult(hr)
            
        def __str__(self):
            length = wintypes.UINT()
            p = combase.WindowsGetStringRawBuffer(self, ctypes.byref(length))
            logger.info("WindowsGetStringRawBuffer %r %r", length, p)

            return ctypes.wstring_at(p, length.value)

        def __del__(self):
            hr = combase.WindowsDeleteString(self)
            logger.info("WindowsDeleteString %r", hex(hr))
            
            check_hresult(hr)

            self.value = None

    # https://learn.microsoft.com/en-us/windows/win32/api/objidlbase/nn-objidlbase-iagileobject
    IID_IAgileObject = comtypes.GUID("{94EA2B94-E9CC-49E0-C0FF-EE64CA8F5B90}")
    class IAgileObject(comtypes.IUnknown):
        # This is a marker-only interface, it doesn't have methods
        _iid_ = IID_IAgileObject
        _case_insensitive_ = True
        _idlflags_ = []
        _methods_ = [
        ]

    # https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/winrt/AsyncInfo.idl
    # https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/winrt/asyncinfo.h
    # {00000036-0000-0000-C000-000000000046}
    class AsyncStatus(ENUM):
        Started = 0
        Completed = 1
        Canceled = 2
        Error = 3
    IID_IAsyncInfo = array_to_guid((54, 0, 0, 192, 0, 0, 0, 0, 0, 0, 70))
    class IAsyncInfo(IInspectable):
        """
            // Properties
            [propget] HRESULT Id([out, retval] unsigned __int32 *id);

            // provide a C++ overload for async status that doesn't rely on 
            // the global definition of asyncstatus to support _HIDE_GLOBAL_ASYNC_STATUS
            [propget] HRESULT Status([out, retval] AsyncStatus *status);

            [propget] HRESULT ErrorCode([out,retval] HRESULT *errorCode);
            
            // Methods
            HRESULT Cancel();
            HRESULT Close();
        """
        _iid_ = IID_IAsyncInfo
        _case_insensitive_ = True
        _idlflags_ = []
        _methods_ = [
            # [propget] HRESULT Id([out, retval] unsigned __int32 *id);
            comtypes.COMMETHOD(
                ['propget'], wintypes.HRESULT, "Id", 
                (['out', 'retval'], wintypes.POINTER(ctypes.c_int32)),
            ),
            # [propget] HRESULT Status([out, retval] AsyncStatus *status);
            comtypes.COMMETHOD(
                ['propget'], wintypes.HRESULT, "Status", 
                (['out', 'retval'], wintypes.POINTER(AsyncStatus)),
            ),
            # [propget] HRESULT ErrorCode([out,retval] HRESULT *errorCode);
            comtypes.COMMETHOD(
                ['propget'], wintypes.HRESULT, "ErrorCode", 
                (['out', 'retval'], wintypes.POINTER(comtypes.HRESULT)),
            ),
            # HRESULT Cancel();
            comtypes.COMMETHOD(
                [], wintypes.HRESULT, "Cancel"
            ),
            # HRESULT Close();
            comtypes.COMMETHOD(
                [], wintypes.HRESULT, "Close"
            ),
        ]

    class IAsyncOperation(IAsyncInfo):
        # See https://learn.microsoft.com/en-us/uwp/api/windows.foundation.iasyncoperation-1?view=winrt-22621
        pass
    
    def make_typed_event_handler(iid, sender_class, args_class):
        name = "ITypedEventHandler_%s_%s" % (sender_class.__name__, args_class.__name__) 
        clazz = type(
            name,
            (comtypes.IUnknown,),
            dict(
                _iid_ = iid,
                _case_insensitive_ = True,
                _idlflags_ = [],
                _methods_ = [
                    # HRESULT Invoke([out, retval] unsigned __int32 *id);
                    comtypes.COMMETHOD(
                        [''], wintypes.HRESULT, "Invoke", 
                        (['in'], sender_class),
                        (['in'], args_class),
                    ),
                ]
            )
        )
        return clazz
    
    # See https://learn.microsoft.com/en-us/windows/win32/api/eventtoken/ns-eventtoken-eventregistrationtoken
    class EventRegistrationToken(ctypes.Structure):
        _fields_ = [
            ('value', ctypes.c_int64),
        ]

    IID_IPasswordCredential = comtypes.GUID("{6AB18989-C720-41A7-A6C1-FEADB36329A0}")
    class IPasswordCredential(IInspectable):
        """
        [uuid(6AB18989-C720-41A7-A6C1-FEADB36329A0)]
        [version(0x06020000)]
        interface IPasswordCredential : IInspectable
        {
            [propget] HRESULT Resource([out] [retval] HSTRING* resource);
            [propput] HRESULT Resource([in] HSTRING resource);
            [propget] HRESULT UserName([out] [retval] HSTRING* userName);
            [propput] HRESULT UserName([in] HSTRING userName);
            [propget] HRESULT Password([out] [retval] HSTRING* password);
            [propput] HRESULT Password([in] HSTRING password);
            HRESULT RetrievePassword();
            [propget] HRESULT Properties([out] [retval] Windows.Foundation.Collections.IPropertySet** props);
        }
        """
        _iid_ = IID_IPasswordCredential
        _case_insensitive_ = True
        _idlflags_ = []
        _methods_ = [
            # [propget] HRESULT Resource([out] [retval] HSTRING* resource);
            comtypes.COMMETHOD(
                ['propget'], wintypes.HRESULT, "Resource", 
                (['out', 'retval'], wintypes.POINTER(HSTRING)),
            ),
            # [propput] HRESULT Resource([in] HSTRING resource);
            comtypes.COMMETHOD(
                ['propput'], wintypes.HRESULT, "Resource", 
                (['in'], HSTRING),
            ),
            # [propget] HRESULT UserName([out] [retval] HSTRING* userName);
            comtypes.COMMETHOD(
                ['propget'], wintypes.HRESULT, "UserName", 
                (['out', 'retval'], wintypes.POINTER(HSTRING)),
            ),
            # [propput] HRESULT UserName([in] HSTRING userName);
            comtypes.COMMETHOD(
                ['propput'], wintypes.HRESULT, "UserName", 
                (['in'], HSTRING),
            ),
            # [propget] HRESULT Password([out] [retval] HSTRING* password);
            comtypes.COMMETHOD(
                ['propget'], wintypes.HRESULT, "Password", 
                (['out', 'retval'], wintypes.POINTER(HSTRING)),
            ),
            # [propput] HRESULT Password([in] HSTRING password);
            comtypes.COMMETHOD(
                ['propput'], wintypes.HRESULT, "Password", 
                (['in'], HSTRING),
            ),
            # HRESULT RetrievePassword();
            comtypes.COMMETHOD(
                [], wintypes.HRESULT, "RetrievePassword"
            ),
            # [propget] HRESULT Properties([out] [retval] Windows.Foundation.Collections.IPropertySet** props);
            comtypes.COMMETHOD(
                ['propget'], wintypes.HRESULT, "Properties", 
                # XXX This is actually IPropertySet**
                (['out', 'retval'], wintypes.POINTER(wintypes.POINTER(IInspectable))),
            ),
        ]

    IID_IWiFiDirectLegacySettings = comtypes.GUID("{A64FDBBA-F2FD-4567-A91B-F5C2F5321057}")
    class IWiFiDirectLegacySettings(IInspectable):
        """
        [exclusiveto(Windows.Devices.WiFiDirect.WiFiDirectLegacySettings)]
        [uuid(A64FDBBA-F2FD-4567-A91B-F5C2F5321057)]
        interface IWiFiDirectLegacySettings : IInspectable
        {
            [propget] HRESULT IsEnabled([out] [retval] boolean* value);
            [propput] HRESULT IsEnabled([in] boolean value);
            [propget] HRESULT Ssid([out] [retval] HSTRING* value);
            [propput] HRESULT Ssid([in] HSTRING value);
            [propget] HRESULT Passphrase([out] [retval] Windows.Security.Credentials.PasswordCredential** value);
            [propput] HRESULT Passphrase([in] Windows.Security.Credentials.PasswordCredential* value);
        }
        """
        _iid_ = IID_IWiFiDirectLegacySettings
        _case_insensitive_ = True
        _idlflags_ = []
        _methods_ = [
            # [propget] HRESULT IsEnabled([out] [retval] boolean* value);
            comtypes.COMMETHOD(
                ['propget'], wintypes.HRESULT, "IsEnabled", 
                (['out', 'retval'], wintypes.POINTER(wintypes.BOOL)),
            ),
            # [propput] HRESULT IsEnabled([in] boolean value);
            comtypes.COMMETHOD(
                ['propput'], wintypes.HRESULT, "IsEnabled", 
                (['in'], wintypes.BOOL),
            ),
            # [propget] HRESULT Ssid([out] [retval] HSTRING* value);
            comtypes.COMMETHOD(
                ['propget'], wintypes.HRESULT, "Ssid", 
                (['out', 'retval'], wintypes.POINTER(HSTRING)),
            ),
            # [propput] HRESULT Ssid([in] HSTRING value);
            comtypes.COMMETHOD(
                ['propput'], wintypes.HRESULT, "Ssid", 
                (['in'], HSTRING),
            ),

            # [propget] HRESULT Passphrase([out] [retval] Windows.Security.Credentials.PasswordCredential** value);
            comtypes.COMMETHOD(
                ['propget'], wintypes.HRESULT, "Passphrase", 
                (['out', 'retval'], wintypes.POINTER(wintypes.POINTER(IPasswordCredential))),
            ),
            # [propput] HRESULT Passphrase([in] Windows.Security.Credentials.PasswordCredential* value);
            comtypes.COMMETHOD(
                ['propput'], wintypes.HRESULT, "Passphrase", 
                (['in'], wintypes.POINTER(IPasswordCredential)),
            ),
        ]

    IID_IWiFiDirectAdvertisement = comtypes.GUID("{AB511A2D-2A06-49A1-A584-61435C7905A6}")
    class IWifiDirectAdvertisement(IInspectable):
        """
        [uuid(AB511A2D-2A06-49A1-A584-61435C7905A6)]
        interface IWiFiDirectAdvertisement : IInspectable
        {
            [propget] HRESULT InformationElements([out] [retval] Windows.Foundation.Collections.IVector<Windows.Devices.WiFiDirect.WiFiDirectInformationElement*>** value);
            [propput] HRESULT InformationElements([in] Windows.Foundation.Collections.IVector<Windows.Devices.WiFiDirect.WiFiDirectInformationElement*>* value);
            [propget] HRESULT ListenStateDiscoverability([out] [retval] Windows.Devices.WiFiDirect.WiFiDirectAdvertisementListenStateDiscoverability* value);
            [propput] HRESULT ListenStateDiscoverability([in] Windows.Devices.WiFiDirect.WiFiDirectAdvertisementListenStateDiscoverability value);
            [propget] HRESULT IsAutonomousGroupOwnerEnabled([out] [retval] boolean* value);
            [propput] HRESULT IsAutonomousGroupOwnerEnabled([in] boolean value);
            [propget] HRESULT LegacySettings([out] [retval] Windows.Devices.WiFiDirect.WiFiDirectLegacySettings** value);
        }
        """
        _iid_ = IID_IWiFiDirectAdvertisement
        _case_insensitive_ = True
        _idlflags_ = []
        _methods_ = [
            # [propget] HRESULT InformationElements([out] [retval] Windows.Foundation.Collections.IVector<Windows.Devices.WiFiDirect.WiFiDirectInformationElement*>** value);
            comtypes.COMMETHOD(
                ['propget'], wintypes.HRESULT, "InformationElements", 
                # XXX This is actually IVector<Windows.Devices.WiFiDirect.WiFiDirectInformationElement*>*
                (['out', 'retval'], wintypes.POINTER(wintypes.POINTER(IInspectable))),
            ),
            # [propput] HRESULT InformationElements([in] Windows.Foundation.Collections.IVector<Windows.Devices.WiFiDirect.WiFiDirectInformationElement*>* value);
            comtypes.COMMETHOD(
                ['propput'], wintypes.HRESULT, "InformationElements", 
                # XXX This is actually IVector<Windows.Devices.WiFiDirect.WiFiDirectInformationElement*>*
                (['in'], wintypes.POINTER(IInspectable)),
            ),
            # [propget] HRESULT ListenStateDiscoverability([out] [retval] Windows.Devices.WiFiDirect.WiFiDirectAdvertisementListenStateDiscoverability* value);
            comtypes.COMMETHOD(
                ['propget'], wintypes.HRESULT, "ListenStateDiscoverability", 
                # XXX This is actually WiFiDirectAdvertisementListenStateDiscoverability 
                (['out', 'retval'], wintypes.POINTER(wintypes.POINTER(IInspectable))),
            ),
            #[propput] HRESULT ListenStateDiscoverability([in] Windows.Devices.WiFiDirect.WiFiDirectAdvertisementListenStateDiscoverability value);
            comtypes.COMMETHOD(
                ['propput'], wintypes.HRESULT, "ListenStateDiscoverability", 
                # XXX This is actually WiFiDirectAdvertisementListenStateDiscoverability 
                (['in'], wintypes.POINTER(IInspectable)),
            ),
            # [propget] HRESULT IsAutonomousGroupOwnerEnabled([out] [retval] boolean* value);
            comtypes.COMMETHOD(
                ['propget'], wintypes.HRESULT, "IsAutonomousGroupOwnerEnabled", 
                (['out', 'retval'], wintypes.POINTER(wintypes.BOOL)),
            ),
            # [propput] HRESULT IsAutonomousGroupOwnerEnabled([in] boolean value);
            comtypes.COMMETHOD(
                ['propput'], wintypes.HRESULT, "IsAutonomousGroupOwnerEnabled", 
                (['in'], wintypes.BOOL),
            ),
            # [propget] HRESULT LegacySettings([out] [retval] Windows.Devices.WiFiDirect.WiFiDirectLegacySettings** value);
            comtypes.COMMETHOD(
                ['propget'], wintypes.HRESULT, "LegacySettings", 
                (['out', 'retval'], wintypes.POINTER(wintypes.POINTER(IWiFiDirectLegacySettings))),
            ),
        ]

    class IWiFiDirectAdvertisementPublisherStatus(ENUM):
        Created = 0
        Started = 1
        Stopped = 2
        Aborted = 3

    class IWiFiDirectError(ENUM):
        Success           = 0
        RadioNotAvailable = 1
        ResourceInUse     = 2
         
    IID_IWiFiDirectAdvertisementPublisherStatusChangedEventArgs = comtypes.GUID("{AAFDE53C-5481-46E6-90DD-32116518F192}")
    class IWiFiDirectAdvertisementPublisherStatusChangedEventArgs(IInspectable):
        """
        [uuid(AAFDE53C-5481-46E6-90DD-32116518F192)]
        [version(0x0A000000)]
        interface IWiFiDirectAdvertisementPublisherStatusChangedEventArgs : IInspectable
        {
            [propget] HRESULT Status([out] [retval] Windows.Devices.WiFiDirect.WiFiDirectAdvertisementPublisherStatus* value);
            [propget] HRESULT Error([out] [retval] Windows.Devices.WiFiDirect.WiFiDirectError* value);
        }
        """
        _iid_ = IID_IWiFiDirectAdvertisementPublisherStatusChangedEventArgs
        _case_insensitive_ = True
        _idlflags_ = []
        _methods_ = [
            # [propget] HRESULT Status([out] [retval] Windows.Devices.WiFiDirect.WiFiDirectAdvertisementPublisherStatus* value);
            comtypes.COMMETHOD(
                ['propget'], wintypes.HRESULT, "Status",
                ( ['out', 'retval'], wintypes.POINTER(IWiFiDirectAdvertisementPublisherStatus), "value" ),
            ),
            
            # [propget] HRESULT Error([out] [retval] Windows.Devices.WiFiDirect.WiFiDirectError* value);
            comtypes.COMMETHOD(
                ['propget'], wintypes.HRESULT, "Error",
                ( ['out', 'retval'], wintypes.POINTER(IWiFiDirectError), "value" ),
            ),
        ]
    
    """
    MIDL_INTERFACE("de73cba7-370d-550c-b23a-53dd0b4e480d")
    __FITypedEventHandler_2_Windows__CDevices__CWiFiDirect__CWiFiDirectAdvertisementPublisher_Windows__CDevices__CWiFiDirect__CWiFiDirectAdvertisementPublisherStatusChangedEventArgs : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE Invoke( 
            /* [in] */ __RPC__in_opt ABI::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisementPublisher *sender,
            /* [in] */ __RPC__in_opt ABI::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisementPublisherStatusChangedEventArgs *e) = 0;
        
    };
    """
    # https://learn.microsoft.com/en-us/previous-versions/hh438424(v=vs.85)
    # XXX Actually TypedEventHandler<IWiFiDirectAdvertisementPublisher*, WiFiDirectAdvertisementPublisherStatusChangedEventArgs*>
    IID_ITypedEventHandler_IInspectable_IWiFiDirectAdvertisementPublisherStatusChangedEventArgs = comtypes.GUID("{DE73CBA7-370D-550C-B23A-53DD0B4E480D}")
    ITypedEventHandler_IInspectable_IWiFiDirectAdvertisementPublisherStatusChangedEventArgs = make_typed_event_handler(
        IID_ITypedEventHandler_IInspectable_IWiFiDirectAdvertisementPublisherStatusChangedEventArgs,
        wintypes.POINTER(IInspectable), 
        wintypes.POINTER(IWiFiDirectAdvertisementPublisherStatusChangedEventArgs)
    )
    
    IID_IWiFiDirectAdvertisementPublisher = comtypes.GUID("{B35A2D1A-9B1F-45D9-925A-694D66DF68EF}")
    class IWiFiDirectAdvertisementPublisher(IInspectable):
        """
        [uuid(B35A2D1A-9B1F-45D9-925A-694D66DF68EF)]
        [version(0x0A000000)]
        interface IWiFiDirectAdvertisementPublisher : IInspectable
        {
            [propget] HRESULT Advertisement([out] [retval] Windows.Devices.WiFiDirect.WiFiDirectAdvertisement** value);
            [propget] HRESULT Status([out] [retval] Windows.Devices.WiFiDirect.WiFiDirectAdvertisementPublisherStatus* value);
            [eventadd] HRESULT StatusChanged([in] Windows.Foundation.TypedEventHandler<Windows.Devices.WiFiDirect.WiFiDirectAdvertisementPublisher*, Windows.Devices.WiFiDirect.WiFiDirectAdvertisementPublisherStatusChangedEventArgs*>* handler, [out] [retval] EventRegistrationToken* token);
            [eventremove] HRESULT StatusChanged([in] EventRegistrationToken token);
            HRESULT Start();
            HRESULT Stop();
        }
        """
        _iid_ = IID_IWiFiDirectAdvertisementPublisher
        _case_insensitive_ = True
        _idlflags_ = []
        _methods_ = [
            # [propget] HRESULT Advertisement([out] [retval] Windows.Devices.WiFiDirect.WiFiDirectAdvertisement** value);
            comtypes.COMMETHOD(
                ['propget'], wintypes.HRESULT, "Advertisement", 
                (['out', 'retval'], wintypes.POINTER(wintypes.POINTER(IWifiDirectAdvertisement))),
            ),

            # [propget] HRESULT Status([out] [retval] Windows.Devices.WiFiDirect.WiFiDirectAdvertisementPublisherStatus* value);
            
            comtypes.COMMETHOD(
                ['propget'], wintypes.HRESULT, "Status", 
                (['out', 'retval'], wintypes.POINTER(IWiFiDirectAdvertisementPublisherStatus)),
            ),

            # [eventadd] HRESULT StatusChanged([in] Windows.Foundation.TypedEventHandler<Windows.Devices.WiFiDirect.WiFiDirectAdvertisementPublisher*, Windows.Devices.WiFiDirect.WiFiDirectAdvertisementPublisherStatusChangedEventArgs*>* handler, [out] [retval] EventRegistrationToken* token);
            # XXX see https://github.com/pywinrt/pywinrt/tree/main/projection#event-handlers
            comtypes.COMMETHOD(
                [], comtypes.HRESULT, 'add_StatusChanged',
                (['in'], ctypes.POINTER(ITypedEventHandler_IInspectable_IWiFiDirectAdvertisementPublisherStatusChangedEventArgs), 'handler'),
                (['out', 'retval'], wintypes.POINTER(EventRegistrationToken), 'token'),
            ),
            # [eventremove] HRESULT StatusChanged([in] EventRegistrationToken token);
            comtypes.COMMETHOD(
                [], comtypes.HRESULT, 'remove_StatusChanged',
                (['in'], EventRegistrationToken, 'handler'),
            ),

            # HRESULT Start();
            comtypes.COMMETHOD(
                [], comtypes.HRESULT, 'Start'
            ),

            # HRESULT Stop();
            comtypes.COMMETHOD(
                [], comtypes.HRESULT, 'Stop'
            ),
        ]

        @property
        def StatusChanged(self):
            return self.StatusChangedHandler

        @StatusChanged.setter
        def StatusChanged(self, handler):
            # type(ctypes.POINTER(ITypedEventHandler_IInspectable_IWiFiDirectAdvertisementPublisherStatusChangedEventArgs)) -> None
            self.StatusChangedToken = EventRegistrationToken()
            
            self.__com_add_StatusChanged(handler, ctypes.byref(self.StatusChangedHandler))
            self.StatusChangedHandler = handler

    # XXX Actually Windows.Devices.Enumeration.DeviceInformation
    IID_IDeviceInformation = comtypes.GUID("{ABA0FB95-4398-489D-8E44-E6130927011F}")
    class IDeviceInformation(IInspectable):
        """
        [uuid(ABA0FB95-4398-489D-8E44-E6130927011F)]
        [version(0x06020000)]
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

        """
        _iid_ = IID_IDeviceInformation
        _case_insensitive_ = True
        _idlflags_ = []
        _methods_ = [
            # [propget] HRESULT Id([out] [retval] HSTRING* value);
            comtypes.COMMETHOD(
                ['propget'], comtypes.HRESULT, 'Id',
                (['out', 'retval'], wintypes.POINTER(HSTRING), 'result'),
            ),
            # XXX Missing the rest
        ]
        
    
    IID_IWiFiDirectConnectionRequest = comtypes.GUID("{8EB99605-914F-49C3-A614-D18DC5B19B43}")
    class IWiFiDirectConnectionRequest(IInspectable):
        """
        [exclusiveto(Windows.Devices.WiFiDirect.WiFiDirectConnectionRequest)]
        [uuid(8EB99605-914F-49C3-A614-D18DC5B19B43)]
        [version(0x0A000000)]
        interface IWiFiDirectConnectionRequest : IInspectable
            requires
                Windows.Foundation.IClosable
        {
            [propget] HRESULT DeviceInformation([out] [retval] Windows.Devices.Enumeration.DeviceInformation** value);
        }
        """
        _iid_ = IID_IWiFiDirectConnectionRequest
        _case_insensitive_ = True
        _idlflags_ = []
        _methods_ = [
            # [propget] HRESULT DeviceInformation([out] [retval] Windows.Devices.Enumeration.DeviceInformation** value);
            comtypes.COMMETHOD(
                ['propget'], comtypes.HRESULT, 'DeviceInformation',
                (['out', 'retval'], wintypes.POINTER(wintypes.POINTER(IDeviceInformation)), 'result'),
            ),
        ]

    IID_IWiFiDirectConnectionRequestedEventArgs = comtypes.GUID("{F99D20BE-D38D-484F-8215-E7B65ABF244C}")
    class IWiFiDirectConnectionRequestedEventArgs(IInspectable):
        """
        [exclusiveto(Windows.Devices.WiFiDirect.WiFiDirectConnectionRequestedEventArgs)]
        [uuid(F99D20BE-D38D-484F-8215-E7B65ABF244C)]
        [version(0x0A000000)]
        interface IWiFiDirectConnectionRequestedEventArgs : IInspectable
        {
            HRESULT GetConnectionRequest([out] [retval] Windows.Devices.WiFiDirect.WiFiDirectConnectionRequest** result);
        }
        """
        _iid_ = IID_IWiFiDirectConnectionRequestedEventArgs
        _case_insensitive_ = True
        _idlflags_ = []
        _methods_ = [
            # HRESULT GetConnectionRequest([out] [retval] Windows.Devices.WiFiDirect.WiFiDirectConnectionRequest** result);
            comtypes.COMMETHOD(
                [], comtypes.HRESULT, 'GetConnectionRequest',
                # XXX Actually WiFiDirectConnectionRequest**
                (['out', 'retval'], wintypes.POINTER(wintypes.POINTER(IWiFiDirectConnectionRequest)), 'result'),
            ),
        ]

    """
    template <>
    struct __declspec(uuid("d04b0403-1fe2-532f-8e47-4823a14e624f"))
    ITypedEventHandler<ABI::Windows::Devices::WiFiDirect::WiFiDirectConnectionListener*,ABI::Windows::Devices::WiFiDirect::WiFiDirectConnectionRequestedEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Devices::WiFiDirect::WiFiDirectConnectionListener*, ABI::Windows::Devices::WiFiDirect::IWiFiDirectConnectionListener*>,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Devices::WiFiDirect::WiFiDirectConnectionRequestedEventArgs*, ABI::Windows::Devices::WiFiDirect::IWiFiDirectConnectionRequestedEventArgs*>> 
    {
        static const wchar_t* z_get_rc_name_impl() 
        {
            return L"Windows.Foundation.TypedEventHandler`2<Windows.Devices.WiFiDirect.WiFiDirectConnectionListener, Windows.Devices.WiFiDirect.WiFiDirectConnectionRequestedEventArgs>"; 
        }
    };
    """
    IID_ITypedEventHandler_IInspectable_IWiFiDirectConnectionRequestedEventArgs = comtypes.GUID("{d04b0403-1fe2-532f-8e47-4823a14e624f}")
    # XXX Actually TypedEventHandler<WiFiDirectConnectionListener*, WiFiDirectConnectionRequestedEventArgs*>
    ITypedEventHandler_IInspectable_IWiFiDirectConnectionRequestedEventArgs = make_typed_event_handler(
        IID_ITypedEventHandler_IInspectable_IWiFiDirectConnectionRequestedEventArgs,
        wintypes.POINTER(IInspectable), 
        wintypes.POINTER(IWiFiDirectConnectionRequestedEventArgs)
    )

    # interface IWiFiDirectConnectionListener : IInspectable
    IID_IWiFiDirectConnectionListener = comtypes.GUID("{699C1B0D-8D13-4EE9-B9EC-9C72F8251F7D}")
    class IWiFiDirectConnectionListener(IInspectable):
        """
        [exclusiveto(Windows.Devices.WiFiDirect.WiFiDirectConnectionListener)]
        [uuid(699C1B0D-8D13-4EE9-B9EC-9C72F8251F7D)]
        [version(0x0A000000)]
        interface IWiFiDirectConnectionListener : IInspectable
        {
            [eventadd] HRESULT ConnectionRequested([in] Windows.Foundation.TypedEventHandler<Windows.Devices.WiFiDirect.WiFiDirectConnectionListener*, Windows.Devices.WiFiDirect.WiFiDirectConnectionRequestedEventArgs*>* handler, [out] [retval] EventRegistrationToken* token);
            [eventremove] HRESULT ConnectionRequested([in] EventRegistrationToken token);
        }
        """
        _iid_ = IID_IWiFiDirectConnectionListener
        _case_insensitive_ = True
        _idlflags_ = []
        _methods_ = [
            # [eventadd] HRESULT ConnectionRequested([in] Windows.Foundation.TypedEventHandler<Windows.Devices.WiFiDirect.WiFiDirectConnectionListener*, Windows.Devices.WiFiDirect.WiFiDirectConnectionRequestedEventArgs*>* handler, [out] [retval] EventRegistrationToken* token);
            # XXX see https://github.com/pywinrt/pywinrt/tree/main/projection#event-handlers
            comtypes.COMMETHOD(
                [], comtypes.HRESULT, 'add_ConnectionRequested',
                (['in'], wintypes.POINTER(ITypedEventHandler_IInspectable_IWiFiDirectConnectionRequestedEventArgs), 'handler'),
                (['out', 'retval'], wintypes.POINTER(EventRegistrationToken), 'token'),
            ),
            # [eventremove] HRESULT ConnectionRequested([in] EventRegistrationToken token);
            comtypes.COMMETHOD(
                [], comtypes.HRESULT, 'remove_ConnectionRequested',
                (['in'], EventRegistrationToken, 'token'),
            ),
        ]

    IID_IWiFiDirectDevice = comtypes.GUID("{72DEAAA8-72EB-4DAE-8A28-8513355D2777}")
    class IWiFiDirectDevice(IInspectable):
        """
        [exclusiveto(Windows.Devices.WiFiDirect.WiFiDirectDevice)]
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
        """
        _iid_ = IID_IWiFiDirectDevice
        # XXX Implement
        pass

    IID_IAsyncOperation_IWiFiDirectDevice = comtypes.GUID("{dad01b61-a82d-566c-ba82-224c11500669}")
    class IAsyncOperation_IWiFiDirectDevice(IInspectable):
        """
        MIDL_INTERFACE("dad01b61-a82d-566c-ba82-224c11500669")
        __FIAsyncOperation_1_Windows__CDevices__CWiFiDirect__CWiFiDirectDevice : public IInspectable
        {
        public:
            virtual /* [propput] */ HRESULT STDMETHODCALLTYPE put_Completed( 
                /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CWiFiDirect__CWiFiDirectDevice *handler) = 0;
            
            virtual /* [propget] */ HRESULT STDMETHODCALLTYPE get_Completed( 
                /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CWiFiDirect__CWiFiDirectDevice **handler) = 0;
            
            virtual HRESULT STDMETHODCALLTYPE GetResults( 
                /* [retval][out] */ __RPC__deref_out_opt ABI::Windows::Devices::WiFiDirect::IWiFiDirectDevice **results) = 0;
            
        };
        """
        _iid_ = IID_IAsyncOperation_IWiFiDirectDevice
        _case_insensitive_ = True
        _idlflags_ = []
        _methods_ = [
            # virtual /* [propput] */ HRESULT STDMETHODCALLTYPE put_Completed( 
            #   /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CWiFiDirect__CWiFiDirectDevice *handler) = 0;
            comtypes.COMMETHOD(
                ['propput'], wintypes.HRESULT, "Completed", 
                # XXX Actually IAsyncOperation_WiFiDirectDevice
                (['in'], wintypes.POINTER(IAsyncOperation), "handler"),
            ),
            # virtual /* [propget] */ HRESULT STDMETHODCALLTYPE get_Completed( 
            #   /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CWiFiDirect__CWiFiDirectDevice **handler) = 0;
            comtypes.COMMETHOD(
                ['propget'], wintypes.HRESULT, "Completed", 
                # XXX Actually IAsyncOperationCompletedHandler_WiFiDirectDevice
                (['out', 'retval'], wintypes.POINTER(wintypes.POINTER(IAsyncOperation))),
            ),
            # virtual HRESULT STDMETHODCALLTYPE GetResults( 
            #   /* [retval][out] */ __RPC__deref_out_opt ABI::Windows::Devices::WiFiDirect::IWiFiDirectDevice **results) = 0;
            comtypes.COMMETHOD(
                [], wintypes.HRESULT, "GetResults",
                (['out', 'retval'], wintypes.POINTER(wintypes.POINTER(IWiFiDirectDevice))),

            ),
        ]

    """
    MIDL_INTERFACE("d34abe17-fb19-57be-bc41-0eb83dea151c")
    __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CWiFiDirect__CWiFiDirectDevice : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE Invoke( 
            /* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CDevices__CWiFiDirect__CWiFiDirectDevice *asyncInfo,
            /* [in] */ AsyncStatus status) = 0;
        
    };
    """
    IID_IAsyncOperationCompletedHandler_WiFiDirectDevice = comtypes.GUID("{d34abe17-fb19-57be-bc41-0eb83dea151c}")
    IAsyncOperationCompletedHandler_WiFiDirectDevice = make_typed_event_handler(
        IID_IAsyncOperationCompletedHandler_WiFiDirectDevice,
        wintypes.POINTER(IAsyncOperation_IWiFiDirectDevice),
        AsyncStatus
    )

    IID_IWiFiDirectDeviceStatics = comtypes.GUID("{E86CB57C-3AAC-4851-A792-482AAF931B04}")
    class IWiFiDirectDeviceStatics(IInspectable):
        """
        [exclusiveto(Windows.Devices.WiFiDirect.WiFiDirectDevice)]
        [uuid(E86CB57C-3AAC-4851-A792-482AAF931B04)]
        [version(0x06030000)]
        interface IWiFiDirectDeviceStatics : IInspectable
        {
            [overload("GetDeviceSelector")] HRESULT GetDeviceSelector([out] [retval] HSTRING* deviceSelector);
            [overload("FromIdAsync")] HRESULT FromIdAsync([in] HSTRING deviceId, [out] [retval] Windows.Foundation.IAsyncOperation<Windows.Devices.WiFiDirect.WiFiDirectDevice*>** asyncOp);
        }
        """
        _iid_ = IID_IWiFiDirectDeviceStatics
        _case_insensitive_ = True
        _idlflags_ = []
        _methods_ = [
            # [overload("GetDeviceSelector")] HRESULT GetDeviceSelector([out] [retval] HSTRING* deviceSelector);
            comtypes.COMMETHOD(
                [], comtypes.HRESULT, 'GetDeviceSelector',
                (['out', 'retval'], wintypes.POINTER(HSTRING), 'deviceSelector'),
            ),
            # [overload("FromIdAsync")] HRESULT FromIdAsync([in] HSTRING deviceId, [out] [retval] Windows.Foundation.IAsyncOperation<Windows.Devices.WiFiDirect.WiFiDirectDevice*>** asyncOp);
            comtypes.COMMETHOD(
                [], comtypes.HRESULT, 'FromIdAsync',
                (['in'], HSTRING, 'deviceId'),
                (['out', 'retval'], wintypes.POINTER(wintypes.POINTER(IAsyncOperation_IWiFiDirectDevice)), 'asyncOp'),
            ),
        ]

    # See https://gist.github.com/olafhartong/980e9cd51925ff06a5a3fdfb24fb96c2 for a list of clsids

    # See https://learn.microsoft.com/en-us/uwp/api/windows.foundation.typedeventhandler-2?view=winrt-22621
    # GUID((2648818996, 27361, 4576, 132, 225, 24, 169, 5, 188, 197, 63))
    # This asks for
    # - INoMarshall {ECC8691B-C1DB-4DC0-855E-65F6C551AF49}
    # - ??????      {00000039-0000-0000-C000-000000000046}
    # - IdentityUnmarshal {0000001B-0000-0000-C000-000000000046}
    # - IAgileObject {94EA2B94-E9CC-49E0-C0FF-EE64CA8F5B90}
    # And once publisher.Start() is called it asks for
    # - ITypedEventHandler {DE73CBA7-370D-550C-B23A-53DD0B4E480D}
    class IAsyncOperationCompletedHandler_Impl(comtypes.COMObject):
        def __init__(self):
            super(IAsyncOperationCompletedHandler_Impl, self).__init__()

        def IInspectable_GetIids(self, this, iidCount, iids):
            # XXX Untested
            logger.info("")
            ifaces = []
            for iface in self._com_interfaces_:
                if iface not in [IInspectable, IUnknown]:
                    ifaces.append(iface._iid_)
            
            pv = combase.CoTaskMemAlloc(len(ifaces) * 4)
            iids.content = pv
            iidCount.content = len(ifaces)
            return comtypes.hresult.S_OK

        def IInspectable_GetRuntimeClassName(self, this):
            logger.info("")
            return comtypes.hresult.E_NOTIMPL

        def IInspectable_GetTrustLevel(self, this):
            logger.info("")
            return comtypes.hresult.E_NOTIMPL

        def IAsyncInfo_Cancel(self, this):
            logger.info("")
            return comtypes.hresult.E_NOTIMPL

        def IAsyncInfo_Close(self, this):
            logger.info("")
            return comtypes.hresult.E_NOTIMPL

        def IAsyncOperation_Cancel(self, this):
            logger.info("")
            return comtypes.hresult.E_NOTIMPL

        def IAsyncOperation_Close(self, this):
            logger.info("")
            return comtypes.hresult.E_NOTIMPL

    class PublisherStatusChangedHandler(IAsyncOperationCompletedHandler_Impl):
        """
        MIDL_INTERFACE("de73cba7-370d-550c-b23a-53dd0b4e480d")
        __FITypedEventHandler_2_Windows__CDevices__CWiFiDirect__CWiFiDirectAdvertisementPublisher_Windows__CDevices__CWiFiDirect__CWiFiDirectAdvertisementPublisherStatusChangedEventArgs : public IUnknown
        {
        public:
            virtual HRESULT STDMETHODCALLTYPE Invoke( 
                /* [in] */ __RPC__in_opt ABI::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisementPublisher *sender,
                /* [in] */ __RPC__in_opt ABI::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisementPublisherStatusChangedEventArgs *e) = 0;
            
        };
        """
        # See https://svn.python.org/projects/ctypes/tags/comtypes-0.3.2/docs/com_interfaces.html
        _com_interfaces_ = [
            IAsyncOperation,
            IInspectable,
            IAgileObject,
            ITypedEventHandler_IInspectable_IWiFiDirectAdvertisementPublisherStatusChangedEventArgs,
        ]
        # XXX Allow passing a callback instead of having to create a class?
        def Invoke(self, this, sender, args):
            logger.info("sender %r args %r", sender, args)
            logger.info("status %s", args.Status.value)
            if (args.Status.value == IWiFiDirectAdvertisementPublisherStatus.Created):
                logger.info("Publisher started, should start created")

            elif (args.Status.value == IWiFiDirectAdvertisementPublisherStatus.Started):
                logger.info("Publisher started, should start listener")
            
            elif (args.Status.value == IWiFiDirectAdvertisementPublisherStatus.Aborted):
                logger.info("Publisher aborted")

            elif (args.Status.value == IWiFiDirectAdvertisementPublisherStatus.Stopped):
                logger.info("Publisher stopped")
                
            return comtypes.hresult.S_OK


    class ConnectionAcceptedCompletedHandler(IAsyncOperationCompletedHandler_Impl):
        """
        MIDL_INTERFACE("d34abe17-fb19-57be-bc41-0eb83dea151c")
        __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CWiFiDirect__CWiFiDirectDevice : public IUnknown
        {
        public:
            virtual HRESULT STDMETHODCALLTYPE Invoke( 
                /* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CDevices__CWiFiDirect__CWiFiDirectDevice *asyncInfo,
                /* [in] */ AsyncStatus status) = 0;
            
        };
        """
        # See https://svn.python.org/projects/ctypes/tags/comtypes-0.3.2/docs/com_interfaces.html
        _com_interfaces_ = [
            IAsyncOperation,
            IInspectable,
            IAgileObject,
            IAsyncOperationCompletedHandler_WiFiDirectDevice,
        ]
        # XXX Allow passing a callback instead of having to create a class?
        def Invoke(self, this, sender, args):
            logger.info("sender %r args %r", sender, args)
            logger.info("status %s", args.value)

            if (args.value == AsyncStatus.Completed):
                logger.info("Completed")
                
                # hr = pHandler->GetResults(wfdDevice.GetAddressOf());
                wfdDevice = wintypes.POINTER(IWiFiDirectDevice)()
                sender._IAsyncOperation_IWiFiDirectDevice__com_GetResults(ctypes.byref(wfdDevice))
                

                # XXX Missing Implementing
                # hr = wfdDevice->GetConnectionEndpointPairs(endpointPairs.GetAddressOf());
                # hr = endpointPairs->GetAt(0, endpointPair.GetAddressOf());
                # hr = endpointPair->get_RemoteHostName(remoteHostName.GetAddressOf());
                # hr = remoteHostName->get_DisplayName(remoteHostNameDisplay.GetAddressOf());
                # EventRegistrationToken statusChangedToken;
                # hr = wfdDevice->add_ConnectionStatusChanged(Callback<ConnectionStatusChangedHandler>([this](IWiFiDirectDevice* sender, IInspectable*) -> HRESULT
                # ...


            elif (args.value == AsyncStatus.Started):
                logger.info("Started")
            elif (args.value == AsyncStatus.Canceled):
                logger.info("Canceled")
            elif (args.value == AsyncStatus.Error):
                logger.info("Error")


            return comtypes.hresult.S_OK

    
    class ConnectionRequestedHandler(IAsyncOperationCompletedHandler_Impl):
        """
        MIDL_INTERFACE("d04b0403-1fe2-532f-8e47-4823a14e624f")
        __FITypedEventHandler_2_Windows__CDevices__CWiFiDirect__CWiFiDirectConnectionListener_Windows__CDevices__CWiFiDirect__CWiFiDirectConnectionRequestedEventArgs : public IUnknown
        {
        public:
            virtual HRESULT STDMETHODCALLTYPE Invoke( 
                /* [in] */ __RPC__in_opt ABI::Windows::Devices::WiFiDirect::IWiFiDirectConnectionListener *sender,
                /* [in] */ __RPC__in_opt ABI::Windows::Devices::WiFiDirect::IWiFiDirectConnectionRequestedEventArgs *e) = 0;
            
        };
        """
        # See https://svn.python.org/projects/ctypes/tags/comtypes-0.3.2/docs/com_interfaces.html
        _com_interfaces_ = [
            IAsyncOperation,
            IInspectable,
            IAgileObject,
            ITypedEventHandler_IInspectable_IWiFiDirectConnectionRequestedEventArgs,
        ]
        # XXX Allow passing a callback instead of having to create a class?
        def Invoke(self, this, sender, args):
            logger.info("sender %r args %r", sender, args)
            # hr = args->GetConnectionRequest(request.GetAddressOf());
            request = ctypes.POINTER(IWiFiDirectConnectionRequest)()
            args._IWiFiDirectConnectionRequestedEventArgs__com_GetConnectionRequest(ctypes.byref(request))
            
            # hr = request->get_DeviceInformation(deviceInformation.GetAddressOf());
            deviceInformation = ctypes.POINTER(IDeviceInformation)()
            request._IWiFiDirectConnectionRequest__com__get_DeviceInformation(ctypes.byref(deviceInformation))

            # hr = GetActivationFactory(HStringReference(RuntimeClass_Windows_Devices_WiFiDirect_WiFiDirectDevice).Get(), &wfdStatics);
            wfdStatics = ctypes.POINTER(IWiFiDirectDeviceStatics)()
            RuntimeClass_Windows_Devices_WiFiDirect_WiFiDirectDevice = HString("Windows.Devices.WiFiDirect.WiFiDirectDevice")
            hr = combase.RoGetActivationFactory(
                RuntimeClass_Windows_Devices_WiFiDirect_WiFiDirectDevice, 
                ctypes.byref(IID_IWiFiDirectDeviceStatics), 
                ctypes.byref(wfdStatics)
            )
            check_hresult(hr)

            # hr = deviceInformation->get_Id(deviceId.GetAddressOf());
            deviceId = HSTRING()
            deviceInformation._IDeviceInformation__com__get_Id(ctypes.byref(deviceId))

            # hr = wfdStatics->FromIdAsync(deviceId.Get(), &asyncAction);
            asyncAction = ctypes.POINTER(IAsyncOperation_IWiFiDirectDevice)()
            wfdStatics._IWiFiDirectDeviceStatics__com_FromIdAsync(deviceId, ctypes.byref(asyncAction))

            # hr = asyncAction->put_Completed(Callback<FromIdAsyncHandler>([this](IAsyncOperation<WiFiDirectDevice*>* pHandler, AsyncStatus status) -> HRESULT
            handler = ConnectionAcceptedCompletedHandler().QueryInterface(IAsyncOperationCompletedHandler_WiFiDirectDevice)
            asyncAction._IAsyncOperation_IWiFiDirectDevice__com__set_Completed(handler)

            return comtypes.hresult.S_OK


    combase=ctypes.WinDLL('combase.dll')
    # See https://stackoverflow.com/questions/16466641/how-to-declare-and-link-to-roinitialize-rouninitialize-rogetactivationfactory-an
    # https://learn.microsoft.com/en-us/windows/win32/api/roapi/nf-roapi-roinitialize
    RO_INIT_SINGLETHREADED = 0
    RO_INIT_MULTITHREADED = 1
    hr = combase.RoInitialize(RO_INIT_MULTITHREADED)
    #hr = combase.RoInitialize(RO_INIT_SINGLETHREADED)
    logger.info("RoInitialize %r", hex(hr))

    Windows_Devices_WiFiDirect_WiFiDirectAdvertisementPublisher = HString("Windows.Devices.WiFiDirect.WiFiDirectAdvertisementPublisher")
    inspectable = wintypes.POINTER(IInspectable)()
    hr = combase.RoActivateInstance(
        Windows_Devices_WiFiDirect_WiFiDirectAdvertisementPublisher,
        ctypes.byref(inspectable)
    )
    check_hresult(hr)
    logger.info("RoActivateInstance 0x%x", hr)
    publisher = inspectable.QueryInterface(IWiFiDirectAdvertisementPublisher)
    inspectable.Release()

    # hr = _publisher->add_StatusChanged(
    #   Callback<StatusChangedHandler>([this](IWiFiDirectAdvertisementPublisher* sender, IWiFiDirectAdvertisementPublisherStatusChangedEventArgs* args) -> HRESULT
    status_changed_token = EventRegistrationToken()
    handler = PublisherStatusChangedHandler().QueryInterface(ITypedEventHandler_IInspectable_IWiFiDirectAdvertisementPublisherStatusChangedEventArgs)
    hr = publisher._IWiFiDirectAdvertisementPublisher__com_add_StatusChanged(handler, ctypes.byref(status_changed_token))
    check_hresult(hr)
    logger.info("add_StatusChanged %r %r", hex(hr), status_changed_token)

    
    # hr = _publisher->get_Advertisement(_advertisement.GetAddressOf());
    advertisement = ctypes.POINTER(IWifiDirectAdvertisement)()
    hr = publisher._IWiFiDirectAdvertisementPublisher__com__get_Advertisement(ctypes.byref(advertisement))
    check_hresult(hr)
    logger.info("Advertisement %r", hex(hr))

    hr = advertisement._IWifiDirectAdvertisement__com__set_IsAutonomousGroupOwnerEnabled(True)
    check_hresult(hr)
    logger.info("set_IsAutonomousGroupOwnerEnabled %r", hex(hr))

    # hr = _advertisement->get_LegacySettings(_legacySettings.GetAddressOf());
    legacy_settings = ctypes.POINTER(IWiFiDirectLegacySettings)()
    hr = advertisement._IWifiDirectAdvertisement__com__get_LegacySettings(ctypes.byref(legacy_settings))
    check_hresult(hr)
    logger.info("get_LegacySettings %r", hex(hr))

    # hr = _legacySettings->put_IsEnabled(true);
    enabled = wintypes.BOOL()
    hr = legacy_settings._IWiFiDirectLegacySettings__com__get_IsEnabled(ctypes.byref(enabled))
    check_hresult(hr)
    logger.info("get_IsEnabled %r %r", hex(hr), enabled)
    hr = legacy_settings._IWiFiDirectLegacySettings__com__set_IsEnabled(True)
    check_hresult(hr)
    logger.info("set_IsEnabled %r", hex(hr))
    hr = legacy_settings._IWiFiDirectLegacySettings__com__get_IsEnabled(ctypes.byref(enabled))
    check_hresult(hr)
    logger.info("get_IsEnabled %r %r", hex(hr), enabled)

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
        ssid = HString()
        hr = legacy_settings._IWiFiDirectLegacySettings__com__get_Ssid(ctypes.byref(ssid))
        check_hresult(hr)
        logger.info("get_Ssid %r %r", hex(hr), ssid)

    else:
        hr = legacy_settings._IWiFiDirectLegacySettings__com__set_Ssid(ssid)
        check_hresult(hr)
        logger.info("set_Ssid %r", hex(hr))
        hr = legacy_settings._IWiFiDirectLegacySettings__com__get_Ssid(ctypes.byref(ssid))
        check_hresult(hr)
        logger.info("get_Ssid %r %r", hex(hr), ssid)

    # hr = _legacySettings->get_Passphrase(passwordCredential.GetAddressOf());
    password_credential = ctypes.POINTER(IPasswordCredential)()
    hr = legacy_settings._IWiFiDirectLegacySettings__com__get_Passphrase(ctypes.byref(password_credential))
    check_hresult(hr)
    logger.info("get_Passphrase %r", hex(hr))

    # hr = passwordCredential->put_Password(hstrPassphrase.Get());
    
    if (password is None):
        password = HString()
        hr = password_credential._IPasswordCredential__com__get_Password(ctypes.byref(password))
        check_hresult(hr)
        logger.info("get_Password %r %r", hex(hr), password)
    
    else:
        hr = password_credential._IPasswordCredential__com__set_Password(password)
        check_hresult(hr)
        logger.info("set_Password %r %r", hex(hr), password)
        hr = password_credential._IPasswordCredential__com__get_Password(ctypes.byref(password))
        check_hresult(hr)
        logger.info("get_Password %r %r", hex(hr), password)

    def start_listener():
        logger.info("start_listener")
        # hr = Windows::Foundation::ActivateInstance(HStringReference(RuntimeClass_Windows_Devices_WiFiDirect_WiFiDirectConnectionListener).Get(), &_connectionListener);
        connection_listener = wintypes.POINTER(IWiFiDirectConnectionListener)()
        Windows_Devices_WiFiDirect_WiFiDirectConnectionListener = HString("Windows.Devices.WiFiDirect.WiFiDirectConnectionListener")
        inspectable = wintypes.POINTER(IInspectable)()
        hr = combase.RoActivateInstance(
            Windows_Devices_WiFiDirect_WiFiDirectConnectionListener,
            ctypes.byref(inspectable)
        )
        logger.info("RoActivateInstance %r", hex(hr))

        connection_listener = inspectable.QueryInterface(IWiFiDirectConnectionListener)
        inspectable.Release()

        listener_token = EventRegistrationToken()
        handler = ConnectionRequestedHandler().QueryInterface(ITypedEventHandler_IInspectable_IWiFiDirectConnectionRequestedEventArgs)
        hr = connection_listener._IWiFiDirectConnectionListener__com_add_ConnectionRequested(handler, ctypes.byref(listener_token))
        check_hresult(hr)
        logger.info("add_ConnectionRequested %r %r", hex(hr), listener_token)

        # Local variable going out of scope will call __del__ and cause
        # Release(), so AddRef 
        # XXX Is there a way so comtypes doesn't Release local variables when
        #     they are returned from the function?
        connection_listener.AddRef()
        return connection_listener, listener_token

    # hr = _publisher->Start();
    # This causes a QuerInterface for ITypedEventHandler {DE73CBA7-370D-550C-B23A-53DD0B4E480D}
    # on IAsyncOperationCompletedHandler_Impl
    logger.info("Starting publisher")
    hr = publisher.Start()
    check_hresult(hr)
    logger.info("Started publisher %r", hex(hr))

    import time
    logger.info("Sleeping")
    time.sleep(1)

    connection_listener, listener_token = start_listener()

    try:
        while (True):
            print "Sleeping forever, ssid '%s' password '%s' press ctrl+c to finish" % (ssid, password)
            time.sleep(60*500)
    finally:
        logger.info("Stopping listener")
        hr = connection_listener._IWiFiDirectConnectionListener__com_remove_ConnectionRequested(listener_token)
        check_hresult(hr)
        logger.info("Removed ConnectionRequested %r %r", hex(hr), listener_token)
        
        logger.info("Stopping publisher")
        hr = publisher.Stop()
        check_hresult(hr)
        logger.info("Stopped publisher %r", hex(hr))

        publisher._IWiFiDirectAdvertisementPublisher__com_remove_StatusChanged(status_changed_token)
        logger.info("Removed StatusChanged %r", status_changed_token)


if (__name__ == "__main__"):
    comtypes_logger.setLevel(logging.WARNING)
    logger.setLevel(logging.WARNING)

    #write_python_from_idls()
    winrt_wifi()

