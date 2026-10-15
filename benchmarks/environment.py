"""Read-only hardware metadata, collected outside benchmark timing."""
import ctypes
import os
import platform


def hardware():
    cpu = platform.processor() or None
    memory = None
    if os.name == 'nt':
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r'HARDWARE\DESCRIPTION\System\CentralProcessor\0') as key:
                cpu = winreg.QueryValueEx(key, 'ProcessorNameString')[0].strip()
        except OSError:
            pass

        class MemoryStatus(ctypes.Structure):
            _fields_ = [('length', ctypes.c_ulong), ('load', ctypes.c_ulong),
                        ('total_physical', ctypes.c_ulonglong),
                        ('available_physical', ctypes.c_ulonglong),
                        ('total_pagefile', ctypes.c_ulonglong),
                        ('available_pagefile', ctypes.c_ulonglong),
                        ('total_virtual', ctypes.c_ulonglong),
                        ('available_virtual', ctypes.c_ulonglong),
                        ('available_extended_virtual', ctypes.c_ulonglong)]

        status = MemoryStatus()
        status.length = ctypes.sizeof(status)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            memory = status.total_physical
    elif hasattr(os, 'sysconf'):
        try:
            memory = os.sysconf('SC_PHYS_PAGES') * os.sysconf('SC_PAGE_SIZE')
        except (OSError, ValueError):
            pass
    return dict(cpu_model=cpu, logical_cpus=os.cpu_count(),
                architecture=platform.machine(), physical_memory_bytes=memory)
