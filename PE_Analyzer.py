import pefile
import struct
import sys
import os

class PEAnalyzer:
    def __init__(self, filepath, base_address=None, auto_detect_base=False):
        self.filepath = filepath
        self.pe = pefile.PE(filepath, fast_load=False)
        self.original_image_base = self.pe.OPTIONAL_HEADER.ImageBase
        self.is_64bit = self.pe.FILE_HEADER.Machine == 0x8664
        
        # Auto-detect base address if requested or if not provided
        if auto_detect_base or base_address is None:
            self.base = self._auto_detect_base()
            self.base_auto_detected = True
        else:
            self.base = base_address
            self.base_auto_detected = False
    
    def _auto_detect_base(self):
        # Use ImageBase from PE header as default
        detected_base = self.original_image_base
        
        # Try to find actual loaded base if possible (for loaded modules)
        # This is the standard ImageBase from PE header
        return detected_base
    
    def _get_api_signatures(self):
        return {
            'WriteProcessMemory': {
                'return_type': 'BOOL',
                'parameters': [
                    {'name': 'hProcess', 'type': 'HANDLE', 'direction': 'in', 'description': 'Process handle (0xFFFFFFFF = current process)'},
                    {'name': 'lpBaseAddress', 'type': 'LPVOID', 'direction': 'in', 'description': 'Destination address to write to'},
                    {'name': 'lpBuffer', 'type': 'LPCVOID', 'direction': 'in', 'description': 'Source buffer address'},
                    {'name': 'nSize', 'type': 'SIZE_T', 'direction': 'in', 'description': 'Number of bytes to write'},
                    {'name': 'lpNumberOfBytesWritten', 'type': 'SIZE_T*', 'direction': 'out', 'description': 'Pointer to writable memory for bytes written count'}
                ],
                'dll': 'kernel32.dll',
                'calling_convention': 'stdcall'
            },
            'VirtualAlloc': {
                'return_type': 'LPVOID',
                'parameters': [
                    {'name': 'lpAddress', 'type': 'LPVOID', 'direction': 'in', 'description': 'Desired starting address (NULL = auto)'},
                    {'name': 'dwSize', 'type': 'SIZE_T', 'direction': 'in', 'description': 'Size of allocation in bytes'},
                    {'name': 'flAllocationType', 'type': 'DWORD', 'direction': 'in', 'description': 'MEM_COMMIT (0x1000) | MEM_RESERVE (0x2000)'},
                    {'name': 'flProtect', 'type': 'DWORD', 'direction': 'in', 'description': 'PAGE_EXECUTE_READWRITE (0x40)'}
                ],
                'dll': 'kernel32.dll',
                'calling_convention': 'stdcall'
            },
            'VirtualProtect': {
                'return_type': 'BOOL',
                'parameters': [
                    {'name': 'lpAddress', 'type': 'LPVOID', 'direction': 'in', 'description': 'Address to change protection'},
                    {'name': 'dwSize', 'type': 'SIZE_T', 'direction': 'in', 'description': 'Size of memory region'},
                    {'name': 'flNewProtect', 'type': 'DWORD', 'direction': 'in', 'description': 'PAGE_EXECUTE_READWRITE (0x40)'},
                    {'name': 'lpflOldProtect', 'type': 'PDWORD', 'direction': 'out', 'description': 'Pointer to writable memory for old protection'}
                ],
                'dll': 'kernel32.dll',
                'calling_convention': 'stdcall'
            },
            'VirtualProtectEx': {
                'return_type': 'BOOL',
                'parameters': [
                    {'name': 'hProcess', 'type': 'HANDLE', 'direction': 'in', 'description': 'Process handle'},
                    {'name': 'lpAddress', 'type': 'LPVOID', 'direction': 'in', 'description': 'Address to change protection'},
                    {'name': 'dwSize', 'type': 'SIZE_T', 'direction': 'in', 'description': 'Size of memory region'},
                    {'name': 'flNewProtect', 'type': 'DWORD', 'direction': 'in', 'description': 'PAGE_EXECUTE_READWRITE (0x40)'},
                    {'name': 'lpflOldProtect', 'type': 'PDWORD', 'direction': 'out', 'description': 'Pointer to writable memory for old protection'}
                ],
                'dll': 'kernel32.dll',
                'calling_convention': 'stdcall'
            },
            'VirtualAllocEx': {
                'return_type': 'LPVOID',
                'parameters': [
                    {'name': 'hProcess', 'type': 'HANDLE', 'direction': 'in', 'description': 'Process handle'},
                    {'name': 'lpAddress', 'type': 'LPVOID', 'direction': 'in', 'description': 'Desired starting address (NULL = auto)'},
                    {'name': 'dwSize', 'type': 'SIZE_T', 'direction': 'in', 'description': 'Size of allocation in bytes'},
                    {'name': 'flAllocationType', 'type': 'DWORD', 'direction': 'in', 'description': 'MEM_COMMIT (0x1000) | MEM_RESERVE (0x2000)'},
                    {'name': 'flProtect', 'type': 'DWORD', 'direction': 'in', 'description': 'PAGE_EXECUTE_READWRITE (0x40)'}
                ],
                'dll': 'kernel32.dll',
                'calling_convention': 'stdcall'
            },
            'ReadProcessMemory': {
                'return_type': 'BOOL',
                'parameters': [
                    {'name': 'hProcess', 'type': 'HANDLE', 'direction': 'in', 'description': 'Process handle'},
                    {'name': 'lpBaseAddress', 'type': 'LPCVOID', 'direction': 'in', 'description': 'Source address to read from'},
                    {'name': 'lpBuffer', 'type': 'LPVOID', 'direction': 'out', 'description': 'Destination buffer address'},
                    {'name': 'nSize', 'type': 'SIZE_T', 'direction': 'in', 'description': 'Number of bytes to read'},
                    {'name': 'lpNumberOfBytesRead', 'type': 'SIZE_T*', 'direction': 'out', 'description': 'Pointer to writable memory for bytes read count'}
                ],
                'dll': 'kernel32.dll',
                'calling_convention': 'stdcall'
            },
            'HeapCreate': {
                'return_type': 'HANDLE',
                'parameters': [
                    {'name': 'flOptions', 'type': 'DWORD', 'direction': 'in', 'description': 'Heap options'},
                    {'name': 'dwInitialSize', 'type': 'SIZE_T', 'direction': 'in', 'description': 'Initial heap size'},
                    {'name': 'dwMaximumSize', 'type': 'SIZE_T', 'direction': 'in', 'description': 'Maximum heap size'}
                ],
                'dll': 'kernel32.dll',
                'calling_convention': 'stdcall'
            },
            'SetProcessDEPPolicy': {
                'return_type': 'BOOL',
                'parameters': [
                    {'name': 'dwFlags', 'type': 'DWORD', 'direction': 'in', 'description': 'DEP policy flags'}
                ],
                'dll': 'kernel32.dll',
                'calling_convention': 'stdcall'
            }
        }
        
    def _parse_iat_manual(self):
        entries = []
        
        try:
            # Get Import Directory RVA and Size
            import_dir = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']]
            import_rva = import_dir.VirtualAddress
            import_size = import_dir.Size
            
            if import_rva == 0 or import_size == 0:
                return entries
            
            # Read raw data
            import_data = self.pe.get_data(import_rva, import_size)
            if not import_data:
                return entries
            
            # IMAGE_IMPORT_DESCRIPTOR structure (20 bytes)
            struct_size = 20
            descriptor_idx = 0
            
            while descriptor_idx * struct_size < len(import_data) - struct_size:
                # Read IMAGE_IMPORT_DESCRIPTOR
                desc_data = import_data[descriptor_idx * struct_size:(descriptor_idx + 1) * struct_size]
                if len(desc_data) < struct_size:
                    break
                
                # Unpack: OriginalFirstThunk(4), TimeDateStamp(4), ForwarderChain(4), Name(4), FirstThunk(4)
                original_first_thunk, _, _, name_rva, first_thunk = struct.unpack('<IIIII', desc_data)
                
                # Check for null descriptor (end marker)
                if original_first_thunk == 0 and first_thunk == 0:
                    break
                
                # Get DLL name
                if name_rva == 0:
                    descriptor_idx += 1
                    continue
                
                try:
                    # Get string from RVA
                    name_data = self.pe.get_data(name_rva, 260)  # Max DLL name length
                    if name_data:
                        null_idx = name_data.find(b'\x00')
                        if null_idx > 0:
                            name_data = name_data[:null_idx]
                        dll_name = name_data.decode('utf-8', errors='ignore')
                    else:
                        descriptor_idx += 1
                        continue
                except:
                    descriptor_idx += 1
                    continue
                
                # Use OriginalFirstThunk to get function names, FirstThunk for IAT addresses
                # FirstThunk points to IAT (runtime addresses)
                # OriginalFirstThunk points to import names/ordinals
                
                lookup_rva = original_first_thunk if original_first_thunk else first_thunk
                iat_rva = first_thunk
                
                if iat_rva == 0 or lookup_rva == 0:
                    descriptor_idx += 1
                    continue
                
                # Read thunks until null
                thunk_size = 8 if self.is_64bit else 4
                thunk_idx = 0
                
                while True:
                    try:
                        lookup_addr = lookup_rva + (thunk_idx * thunk_size)
                        iat_addr = iat_rva + (thunk_idx * thunk_size)
                        
                        # Read thunk value
                        thunk_data = self.pe.get_data(lookup_addr, thunk_size)
                        if not thunk_data or len(thunk_data) < thunk_size:
                            break
                        
                        if self.is_64bit:
                            thunk_val = struct.unpack('<Q', thunk_data)[0]
                        else:
                            thunk_val = struct.unpack('<I', thunk_data)[0]
                        
                        if thunk_val == 0:
                            break
                        
                        # Check if it's ordinal or name import
                        ordinal_mask = 0x8000000000000000 if self.is_64bit else 0x80000000
                        if thunk_val & ordinal_mask:
                            # Ordinal import
                            ordinal = thunk_val & 0xFFFF
                            func_name = f"Ordinal_{ordinal}"
                        else:
                            # Name import
                            hint_name_rva = thunk_val & 0xFFFFFFFF
                            try:
                                # Read IMAGE_IMPORT_BY_NAME: Hint(2) + Name(string)
                                hint_name_data = self.pe.get_data(hint_name_rva, 260)  # Max reasonable length
                                if hint_name_data and len(hint_name_data) >= 2:
                                    # Skip hint, get function name
                                    func_name_bytes = hint_name_data[2:]
                                    null_idx = func_name_bytes.find(b'\x00')
                                    if null_idx > 0:
                                        func_name_bytes = func_name_bytes[:null_idx]
                                    func_name = func_name_bytes.decode('utf-8', errors='ignore')
                                else:
                                    func_name = f"Unknown_{thunk_idx}"
                            except:
                                func_name = f"Unknown_{thunk_idx}"
                        
                        # Calculate IAT address
                        iat_entry_va = self.base + iat_addr
                        
                        entries.append({
                            'dll': dll_name,
                            'function': func_name,
                            'iat_rva': iat_addr,
                            'iat_va': iat_entry_va
                        })
                        
                        thunk_idx += 1
                    except:
                        break
                
                descriptor_idx += 1
                    
        except Exception as e:
            pass  # Silent fail, will use standard method
        
        return entries
    
    def get_iat_entries(self):
        entries = []
        
        # Try standard method first
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT') and self.pe.DIRECTORY_ENTRY_IMPORT:
            for dll in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = dll.dll.decode('utf-8')
                
                for imp in dll.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8')
                    else:
                        func_name = f"Ordinal_{imp.ordinal}"
                    
                    iat_rva = imp.address - self.pe.OPTIONAL_HEADER.ImageBase
                    iat_va = self.base + iat_rva
                    
                    entries.append({
                        'dll': dll_name,
                        'function': func_name,
                        'iat_rva': iat_rva,
                        'iat_va': iat_va
                    })
        else:
            # Fallback to manual parsing
            entries = self._parse_iat_manual()
        
        return entries
    
    def _find_api_stubs_in_code(self, api_names):
        stubs = []
        
        target_apis = [name.lower() for name in api_names]
        
        # Get IAT entries first
        iat_entries = self.get_iat_entries()
        iat_addresses = {entry['iat_va']: entry for entry in iat_entries}
        
        # Scan executable sections
        for section in self.pe.sections:
            if not (section.Characteristics & 0x20000000):  # Not executable
                continue
            
            section_name = section.Name.decode('utf-8').rstrip('\x00')
            section_start = self.base + section.VirtualAddress
            data = section.get_data()
            
            # Look for call/jmp instructions to IAT addresses
            # Pattern: FF 15/25 (call/jmp dword ptr [addr]) for x86
            # Pattern: FF 15/25 (call/jmp qword ptr [rip+offset]) for x64
            for i in range(len(data) - 6):
                # Call via IAT: FF 15 [IAT_ADDR] (x86)
                # FF 25 = jmp dword ptr [addr] (x86)
                if data[i] == 0xFF and data[i+1] in [0x15, 0x25]:
                    try:
                        if self.is_64bit:
                            # x64: FF 15 [rel32] - relative addressing
                            if i + 6 <= len(data):
                                rel32 = struct.unpack('<i', data[i+2:i+6])[0]
                                instruction_end = section_start + i + 6
                                target_va = instruction_end + rel32
                        else:
                            # x86: FF 15 [abs32] - absolute addressing
                            if i + 6 <= len(data):
                                target_va = struct.unpack('<I', data[i+2:i+6])[0]
                        
                        # Check if this points to IAT
                        if target_va in iat_addresses:
                            entry = iat_addresses[target_va]
                            func_name_lower = entry['function'].lower()
                            
                            if any(api.lower() in func_name_lower for api in target_apis):
                                stub_addr = section_start + i
                                stubs.append({
                                    'function': entry['function'],
                                    'dll': entry['dll'],
                                    'stub_address': stub_addr,
                                    'stub_rva': section.VirtualAddress + i,
                                    'iat_address': entry['iat_va'],
                                    'iat_rva': entry['iat_rva'],
                                    'instruction_type': 'call' if data[i+1] == 0x15 else 'jmp',
                                    'section': section_name
                                })
                    except:
                        pass  # Skip invalid instructions
        
        return stubs
    
    def find_dep_bypass_functions(self):        
        dep_functions = [
            'VirtualProtect',
            'VirtualAlloc',
            'WriteProcessMemory',
            'HeapCreate',
            'SetProcessDEPPolicy',
            'NtSetInformationProcess',
            'VirtualProtectEx',
            'memcpy',
            'memmove'
        ]
        
        found = []
        entries = self.get_iat_entries()
        
        for func in dep_functions:
            for entry in entries:
                if func.lower() in entry['function'].lower():
                    found.append(entry)
        
        # Also search for stubs in code
        stubs = self._find_api_stubs_in_code(dep_functions)
        for stub in stubs:
            # Check if not already added
            if not any(f['function'] == stub['function'] and f['iat_va'] == stub['iat_address'] for f in found):
                found.append({
                    'dll': stub['dll'],
                    'function': stub['function'],
                    'iat_rva': stub['iat_rva'],
                    'iat_va': stub['iat_address'],
                    'stub_address': stub['stub_address'],
                    'stub_rva': stub['stub_rva']
                })
        
        return found
    
    def get_api_info_for_exploit(self, api_name):
        api_name_lower = api_name.lower()
        
        result = {
            'api_name': api_name,
            'found': False,
            'iat_entry': None,
            'stubs': [],
            'rop_info': {},
            'signature': None
        }
        
        # Get API signature
        api_sigs = self._get_api_signatures()
        if api_name in api_sigs:
            result['signature'] = api_sigs[api_name]
        
        # Search in IAT
        entries = self.get_iat_entries()
        for entry in entries:
            if api_name_lower in entry['function'].lower():
                result['found'] = True
                result['iat_entry'] = entry
                break
        
        # Search for stubs
        stubs = self._find_api_stubs_in_code([api_name])
        result['stubs'] = [s for s in stubs if api_name_lower in s['function'].lower()]
        
        if result['found']:
            iat = result['iat_entry']
            result['rop_info'] = {
                'function_ptr': iat['iat_va'],
                'function_ptr_rva': iat['iat_rva'],
                'function_name': iat['function'],
                'dll': iat['dll'],
                'base_address': self.base,
                'offset_from_base': iat['iat_va'] - self.base
            }
        
        return result
    
    def get_writable_addresses_for_out_params(self, count=5):
        writable_addresses = []
        
        for section in self.pe.sections:
            section_name = section.Name.decode('utf-8').rstrip('\x00')
            
            # Check if section is writable
            is_writable = section.Characteristics & 0x80000000  # IMAGE_SCN_MEM_WRITE
            is_readable = section.Characteristics & 0x40000000   # IMAGE_SCN_MEM_READ
            
            if not is_writable or not is_readable:
                continue
            
            section_start = self.base + section.VirtualAddress
            section_size = section.Misc_VirtualSize
            data = section.get_data()
            
            # Find addresses with zeros (unused space) - good for out parameters
            # We need at least 4 bytes for a DWORD
            min_size = 4
            found_count = 0
            
            # Check first 1KB of section for safe addresses
            check_size = min(len(data), 1024)
            
            for i in range(0, check_size - min_size, 4):  # Align to 4 bytes
                # Check if this area is all zeros (safe to use)
                area = data[i:i+min_size]
                if all(b == 0 for b in area):
                    addr = section_start + i
                    writable_addresses.append({
                        'address': addr,
                        'rva': section.VirtualAddress + i,
                        'section': section_name,
                        'offset_in_section': i,
                        'size_available': self._count_consecutive_zeros(data, i),
                        'virtual_size': section_size,
                        'raw_size': section.SizeOfRawData
                    })
                    found_count += 1
                    if found_count >= count:
                        break
            
            if len(writable_addresses) >= count:
                break
        
        return writable_addresses[:count]
    
    def _count_consecutive_zeros(self, data, start_index):
        count = 0
        for i in range(start_index, len(data)):
            if data[i] == 0:
                count += 1
            else:
                break
        return count
    
    def print_api_full_info(self, api_name):
        info = self.get_api_info_for_exploit(api_name)
        
        print(f"\n{'='*70}")
        print(f"API: {api_name.upper()}")
        print(f"{'='*70}")
        
        if not info['found']:
            print(f"[!] {api_name} NOT FOUND in IAT")
            return
        
        # Print signature
        if info['signature']:
            sig = info['signature']
            print(f"\n[FUNCTION SIGNATURE]")
            print(f"Return Type: {sig['return_type']}")
            print(f"DLL: {sig['dll']}")
            print(f"Calling Convention: {sig['calling_convention']}")
            
            print(f"\n[PARAMETERS]")
            param_num = 1
            out_params = []  # Track out parameters
            for param in sig['parameters']:
                is_out = param['direction'] == 'out' or '*' in param['type']
                print(f"  [{param_num}] {param['name']:<25} {param['type']:<15} [{param['direction']:>3}]")
                print(f"      Description: {param['description']}")
                if is_out:
                    out_params.append(param)
                param_num += 1
        
        # Print IAT info
        if info['rop_info']:
            rop = info['rop_info']
            print(f"\n[IAT INFORMATION]")
            print(f"  Function Ptr (VA):   0x{rop['function_ptr']:08X}")
            print(f"  Function Ptr (RVA):  0x{rop['function_ptr_rva']:08X}")
            print(f"  Offset from Base:    0x{rop['offset_from_base']:08X}")
            print(f"  Base Address:        0x{rop['base_address']:08X}")
            print(f"  DLL:                 {rop['dll']}")
        
        # Print stubs
        if info['stubs']:
            print(f"\n[STUBS FOUND: {len(info['stubs'])}]")
            for i, stub in enumerate(info['stubs'][:5], 1):  # Show first 5
                print(f"  [{i}] Address: 0x{stub['stub_address']:08X} | Type: {stub['instruction_type']} | Section: {stub['section']}")
        
        # Get code caves for Return address and lpBaseAddress
        code_caves = self.find_code_caves(min_size=100)
        exec_caves = [c for c in code_caves if 'X' in c['permissions']]  # Executable caves
        if exec_caves:
            exec_caves.sort(key=lambda x: x['size'], reverse=True)  # Sort by size, largest first
        
        # Print code caves for shellcode injection
        if exec_caves:
            print(f"\n[CODE CAVES FOR RETURN ADDRESS & lpBaseAddress]")
            print(f"  These are executable code caves suitable for shellcode injection")
            print(f"  Use them for Return address (where to jump after API call) and lpBaseAddress (where to write)")
            print(f"")
            for i, cave in enumerate(exec_caves[:5], 1):  # Show top 5
                print(f"  [{i}] Address: 0x{cave['address']:08X} | Size: {cave['size']} bytes | Section: {cave['section']}")
            if exec_caves:
                print(f"\n  [!] RECOMMENDATION: Use first cave (0x{exec_caves[0]['address']:08X})")
                print(f"      - For Return address: Jump here after API call")
                print(f"      - For lpBaseAddress: Write shellcode here")
                print(f"      - Verify with: !vprot 0x{exec_caves[0]['address']:08X}")
        else:
            print(f"\n[!] WARNING: No executable code caves found (min 100 bytes)")
            print(f"    You may need to use VirtualAlloc to allocate executable memory")
        
        # Print writable addresses for out parameters
        if out_params:
            writable_addrs = self.get_writable_addresses_for_out_params(count=5)
            if writable_addrs:
                print(f"\n[WRITABLE ADDRESSES FOR OUT PARAMETERS]")
                print(f"  These addresses can be used for out parameters (e.g., lpNumberOfBytesWritten, lpflOldProtect)")
                print(f"  All addresses are in writable sections and contain zeros (safe to use)")
                print(f"")
                for i, addr_info in enumerate(writable_addrs, 1):
                    print(f"  [{i}] Address: 0x{addr_info['address']:08X} (RVA: 0x{addr_info['rva']:08X})")
                    print(f"      Section: {addr_info['section']}")
                    print(f"      Size Available: {addr_info['size_available']} bytes")
                    print(f"      Section Size: 0x{addr_info['virtual_size']:08X} bytes")
                print(f"\n  [!] RECOMMENDATION: Use first address (0x{writable_addrs[0]['address']:08X})")
                print(f"      Verify the address content is not being used at runtime")
                print(f"      Check memory protections with: !vprot 0x{writable_addrs[0]['address']:08X}")
            else:
                print(f"\n[!] WARNING: No writable sections found for out parameters")
                print(f"    You may need to use stack addresses or allocate memory")
        
        # Print ROP stack layout with recommendations
        if info['signature']:
            print(f"\n[ROP STACK LAYOUT]")
            print(f"  [0] {api_name} pointer (IAT)        = 0x{info['rop_info']['function_ptr']:08X}")
            
            # Use best executable code cave for return address
            best_cave = exec_caves[0] if exec_caves else None
            if best_cave:
                print(f"  [1] Return address                  = 0x{best_cave['address']:08X}  [CODE CAVE]")
            else:
                print(f"  [1] Return address                  = <return_addr>")
            
            param_offset = 2
            writable_addrs = self.get_writable_addresses_for_out_params(count=1)
            out_param_idx = 0
            
            # Track if we need lpBaseAddress (for WriteProcessMemory)
            needs_base_address = api_name.lower() in ['writeprocessmemory', 'virtualprotect']
            base_address_used = False
            
            for param in info['signature']['parameters']:
                param_name_lower = param['name'].lower()
                is_out = param['direction'] == 'out' or '*' in param['type']
                
                # Check if this is lpBaseAddress and we have a code cave
                if (param_name_lower in ['lpbaseaddress', 'lpaddress'] and 
                    needs_base_address and best_cave and not base_address_used):
                    print(f"  [{param_offset}] {param['name']:<25} = 0x{best_cave['address']:08X}  [CODE CAVE]")
                    base_address_used = True
                elif is_out and writable_addrs and out_param_idx < len(writable_addrs):
                    recommended_addr = writable_addrs[out_param_idx]['address']
                    print(f"  [{param_offset}] {param['name']:<25} = 0x{recommended_addr:08X}  [RECOMMENDED]")
                    out_param_idx += 1
                else:
                    print(f"  [{param_offset}] {param['name']:<25} = <{param['name']}>")
                param_offset += 1
    
    def get_sections(self):
        sections = []
        
        for section in self.pe.sections:
            name = section.Name.decode('utf-8').rstrip('\x00')
            
            perms = ""
            if section.Characteristics & 0x40000000: perms += "R"
            if section.Characteristics & 0x80000000: perms += "W"
            if section.Characteristics & 0x20000000: perms += "X"
            
            sections.append({
                'name': name,
                'virtual_address': self.base + section.VirtualAddress,
                'virtual_size': section.Misc_VirtualSize,
                'raw_size': section.SizeOfRawData,
                'permissions': perms
            })
        
        return sections
    
    def find_code_caves(self, min_size=100):
        caves = []
        
        for section in self.pe.sections:
            section_name = section.Name.decode('utf-8').rstrip('\x00')
            section_start = self.base + section.VirtualAddress
            data = section.get_data()
            
            perms = ""
            if section.Characteristics & 0x40000000: perms += "R"
            if section.Characteristics & 0x80000000: perms += "W"
            if section.Characteristics & 0x20000000: perms += "X"
            
            cave_start = None
            cave_length = 0
            
            for i, byte in enumerate(data):
                if byte == 0:
                    if cave_start is None:
                        cave_start = i
                    cave_length += 1
                else:
                    if cave_length >= min_size:
                        caves.append({
                            'address': section_start + cave_start,
                            'size': cave_length,
                            'section': section_name,
                            'permissions': perms
                        })
                    cave_start = None
                    cave_length = 0
            
            if cave_length >= min_size:
                caves.append({
                    'address': section_start + cave_start,
                    'size': cave_length,
                    'section': section_name,
                    'permissions': perms
                })
        
        return caves
    
    def generate_report(self, min_cave_size=100):        
        print("=" * 70)
        print(f"PE ANALYSIS REPORT: {os.path.basename(self.filepath)}")
        print("=" * 70)
        
        # Basic info
        base_info = f"0x{self.base:08X}"
        if self.base_auto_detected:
            base_info += " (Auto-detected from PE ImageBase)"
        if self.base != self.original_image_base:
            base_info += f" [Original: 0x{self.original_image_base:08X}]"
        
        print(f"\n[*] Base Address: {base_info}")
        print(f"[*] Entry Point:  0x{self.base + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint:08X}")
        print(f"[*] Architecture: {'x64' if self.is_64bit else 'x86'}")
        
        # Sections
        print("\n" + "-" * 70)
        print("SECTIONS")
        print("-" * 70)
        print(f"{'Name':<10} {'Address':<12} {'VirtSize':<12} {'RawSize':<12} {'Perms':<6}")
        print("-" * 70)
        
        for sec in self.get_sections():
            print(f"{sec['name']:<10} 0x{sec['virtual_address']:08X} "
                  f"0x{sec['virtual_size']:08X} 0x{sec['raw_size']:08X} {sec['permissions']:<6}")
        
        # DEP Bypass Functions
        print("\n" + "-" * 70)
        print("DEP BYPASS FUNCTIONS & API STUBS")
        print("-" * 70)
        
        dep_funcs = self.find_dep_bypass_functions()
        if dep_funcs:
            print(f"{'Function':<25} {'IAT Address':<14} {'Stub Addr':<12} {'DLL':<20}")
            print("-" * 70)
            for func in dep_funcs:
                stub_info = ""
                if 'stub_address' in func:
                    stub_info = f"0x{func['stub_address']:08X}"
                else:
                    stub_info = "N/A"
                print(f"{func['function']:<25} 0x{func['iat_va']:08X} {stub_info:<12} {func['dll']:<20}")
        else:
            print("No DEP bypass functions found in IAT")
        
        # Critical APIs for Exploitation - FULL DETAILS
        print("\n" + "=" * 70)
        print("CRITICAL API INFORMATION FOR ROP/EXPLOIT")
        print("=" * 70)
        
        critical_apis = ['WriteProcessMemory', 'VirtualAlloc', 'VirtualProtect']
        for api in critical_apis:
            self.print_api_full_info(api)
        
        # Code Caves
        print("\n" + "-" * 70)
        print(f"CODE CAVES (min {min_cave_size} bytes)")
        print("-" * 70)
        
        caves = self.find_code_caves(min_cave_size)
        if caves:
            # Sort by size
            caves.sort(key=lambda x: x['size'], reverse=True)
            
            print(f"{'Address':<14} {'Size':<10} {'Section':<10} {'Perms':<6}")
            print("-" * 70)
            for cave in caves[:10]:  # Top 10
                print(f"0x{cave['address']:08X}   {cave['size']:<10} "
                      f"{cave['section']:<10} {cave['permissions']:<6}")
            
            # Recommend best for shellcode
            exec_caves = [c for c in caves if 'X' in c['permissions']]
            if exec_caves:
                best = exec_caves[0]
                print(f"\n[RECOMMENDED] Best executable cave:")
                print(f"    Address: 0x{best['address']:08X}")
                print(f"    Size:    {best['size']} bytes")
                print(f"    Section: {best['section']}")
        else:
            print(f"No caves >= {min_cave_size} bytes found")
        
        # Full IAT
        print("\n" + "-" * 70)
        print("COMPLETE IAT LISTING")
        print("-" * 70)
        
        entries = self.get_iat_entries()
        current_dll = ""
        for entry in entries:
            if entry['dll'] != current_dll:
                current_dll = entry['dll']
                print(f"\n[{current_dll}]")
            print(f"    0x{entry['iat_va']:08X}  {entry['function']}")
        
        print("\n" + "=" * 70)
        print("END OF REPORT")
        print("=" * 70)
    
    def close(self):
        self.pe.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python PE_Analyzer.py <module.dll|exe> [base_address] [min_cave_size]")
        print("")
        print("Arguments:")
        print("  module.dll|exe  - PE file to analyze (required)")
        print("  base_address    - Base address in hex (optional, auto-detected from PE if not provided)")
        print("  min_cave_size   - Minimum code cave size in bytes (optional, default: 400)")
        print("")
        print("Examples:")
        print("  python PE_Analyzer.py module.dll                    # Auto-detect base address")
        print("  python PE_Analyzer.py module.dll 0x63100000         # Use custom base address")
        print("  python PE_Analyzer.py module.dll 0x63100000 500     # Custom base + min cave size")
        sys.exit(1)
    
    filepath = sys.argv[1]
    
    # Parse base address (optional)
    base = None
    min_cave = 400
    if len(sys.argv) > 2:
        try:
            base = int(sys.argv[2], 16)
        except ValueError:
            # If not hex, might be min_cave_size as second argument
            try:
                min_cave = int(sys.argv[2])
                base = None
            except ValueError:
                print(f"[!] Invalid base address or min_cave_size: {sys.argv[2]}")
                sys.exit(1)
    
    # Parse min_cave_size (optional)
    if len(sys.argv) > 3:
        try:
            min_cave = int(sys.argv[3])
        except ValueError:
            print(f"[!] Invalid min_cave_size: {sys.argv[3]}")
            sys.exit(1)
    
    # Create analyzer with auto-detection if base not provided
    analyzer = PEAnalyzer(filepath, base, auto_detect_base=(base is None))
    analyzer.generate_report(min_cave)
    analyzer.close()
