# PE_Analyzer
A powerful Python tool for analyzing PE (Portable Executable) files with focus on exploit development, ROP chain building, and security research. Automatically detects IAT entries, finds API stubs, code caves, and provides comprehensive information for Windows API exploitation.

## Features

### **Advanced IAT Analysis**
- Automatic IAT parsing using standard methods
- **Manual IAT parsing** when `DIRECTORY_ENTRY_IMPORT` is unavailable
- Support for both x86 and x64 architectures
- Complete IAT listing with Virtual Addresses (VA) and Relative Virtual Addresses (RVA)

### **API Information for Exploitation**
- **Complete API signatures** with full parameter details
- **ROP stack layout** generation with recommended addresses
- **API stub detection** in executable sections
- Automatic detection of critical APIs:
  - `WriteProcessMemory`
  - `VirtualAlloc`
  - `VirtualProtect`
  - `VirtualAllocEx`
  - `VirtualProtectEx`
  - `ReadProcessMemory`
  - `HeapCreate`
  - `SetProcessDEPPolicy`

### **Code Cave Detection**
- Finds executable code caves suitable for shellcode injection
- Automatic size filtering
- Permission analysis (Read/Write/Execute)
- Recommendations for best caves

### **Writable Addresses for Out Parameters**
- Automatically finds writable data sections
- Identifies safe addresses (containing zeros) for out parameters
- Perfect for APIs like `WriteProcessMemory` and `VirtualProtect`
- Recommendations included in ROP stack layout

### **Comprehensive Reports**
- Detailed section information
- DEP bypass function detection
- Complete parameter information with descriptions
- Ready-to-use addresses for ROP chains

## Requirements

```bash
pip install pefile
```

## Installation

```bash
git clone https://github.com/yourusername/PE_Analyzer.git
cd PE_Analyzer
```

## Usage

### Basic Usage (Auto-detect Base Address)

```bash
python PE_Analyzer.py module.dll
```

### Custom Base Address

```bash
python PE_Analyzer.py module.dll 0x63100000
```

### Custom Base Address and Minimum Code Cave Size

```bash
python PE_Analyzer.py module.dll 0x63100000 500
```

## Output Example

```
======================================================================
PE ANALYSIS REPORT: module.dll
======================================================================

[*] Base Address: 0x63100000 (Auto-detected from PE ImageBase)
[*] Entry Point:  0x63101000
[*] Architecture: x86

----------------------------------------------------------------------
SECTIONS
----------------------------------------------------------------------
Name       Address      VirtSize     RawSize      Perms 
----------------------------------------------------------------------
.text      0x63101000   0x00010000   0x0000F000   RX   
.data      0x63111000   0x00002000   0x00001000   RW   
.rdata     0x63113000   0x00001000   0x00000800   R    

======================================================================
API: WRITEPROCESSMEMORY
======================================================================

[FUNCTION SIGNATURE]
Return Type: BOOL
DLL: kernel32.dll
Calling Convention: stdcall

[PARAMETERS]
  [1] hProcess                    HANDLE           [ in]
      Description: Process handle (0xFFFFFFFF = current process)
  [2] lpBaseAddress               LPVOID           [ in]
      Description: Destination address to write to
  [3] lpBuffer                    LPCVOID          [ in]
      Description: Source buffer address
  [4] nSize                       SIZE_T           [ in]
      Description: Number of bytes to write
  [5] lpNumberOfBytesWritten      SIZE_T*          [out]
      Description: Pointer to writable memory for bytes written count

[IAT INFORMATION]
  Function Ptr (VA):   0x63103020
  Function Ptr (RVA):  0x00003020
  Offset from Base:    0x00003020
  Base Address:        0x63100000
  DLL:                 kernel32.dll

[CODE CAVES FOR RETURN ADDRESS & lpBaseAddress]
  These are executable code caves suitable for shellcode injection
  Use them for Return address (where to jump after API call) and lpBaseAddress (where to write)

  [1] Address: 0x63105114 | Size: 512 bytes | Section: .text
  [2] Address: 0x63105200 | Size: 256 bytes | Section: .text

  [!] RECOMMENDATION: Use first cave (0x63105114)
      - For Return address: Jump here after API call
      - For lpBaseAddress: Write shellcode here
      - Verify with: !vprot 0x63105114

[WRITABLE ADDRESSES FOR OUT PARAMETERS]
  These addresses can be used for out parameters (e.g., lpNumberOfBytesWritten, lpflOldProtect)
  All addresses are in writable sections and contain zeros (safe to use)

  [1] Address: 0x63111000 (RVA: 0x00011000)
      Section: .data
      Size Available: 1024 bytes
      Section Size: 0x00002000 bytes

  [!] RECOMMENDATION: Use first address (0x63111000)
      Verify the address content is not being used at runtime
      Check memory protections with: !vprot 0x63111000

[ROP STACK LAYOUT]
  [0] WriteProcessMemory pointer (IAT) = 0x63103020
  [1] Return address                   = 0x63105114  [CODE CAVE]
  [2] hProcess                         = <hProcess>
  [3] lpBaseAddress                    = 0x63105114  [CODE CAVE]
  [4] lpBuffer                         = <lpBuffer>
  [5] nSize                            = <nSize>
  [6] lpNumberOfBytesWritten           = 0x63111000  [RECOMMENDED]
```

## Features in Detail

### Auto Base Address Detection
The tool automatically detects the base address from the PE file's `ImageBase` field. No need to manually specify it unless you're analyzing a loaded module with a different base address.

### Manual IAT Parsing
When standard IAT parsing fails (packed/obfuscated files), the tool falls back to manual parsing of the Import Directory Table, ensuring you get IAT information even in difficult cases.

### ROP-Ready Information
All addresses provided are ready to use in ROP chains:
- **Function pointers** from IAT
- **Code caves** for shellcode injection
- **Writable addresses** for out parameters
- **Complete stack layout** with recommended values

### Parameter Descriptions
Every API parameter includes:
- Type information
- Direction (in/out)
- Detailed description
- Common values (e.g., `0xFFFFFFFF` for current process)

## Use Cases

- **Exploit Development**: Get ready-to-use addresses for ROP chains
- **Malware Analysis**: Understand PE structure and imports
- **Security Research**: Analyze DEP bypass techniques
- **Reverse Engineering**: Understand API usage in binaries
- **CTF Competitions**: Quick PE file analysis

## Supported APIs

The tool has complete signatures for:

| API | Description |
|-----|-------------|
| `WriteProcessMemory` | Write data to process memory |
| `VirtualAlloc` | Allocate virtual memory |
| `VirtualProtect` | Change memory protection |
| `VirtualAllocEx` | Allocate memory in another process |
| `VirtualProtectEx` | Change protection in another process |
| `ReadProcessMemory` | Read data from process memory |
| `HeapCreate` | Create a heap |
| `SetProcessDEPPolicy` | Set DEP policy |

## Examples

### Analyzing a DLL for Exploitation

```bash
# Basic analysis
python PE_Analyzer.py target.dll

# With custom base (if module is loaded at different address)
python PE_Analyzer.py target.dll 0x63100000

# Find larger code caves only
python PE_Analyzer.py target.dll 0x63100000 1000
```

### Using Output in Exploits

The tool provides addresses that can be directly used in Python:

```python
# From the report output
write_process_memory = 0x63103020  # IAT address
return_address = 0x63105114        # Code cave
lp_base_address = 0x63105114       # Code cave (same as return)
lp_number_of_bytes = 0x63111000    # Writable address

# Use in ROP chain
rop_chain = struct.pack("<I", write_process_memory)
rop_chain += struct.pack("<I", return_address)
rop_chain += struct.pack("<I", 0xFFFFFFFF)  # hProcess
rop_chain += struct.pack("<I", lp_base_address)
# ... rest of parameters
```

## Architecture Support

- **x86 (32-bit)**: Full support
- **x64 (64-bit)**: Full support

## Notes

- The tool uses `pefile` library which is actively maintained
- Base address auto-detection uses `ImageBase` from PE header
- Code caves are searched for consecutive null bytes
- Writable addresses are verified to contain zeros (safe to use)
- All addresses are relative to the provided (or auto-detected) base address

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is open source and available under the MIT License.

## Disclaimer

This tool is for educational and authorized security testing purposes only. Use responsibly and only on systems you own or have explicit permission to test.

## Acknowledgments

- Built with [pefile](https://github.com/erocarrera/pefile)
- Designed for exploit developers and security researchers

---

**Made for the security research community**
