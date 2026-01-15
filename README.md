🔍 File Type & Malware Scanner
A Python-based tool for identifying file types, detecting suspicious files, and scanning directories recursively for potential malware indicators. It uses magic numbers, file extensions, and archive inspection to flag threats.

✅ Features

Detects common file types using magic numbers:

JPEG, PNG, GIF, PDF, ZIP, Executables (PE, ELF, Mach-O)


Identifies scripts (Bash, PowerShell) via shebang lines.
Flags malware-related extensions:

.exe, .bat, .cmd, .vbs, .js, .ps1, .dll, .scr, .msi, etc.


Detects double extensions (e.g., file.txt.exe).
Inspects archives:

ZIP (built-in), RAR, 7z (requires rarfile and py7zr).


Recursive directory scanning with summary report.
Logs all findings in scan_report.txt.


📦 Installation
```
git clone https://github.com/yourusername/file-malware-scanner.git
cd file-malware-scanner
pip install rarfile py7zr
```

Usage
Scan a Single File:
Python
```
from scanner import identify_file_type
result = identify_file_type("path/to/file")
print(result)
```

Scan a Directory Recursively:
Python
```
from scanner import scan_directory
summary = scan_directory("path/to/directory")
print(summary)
```

📝 Output

Detailed findings logged in scan_report.txt:

File type
Suspicious indicators
Archive contents


Summary includes:

Total files scanned
Suspicious files count
List of suspicious files




⚠ Requirements

Python 3.7+
Libraries:

rarfile (for RAR support)
py7zr (for 7z support)



Install dependencies:
```
pip install rarfile py7zrShow 
```

✅ Future Enhancements


Multi-threaded scanning for speed.

JSON output for integration with SIEM tools.

Optional hash-based malware signature checks.


🔒 Disclaimer

This tool is for educational and security auditing purposes only. Do not use it for malicious activities.
