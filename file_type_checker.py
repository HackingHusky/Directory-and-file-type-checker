import os
import zipfile

try:
    import rarfile
    import py7zr
except ImportError:
    rarfile = None
    py7zr = None

def scan_directory(directory, report_path="scan_report.txt"):
    """Recursively scans a directory for suspicious files and generates a summary report."""
    suspicious_files = []
    total_files = 0

    with open(report_path, 'w') as report:
        report.write(f"Scan Report for Directory: {directory}\n{'='*50}\n")

    for root, _, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            total_files += 1
            result = identify_file_type(filepath, report_path)
            if "Suspicious" in result or "Archive contains" in result:
                suspicious_files.append(filepath)

    # Write summary
    with open(report_path, 'a') as report:
        report.write("\nSummary:\n")
        report.write(f"Total files scanned: {total_files}\n")
        report.write(f"Suspicious files found: {len(suspicious_files)}\n")
        if suspicious_files:
            report.write("List of suspicious files:\n")
            for sf in suspicious_files:
                report.write(f" - {sf}\n")
        report.write("="*50 + "\n")

    return f"Scan complete! {total_files} files scanned, {len(suspicious_files)} suspicious files found."


def identify_file_type(filepath, report_path="scan_report.txt"):
    """Identifies file type using magic numbers, script indicators, suspicious extensions, and archive inspection."""
    
    magic_numbers = {
        b'\xff\xd8\xff': 'JPEG',
        b'\x89PNG\r\n\x1a\n': 'PNG',
        b'GIF87a': 'GIF',
        b'GIF89a': 'GIF',
        b'PK\x03\x04': 'ZIP/DOCX/XLSX/PPTX',
        b'%PDF': 'PDF',
        b'MZ': 'Windows Executable (PE)',
        b'\x7fELF': 'Linux Executable (ELF)',
        b'\xFE\xED\xFA\xCE': 'Mach-O Executable',
        b'\xFE\xED\xFA\xCF': 'Mach-O Executable'
    }

    malware_extensions = [
        '.exe', '.scr', '.bat', '.cmd', '.vbs', '.js', '.ps1', '.dll', '.com', '.pif', '.msi'
    ]

    findings = []

    try:
        with open(filepath, 'rb') as f:
            header = f.read(8)

           
            for magic_bytes, file_type in magic_numbers.items():
                if header.startswith(magic_bytes):
                    findings.append(f"Magic number detected: {file_type}")
                    # If it's an archive, inspect contents
                    if file_type.startswith('ZIP'):
                        if check_zip_for_executables(filepath, malware_extensions):
                            findings.append("Archive contains suspicious executable files")
                    return log_findings(report_path, filepath, findings)

            # Check for script indicators
            f.seek(0)
            first_line = f.readline().decode(errors='ignore').strip()
            if first_line.startswith('#!'):
                if 'bash' in first_line:
                    findings.append("Script detected: Bash")
                elif 'powershell' in first_line.lower():
                    findings.append("Script detected: PowerShell")
                return log_findings(report_path, filepath, findings)

    except FileNotFoundError:
        findings.append("File not found")
        return log_findings(report_path, filepath, findings)
    except IOError as e:
        findings.append(f"IO Error: {e}")
        return log_findings(report_path, filepath, findings)

    filename = os.path.basename(filepath)
    _, ext = os.path.splitext(filename)
    if ext.lower() in malware_extensions:
        findings.append(f"Suspicious file type (possible malware): {ext}")

    # Check for double extensions
    parts = filename.split('.')
    if len(parts) > 2 and parts[-1].lower() in [e.strip('.') for e in malware_extensions]:
        findings.append(f"Suspicious double extension: {filename}")

    # Check archives (.rar, .7z)
    if rarfile and filename.lower().endswith('.rar'):
        if check_rar_for_executables(filepath, malware_extensions):
            findings.append("RAR archive contains suspicious executable files")
    if py7zr and filename.lower().endswith('.7z'):
        if check_7z_for_executables(filepath, malware_extensions):
            findings.append("7z archive contains suspicious executable files")

    if not findings:
        findings.append("Unknown file type")

    return log_findings(report_path, filepath, findings)


def check_zip_for_executables(zip_path, malware_exts):
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            for name in zip_ref.namelist():
                _, ext = os.path.splitext(name)
                if ext.lower() in malware_exts:
                    return True
    except zipfile.BadZipFile:
        return False
    return False

def check_rar_for_executables(rar_path, malware_exts):
    try:
        with rarfile.RarFile(rar_path) as rf:
            for name in rf.namelist():
                _, ext = os.path.splitext(name)
                if ext.lower() in malware_exts:
                    return True
    except:
        return False
    return False

def check_7z_for_executables(sevenz_path, malware_exts):
    try:
        with py7zr.SevenZipFile(sevenz_path, mode='r') as archive:
            for name in archive.getnames():
                _, ext = os.path.splitext(name)
                if ext.lower() in malware_exts:
                    return True
    except:
        return False
    return False

def log_findings(report_path, filepath, findings):
    with open(report_path, 'a') as report:
        report.write(f"File: {filepath}\n")
        report.write("\n".join(findings) + "\n" + "-"*40 + "\n")
    return findings[-1]  

