import os
import sys
import re

# --- Decryption Logic for Type 7 ---
def decrypt_type7(encoded_password):
    xlat = [
        0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f,
        0x41, 0x2c, 0x2e, 0x69, 0x79, 0x65, 0x77, 0x72,
        0x6b, 0x6c, 0x64, 0x4a, 0x4b, 0x44, 0x48, 0x53,
        0x55, 0x42, 0x73, 0x67, 0x76, 0x63, 0x61, 0x36,
        0x39, 0x38, 0x33, 0x34, 0x6e, 0x63, 0x78, 0x76,
        0x39, 0x38, 0x37, 0x33, 0x32, 0x35, 0x34, 0x6b,
        0x3b, 0x66, 0x67, 0x38, 0x37, 0x00
    ]
    try:
        if not re.match(r'^[0-9A-Fa-f]+$', encoded_password): return None
        seed = int(encoded_password[:2])
        result = ""
        for i in range(2, len(encoded_password), 2):
            val = int(encoded_password[i:i+2], 16)
            result += chr(val ^ xlat[seed])
            seed = (seed + 1) % 53
        return result
    except:
        return None

def analyze_line(filename, line_num, line):
    findings = []
    line = line.strip()
    
    # regex patterns for common creds
    # 1. Type 7 (Reversible)
    #    Matches: 'enable password 7 HASH' or 'username bob password 7 HASH'
    match_7 = re.search(r'(?:username\s+(?P<user>\S+)\s+.*)?password 7\s+(?P<hash>[0-9A-Fa-f]+)', line, re.IGNORECASE)
    
    # 2. Type 5 (MD5) - Crack needed
    #    Matches: 'enable secret 5 HASH' or 'username bob secret 5 HASH'
    match_5 = re.search(r'(?:username\s+(?P<user>\S+)\s+.*)?secret 5\s+(?P<hash>\S+)', line, re.IGNORECASE)
    
    # 3. Type 8/9 (SHA/Scrypt) - Crack needed
    match_9 = re.search(r'(?:username\s+(?P<user>\S+)\s+.*)?secret [89]\s+(?P<hash>\S+)', line, re.IGNORECASE)

    # 4. Type 0 / Cleartext
    #    Matches: 'password 0 PLAIN' or just 'password PLAIN' (if no 7/5/secret keyword)
    match_0 = re.search(r'(?:username\s+(?P<user>\S+)\s+.*)?password 0\s+(?P<pass>\S+)', line, re.IGNORECASE)
    
    # 5. SNMP Community
    match_snmp = re.search(r'snmp-server\s+community\s+(?P<comm>\S+)', line, re.IGNORECASE)

    # --- Processing ---
    
    if match_7:
        user = match_7.group('user') if match_7.group('user') else "Global/Enable"
        p_hash = match_7.group('hash')
        decrypted = decrypt_type7(p_hash)
        findings.append({
            "type": "Type 7 (Weak)",
            "user": user,
            "cred": p_hash[:15]+"...",
            "value": f"\033[92m{decrypted}\033[0m" # Green Text
        })

    if match_5:
        user = match_5.group('user') if match_5.group('user') else "Global/Enable"
        findings.append({
            "type": "Type 5 (MD5)",
            "user": user,
            "cred": match_5.group('hash')[:15]+"...",
            "value": "\033[93m[Crack Needed]\033[0m" # Yellow Text
        })

    if match_9:
        user = match_9.group('user') if match_9.group('user') else "Global/Enable"
        findings.append({
            "type": "Type 8/9 (Strong)",
            "user": user,
            "cred": match_9.group('hash')[:15]+"...",
            "value": "\033[93m[Crack Needed]\033[0m"
        })

    if match_0:
        user = match_0.group('user') if match_0.group('user') else "Global/Enable"
        findings.append({
            "type": "Cleartext!",
            "user": user,
            "cred": "N/A",
            "value": f"\033[91m{match_0.group('pass')}\033[0m" # Red Text
        })
        
    if match_snmp:
        findings.append({
            "type": "SNMP Community",
            "user": "N/A",
            "cred": "N/A",
            "value": f"\033[91m{match_snmp.group('comm')}\033[0m" # Red Text
        })

    return findings

def scan_directory(directory):
    print(f"{'FILE':<25} | {'TYPE':<15} | {'USER':<15} | {'DECRYPTED / VALUE'}")
    print("-" * 80)
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    for i, line in enumerate(f, 1):
                        results = analyze_line(file, i, line)
                        for r in results:
                            print(f"{file[:25]:<25} | {r['type']:<15} | {r['user']:<15} | {r['value']}")
            except:
                pass

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 cisco_audit.py <directory>")
    else:
        scan_directory(sys.argv[1])
