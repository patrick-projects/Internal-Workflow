import os
import sys
import re

# Cisco Type 7 Decryption Logic
def decrypt_type7(encoded_password):
    # The static Cisco lookup table
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
        # Validate input char set
        if not re.match(r'^[0-9A-Fa-f]+$', encoded_password):
            return "(Invalid Hex Characters)"

        # First two digits are the salt/index
        seed = int(encoded_password[:2])
        result = ""
        
        # Process the rest of the string in pairs of hex digits
        for i in range(2, len(encoded_password), 2):
            val = int(encoded_password[i:i+2], 16)
            result += chr(val ^ xlat[seed])
            seed = (seed + 1) % 53
            
        return result
    except Exception as e:
        return f"(Error: {str(e)})"

def scan_directory(directory):
    # Regex to find 'password 7' followed by the hash
    # Captures things like: 'enable password 7 <hash>' or 'username bob password 7 <hash>'
    pattern = re.compile(r'password 7\s+([0-9A-Fa-f]+)', re.IGNORECASE)

    print(f"[*] Scanning directory: {directory}")
    print(f"{'-'*80}")
    print(f"{'FILENAME':<35} | {'HASH':<20} | {'DECRYPTED'}")
    print(f"{'-'*80}")

    found_count = 0

    for root, dirs, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            
            try:
                # Open with 'ignore' errors to handle binary files or weird encodings without crashing
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    for line_num, line in enumerate(f, 1):
                        match = pattern.search(line)
                        if match:
                            full_hash = match.group(1)
                            # Cisco Type 7 hashes are usually even length. 
                            # If odd, it's often a false positive or malformed, but we try anyway.
                            if len(full_hash) % 2 != 0:
                                continue

                            plaintext = decrypt_type7(full_hash)
                            
                            # Clean up the output to make it readable
                            display_name = os.path.basename(filepath)
                            print(f"{display_name:<35} | {full_hash[:18]+'..':<20} | \033[92m{plaintext}\033[0m")
                            found_count += 1
            except Exception as e:
                # Permission errors or really broken files
                pass

    print(f"{'-'*80}")
    print(f"[*] Scan complete. Found {found_count} credentials.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 cisco_decryptor.py <directory_path>")
        sys.exit(1)
    
    target_dir = sys.argv[1]
    if os.path.isdir(target_dir):
        scan_directory(target_dir)
    else:
        print("Error: The provided path is not a directory.")
