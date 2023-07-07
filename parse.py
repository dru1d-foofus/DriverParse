#! /usr/bin/env python3
## dru1d (tyler.booth@cdw.com)

import argparse
import hashlib
import os
import pefile
import xml.etree.ElementTree as ET

def is_driver(file_path):
    try:
        pe = pefile.PE(file_path)
        if pe.OPTIONAL_HEADER.Subsystem == pefile.SUBSYSTEM_TYPE['IMAGE_SUBSYSTEM_NATIVE']:
            return True
        return False
    except Exception as e:
        print(f"Error parsing file: {file_path}. Error: {str(e)}")
        return False

def check_imports(file_path, common_functions):
    pe = pefile.PE(file_path)
    identified_functions = []

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            if imp.name is not None and imp.name.decode() in common_functions:
                identified_functions.append(imp.name.decode())
    
    if not identified_functions: # if list is empty
        return "There were no imports identified."
    
    return ', '.join(identified_functions)

def hash_file(file_path, hash_type):
    BUF_SIZE = 65536  # lets read stuff in 64kb chunks!
    if hash_type == 'md5':
        hash_obj = hashlib.md5()
    elif hash_type == 'sha256':
        hash_obj = hashlib.sha256()

    with open(file_path, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            hash_obj.update(data)
    return hash_obj.hexdigest()

def get_blocked_hashes(xml_file):
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()

        blocked_hashes = set()

        for deny_node in root.findall("./Deny"):
            hash_value = deny_node.get('Hash')
            if hash_value:
                blocked_hashes.add(hash_value.upper())

        return blocked_hashes

    except ET.ParseError as e:
        print(f"Error parsing XML file: {xml_file}. Error: {str(e)}")
        return set()

def get_hashes_from_loldrivers(file_path):
    with open(file_path, 'r') as f:
        hashes = {line.strip().upper() for line in f}
    return hashes

def process_file(file_path, output, common_functions, blocked_hashes):
    print(f"[*] Processing file: {file_path}")
    try:
        result = is_driver(file_path)
        imp_result = check_imports(file_path, common_functions)
        md5_hash = hash_file(file_path, 'md5')
        sha256_hash = hash_file(file_path, 'sha256')  # converting to uppercase
        is_blocked = sha256_hash.upper() in blocked_hashes
        output.write(f"{file_path}|{result}|{imp_result}|{md5_hash}|{sha256_hash}|{is_blocked}\n")
        print(f"[+] File: {file_path}, Is driver: {result}, Identified imports: {imp_result}, MD5: {md5_hash}, SHA256: {sha256_hash}, Blocked: {is_blocked}")
    except pefile.PEFormatError:
        print(f"[!] File: {file_path} is empty or is not a PE file.")

def main():
    parser = argparse.ArgumentParser(description="Process some files.")
    parser.add_argument('-i', '--input', help='Input file path', required=True)
    parser.add_argument('-o', '--output', help='Output file path', required=True)
    parser.add_argument('-x', '--xml', help='Input XML file path', required=True)
    parser.add_argument('-l', '--hashfile', help='File with loldrivers hashes', required=True)
    args = parser.parse_args()

    output_file = open(args.output, 'w')
    common_functions = ["ZwOpenProcess", "MmMapIoSpace", "ZwQuerySystemInformation", "KeStackAttachProcess",
    "ZwTerminateProcess", "ZwMapViewOfSection"]

    blocked_hashes = get_blocked_hashes(args.xml)
    file_hashes = get_hashes_from_loldrivers(args.hashfile)
    blocked_hashes.update(file_hashes)

    # Write the header once here
    output_file.write(f"File|Driver|Imports|MD5|SHA256|Blocked\n")  

    if os.path.isdir(args.input):
        for root, dirs, files in os.walk(args.input):
            for file in files:
                process_file(os.path.join(root, file), output_file, common_functions, blocked_hashes)
    else:
        process_file(args.input, output_file, common_functions, blocked_hashes)
    
    output_file.close()

if __name__ == "__main__":
    main()
