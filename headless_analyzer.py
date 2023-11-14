#!/usr/bin/env python3
import os
import subprocess
import time
import re

GHIDRA_PATH = os.path.expanduser("~/ghidra_10.3.3_PUBLIC")
GHIDRA_SCRIPT_PATH = os.path.expanduser("~/ghidra_scripts")
CURRENT_DIR = os.getcwd()

print("---------------------Started Analyzing------------------------")
print("")

start_time = time.time()

binaries_path = os.path.join(CURRENT_DIR, "binaries")
root_results_directory = os.path.join(CURRENT_DIR, "root_results")
os.makedirs(root_results_directory, exist_ok=True)
for fileName in os.listdir(binaries_path):
    binary_path = os.path.join(binaries_path, fileName)
    results_directory = os.path.join(root_results_directory, f"{fileName}_results")
    os.makedirs(results_directory, exist_ok=True)
    result_xrefs = os.path.join(results_directory, f"{fileName}_xrefs.txt")
    cleaned_source = os.path.join(results_directory, f"{fileName}_cleaned_source.c")
    exported_source = os.path.join(results_directory, f"{fileName}_exported_source.c")

    # Run Ghidra Headless
    ghidra_project_name = f"{fileName}_ghidra_project"
    subprocess.run([
        f"{GHIDRA_PATH}/support/analyzeHeadless",
        results_directory,
        ghidra_project_name,
        "-import",
        binary_path,
        "-scriptPath",
        GHIDRA_SCRIPT_PATH,
        "-postscript",
        "analyzer.py",
        result_xrefs,
        cleaned_source,
        exported_source
    ])

end_time = time.time()
elapsed_time = round(end_time - start_time)

print("")
print("---------------------Finished Analyzing------------------------")
print(f"Elapsed time: {elapsed_time} seconds")