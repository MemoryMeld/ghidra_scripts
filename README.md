# Ghidra Scripts

Collection of Ghidra scripts for reverse engineering and static analysis on multiple binaries.

## Features

- **Get Decompilation:** Leverages Ghidra’s embedded CppExporter to obtain decompilation for multiple binaries.
- **Filtered Decompilation:** Get decompilation while excluding external symbols, dead code, and thunk functions.
- **Filtered Disassembly:** Get disassembly while excluding external symbols.
- **XREFS:** Catalogs cross-references to C library function calls across multiple binaries.

## Installation

1. Install openjdk-17-jdk:

    ```bash
    sudo apt install openjdk-17-jdk
    ```

2. Download Ghidra, unzip it, and run it:

    ```bash
    wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.3.3_build/ghidra_10.3.3_PUBLIC_20230829.zip
    unzip ghidra_10.3.3_PUBLIC_20230829.zip
    ghidra_10.3.3_PUBLIC/./ghidraRun
    ```

3. Clone this GitHub repository:

    ```bash
    git clone https://github.com/MemoryMeld/ghidra_scripts.git
    ```

4. Move all binaries you want to analyze into the `binaries` folder.

## Usage

Run the headless_analyzer script:

```bash
python3 headless_analyzer.py
```

To rerun, delete the entire `root_results` folder
```bash
rm -rf root_results
```
## Note: Ensure that you perform all these steps from your user's home directory.

