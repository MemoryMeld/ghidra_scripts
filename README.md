# ghidra_scripts
Collection of scripts to perform static analysis utilizing Ghidra in headless mode

Author: ReconDeveloper

# Install notes - Do all steps from your user's home directory 
# install openjdk-17-jdk, download Ghidra, unzip it and run it

sudo apt install openjdk-17-jdk 

wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.3.3_build/ghidra_10.3.3_PUBLIC_20230829.zip

unzip ghidra_10.3.3_PUBLIC_20230829.zip

ghidra_10.3.3_PUBLIC/./ghidraRun

# Now clone this github 

git clone https://github.com/ReconDeveloper/ghidra_scripts.git

# Move all binaries you want analyzed into the binaries folder

# run the headless_anaylzer script 

python3 headless_analyzer.py 

# To rerun, delete entire root_results folder 

rm -rf root_results
