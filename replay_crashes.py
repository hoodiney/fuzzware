import os
import argparse
import subprocess
from tqdm import tqdm

def find_files_in_crashes(root_path):
    # List to hold all file paths
    files_in_crashes = []

    # Walk through directory
    for dirpath, dirnames, filenames in os.walk(root_path):
        # Check if current directory name is 'crashes'
        if os.path.basename(dirpath) == 'crashes':
            # Add files to list
            for filename in filenames:
                if filename == "README.txt" or filename.endswith(".log"):
                    continue
                # Construct full file path
                full_path = os.path.join(dirpath, filename)
                files_in_crashes.append(full_path)
    
    return files_in_crashes

def run_fuzzware_on_files(files, config_path):
    print("now start replaying!")
    for file_path in tqdm(files):
        # Create log file path by replacing the file extension with '.log'
        log_file_path = f"{os.path.splitext(file_path)[0]}.log"
        
        # Open log file to write
        with open(log_file_path, 'w') as log_file:
            # Execute fuzzware binary with the file as input
            # Note: Adjust the command if 'fuzzware' needs specific command line options
            # subprocess.run is blocking, so no need to check if all subprocesses finish
            subprocess.run(["fuzzware", "emu", "-c", config_path, "-d", "-v", file_path], stdout=log_file, stderr=subprocess.STDOUT)

# rule out the ones with "If no other reason, we ran into one of the limits"
# We only check if that sentence appears at the end of the log
def postprocess(files):
    print("now start postprocessing!")
    limit_check = "If no other reason, we ran into one of the limits"
    interesting_files = []
    for file_path in tqdm(files):
        log_file_path = f"{os.path.splitext(file_path)[0]}.log"

        with open(log_file_path, 'r') as log_file:
            lines = log_file.readlines()
            if limit_check not in lines[-1]:
                interesting_files.append(file_path)
    print("Here are the interesting files:")
    for file_path in interesting_files:
        print(file_path)

parser = argparse.ArgumentParser(
                    prog='replay_crashes.py',
                    description='Replay the crashing seeds and log the output',
                    epilog='')

parser.add_argument('-p', '--project_dir')  
parser.add_argument('-c', '--config_path')  

args = parser.parse_args()

files = find_files_in_crashes(args.project_dir)
# run_fuzzware_on_files(files, args.config_path)

postprocess(files)