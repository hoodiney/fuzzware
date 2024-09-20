import os
import argparse
import subprocess
from tqdm import tqdm

def replay_crashes(proj_path):
    # get all crashes folders in project
    command = ["find", proj_path, "-type", "d", "-path", "*/main*/*/crashes"]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    directories = result.stdout.splitlines()

    for dir in directories:
        print(dir)
        main_folder_path = os.path.join(*dir.split("/")[:-3])
        files = os.listdir(dir)
        file_paths = []
        for file in files:
            if file.startswith("id") and not file.endswith(".log"):
                file_paths.append(os.path.join(dir, file))
        run_fuzzware_on_files(file_paths, main_folder_path)

def run_fuzzware_on_files(file_paths, main_folder_path):
    config_path = os.path.join(main_folder_path, "config.yml")
    extra_args_path = os.path.join(main_folder_path, "extra_args.txt")
    extra_cmds = []

    if os.path.exists(extra_args_path):
        with open(extra_args_path, "r") as file:
            cmds = file.readlines()
            for cmd in cmds:
                if cmd.endswith("\n"):
                    extra_cmds.append(cmd[:-1])
                else:
                    extra_cmds.append(cmd)

    print("now start replaying!")
    for file_path in tqdm(file_paths):
        # Create log file path by replacing the file extension with '.log'
        log_file_path = f"{file_path}.log"
        
        # Open log file to write
        with open(log_file_path, 'w') as log_file:
            # Execute fuzzware binary with the file as input
            # Note: Adjust the command if 'fuzzware' needs specific command line options
            # subprocess.run is blocking, so no need to check if all subprocesses finish
            subprocess.run(["fuzzware", "emu", "-c", config_path, "-v"] + extra_cmds + [file_path], stdout=log_file, stderr=subprocess.STDOUT)

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

args = parser.parse_args()

replay_crashes(args.project_dir)

# postprocess(files)