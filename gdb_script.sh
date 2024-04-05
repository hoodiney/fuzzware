target=$1

# gdb -ex "set confirm off" \
#     -ex "set follow-fork-mode child" \
#     -ex "add-symbol-file emulator/harness/fuzzware_harness/native/native_hooks.so" \
#     --args /home/user/.virtualenvs/fuzzware/bin/python pipeline/fuzzware.py pipeline $target
    
gdb -ex "set follow-fork-mode child" \
    -ex "add-symbol-file emulator/harness/fuzzware_harness/native/native_hooks.so" \
    --args /home/user/.virtualenvs/fuzzware/bin/python pipeline/fuzzware.py pipeline $target
    