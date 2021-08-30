#! /bin/bash

set -e

build_root=$(dirname $(readlink -f $0))
exe_dir=${build_root}/Debug

mkdir -p ${exe_dir}

gcc -std=gnu99 ${build_root}/switch_test_main.c -o ${exe_dir}/switch_test -l pcap
echo "Setting permission for switch_test to send/receive packets"
sudo setcap cap_net_admin,cap_net_raw+eip ${exe_dir}/switch_test

