#! /bin/bash

set -e

build_root=$(dirname $(readlink -f $0))
build_configurations="Debug Release"
for build_configuration in ${build_configurations}
do
   exe_dir=${build_root}/${build_configuration}

  mkdir -p ${exe_dir}

  case ${build_configuration} in
     Debug)
        build_configuration_flags="-g"
        ;;
     Release)
        build_configuration_flags="-O3"
        ;;
  esac
  gcc -Wall -std=gnu99 ${build_root}/switch_test_main.c -o ${exe_dir}/switch_test -l m -l pcap -l rt -l pthread ${build_configuration_flags}
  echo "Setting permission for switch_test to send/receive packets"
  sudo setcap cap_net_admin,cap_net_raw+eip ${exe_dir}/switch_test
done

