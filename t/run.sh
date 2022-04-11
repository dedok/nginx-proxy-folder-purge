#!/bin/bash

#
# (C)
#

set -e

PREF=$PWD
DELAY=2
WAITING=5
NGINX_ROOT=./nginx

# Prepare env. i.e. copy nginx.conf, start nginx
function prepare_env() {
  echo "[+] Prepare env"
  cd ${PREF}
  ${NGINX_ROOT}/objs/nginx -sstop || echo
  sleep $DELAY

  rm -f ${PREF}/test-root/conf/domains/*
  rm -rf ${PREF}/test-root/cache/* || echo
  rm -rf ${PREF}/test-root/masks_storage/* || echo
  if ! [ -d ${PREF}/test-root/conf/domains ]
  then
    mkdir -p ${PREF}/test-root/conf/domains/
    mkdir -p ${PREF}/test-root/logs/
  fi
  cp -f \
    ${PREF}/conf/${1} \
    ${PREF}/test-root/conf/domains/${1}

  ${NGINX_ROOT}/objs/nginx
  cd -
  sleep $WAITING
  echo "[+] OK"
}


#
function restart_nginx() {
  cd ${PREF}
  ${NGINX_ROOT}/objs/nginx -sstop || echo
  sleep $DELAY
  ${NGINX_ROOT}/objs/nginx
  sleep $DELAY
  cd -
}

#
function masks_in_lines_count() {
  cd ${PREF}
  local res=`cat test-root/masks_storage/masks.in* | wc -l`
  cd -
  echo $res
}

#
function die() {
  echo "Error: $1"
  exit 1
}

#
# Run tests {{[
#

rm -f ${PREF}/test-root/conf/domains/*
rm -rf ${PREF}/test-root/cache/* || echo
rm -rf ${PREF}/test-root/masks_storage/* || echo

echo "[+] Consistency test"
prepare_env 'foreground_purge.conf'
# Add some purges
for i in {1..8}; do
  curl -XPURGE -H"Host: purge_folder" -H"X-Purge-Options: delete" \
      127.0.0.1:8082/foreground_purge_on/folder_$i/*
done
for i in {1..8}; do
  curl -XPURGE -H"Host: purge_folder" -H"X-Purge-Options: delete" \
      127.0.0.1:8082/foreground_purge_on/folder_$i/*
done
# Testing
./t/consistency_test.py
restart_nginx
./t/consistency_test.py
restart_nginx
./t/masks_storage_test.py
echo "[+] OK"

echo "[+] Purge API test"
prepare_env 'foreground_purge.conf'
for i in {1..1}; do
  ./t/purge_folder_api_test.py
  ./t/foreground_purge_test.py
  ./t/x_purge_timestamp_test.py
done
echo "[+] OK"

echo "[+] Parallel clients test"
./t/add_mask_test.py &
./t/add_mask_test.py &
./t/add_mask_test.py
wait
echo "[+] OK"

echo "[+] Background purge"
prepare_env 'background_purge.conf'
./t/background_purge_test.py
echo "[+] OK"

echo "[+] Not use scheme"
prepare_env 'not_use_scheme.conf'
./t/not_use_scheme_test.py
echo "[+] OK"

echo "[+] Use scheme"
prepare_env 'use_scheme.conf'
./t/use_scheme_test.py
echo "[+] OK"

# BROKEN
#echo "[+] Http host purge"
#prepare_env 'http_host_purge.conf'
#./t/http_host_purge_test.py
#echo "[+] OK"

# BROKEN
#echo "[+] NCCS-738"
#prepare_env 'nccs_738.conf'
#./t/nccs_738_test.py
#echo "[+] OK"

echo "[+] NCCS-729"
prepare_env 'background_purge.conf'
./t/nccs_729_test.py
echo "[+] OK"

# BROKEN
#echo "[+] Multiple purger file"
#prepare_env 'multi_purger_file.conf'
#./t/multi_purger_file_test.py
#echo "[+] OK"

# BROKEN
#echo "[+] NCCS-799"
#prepare_env 'background_purge.conf'
#./t/nccs_799_test.py
#echo "[+] OK"
#
# }}}
#

