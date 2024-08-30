#!/usr/bin/env bash

declare -r SOLANA_LOCK_FILE="/home/solana/.solana.lock"

__colo_here="$(dirname "${BASH_SOURCE[0]}")"

# shellcheck source=net/common.sh
source "${__colo_here}"/../common.sh

# Load colo resource specs
export COLO_RES_N=0
export COLO_RES_HOSTNAME=()
export COLO_RES_IP=()
export COLO_RES_IP_PRIV=()
export COLO_RES_CPU_CORES=()
export COLO_RES_RAM_GB=()
export COLO_RES_STORAGE_TYPE=()
export COLO_RES_STORAGE_CAP_GB=()
export COLO_RES_ADD_STORAGE_TYPE=()
export COLO_RES_ADD_STORAGE_CAP_GB=()
export COLO_RES_MACHINE=()

export COLO_RESOURCES_LOADED=false
colo_load_resources() {
  if ! ${COLO_RESOURCES_LOADED}; then
    while read -r LINE; do
      IFS='|' read -r H I PI C M ST SC AST ASC G Z <<<"${LINE}"
      COLO_RES_HOSTNAME+=( "${H}" )
      COLO_RES_IP+=( "${I}" )
      COLO_RES_IP_PRIV+=( "${PI}" )
      COLO_RES_CPU_CORES+=( "${C}" )
      COLO_RES_RAM_GB+=( "${M}" )
      COLO_RES_STORAGE_TYPE+=( "${ST}" )
      COLO_RES_STORAGE_CAP_GB+=( "${SC}" )
      COLO_RES_ADD_STORAGE_TYPE+=( "$(tr ',' $'\x1f' <<<"${AST}")" )
      COLO_RES_ADD_STORAGE_CAP_GB+=( "$(tr ',' $'\x1f' <<<"${ASC}")" )
      COLO_RES_MACHINE+=( "${G}" )
      COLO_RES_ZONE+=( "${Z}" )
      COLO_RES_N=$((COLO_RES_N+1))
    done < <(sort -nt'|' -k10,10 "${__colo_here}"/colo_nodes)
    COLO_RESOURCES_LOADED=true
  fi
}

declare COLO_RES_AVAILABILITY_CACHED=false
declare -ax COLO_RES_AVAILABILITY
colo_load_availability() {
  declare USE_CACHE=${1:-${COLO_RES_AVAILABILITY_CACHED}}
  declare LINE PRIV_IP STATUS LOCK_USER I IP HOST_NAME ZONE INSTNAME PREEMPTIBLE
  if ! ${USE_CACHE}; then
    COLO_RES_AVAILABILITY=()
    COLO_RES_REQUISITIONED=()
    while read -r LINE; do
      IFS=$'\x1f' read -r IP STATUS LOCK_USER INSTNAME PREEMPTIBLE <<< "${LINE}"
      I=$(colo_res_index_from_ip "${IP}")
      PRIV_IP="${COLO_RES_IP_PRIV[${I}]}"
      HOST_NAME="${COLO_RES_HOSTNAME[${I}]}"
      ZONE="${COLO_RES_ZONE[${I}]}"
      COLO_RES_AVAILABILITY+=( "$(echo -e "${HOST_NAME}\x1f${IP}\x1f${PRIV_IP}\x1f${STATUS}\x1f${ZONE}\x1f${LOCK_USER}\x1f${INSTNAME}\x1f${PREEMPTIBLE}")" )
    done < <(colo_node_status_all | sort -t $'\x1f' -k1)
    COLO_RES_AVAILABILITY_CACHED=true
  fi
}

colo_res_index_from_ip() {
  declare IP="${1}"
  for i in "${!COLO_RES_IP_PRIV[@]}"; do
    if [[ "${IP}" = "${COLO_RES_IP[${i}]}" || "${IP}" = "${COLO_RES_IP_PRIV[${i}]}" ]]; then
      echo "${i}"
      return 0
    fi
  done
  return 1
}

colo_instance_run() {
  declare IP=${1}
  declare CMD="${2}"
  declare OUT
  set +e
  OUT=$(ssh -l solana -o "StrictHostKeyChecking=no" -o "ConnectTimeout=3" -n "${IP}" "${CMD}" 2>&1)
  declare RC=$?
  set -e
  while read -r LINE; do
    echo -e "${IP}\x1f${RC}\x1f${LINE}"
    if [[ "${RC}" -ne 0 ]]; then
      echo "IP(${IP}) Err(${RC}) LINE(${LINE})" 1>&2
    fi
  done < <(tr -d $'\r' <<<"${OUT}")
  return ${RC}
}

colo_instance_run_foreach() {
  declare CMD
  if test 1 -eq $#; then
    CMD="${1}"
    declare IPS=()
    for I in $(seq 0 $((COLO_RES_N-1))); do
      IPS+=( "${COLO_RES_IP[${I}]}" )
    done
    set "${IPS[@]}" "${CMD}"
  fi
  CMD="${*: -1}"
  for I in $(seq 0 $(($#-2))); do
    declare IP="${1}"
    colo_instance_run "${IP}" "${CMD}" &
    shift
  done

  wait
}

colo_whoami() {
  declare ME LINE SOL_USER EOL
  while read -r LINE; do
    declare IP RC
    IFS=$'\x1f' read -r IP RC SOL_USER EOL <<< "${LINE}"
    if [ "${RC}" -eq 0 ]; then
      [[ "${EOL}" = "EOL" ]] || echo "${FUNCNAME[0]}: Unexpected input \"${LINE}\"" 1>&2
      if [ -z "${ME}" ] || [ "${ME}" = "${SOL_USER}" ]; then
        ME="${SOL_USER}"
      else
        echo "Found conflicting username \"${SOL_USER}\" on ${IP}, expected \"${ME}\"" 1>&2
      fi
    fi
  done < <(colo_instance_run_foreach "[ -n \"\${SOLANA_USER}\" ] && echo -e \"\${SOLANA_USER}\\x1fEOL\"")
  echo "${ME}"
}

COLO_SOLANA_USER=""
colo_get_solana_user() {
  if [ -z "${COLO_SOLANA_USER}" ]; then
    COLO_SOLANA_USER=$(colo_whoami)
  fi
  echo "${COLO_SOLANA_USER}"
}

__colo_node_status_script() {
  cat <<EOF
  exec 3>&2
  exec 2>/dev/null  # Suppress stderr as the next call to exec fails most of
                    # the time due to ${SOLANA_LOCK_FILE} not existing and is running from a
                    # subshell where normal redirection doesn't work
  exec 9<"${SOLANA_LOCK_FILE}" && flock -s 9 && . "${SOLANA_LOCK_FILE}" && exec 9>&-
  echo -e "\${SOLANA_LOCK_USER}\\x1f\${SOLANA_LOCK_INSTANCENAME}\\x1f\${PREEMPTIBLE}\\x1fEOL"
  exec 2>&3 # Restore stderr
EOF
}

__colo_node_status_result_normalize() {
  declare IP RC US BY INSTNAME PREEMPTIBLE EOL
  declare ST="DOWN"
  IFS=$'\x1f' read -r IP RC US INSTNAME PREEMPTIBLE EOL <<< "${1}"
  if [ "${RC}" -eq 0 ]; then
    [[ "${EOL}" = "EOL" ]] || echo "${FUNCNAME[0]}: Unexpected input \"${1}\"" 1>&2
    if [ -n "${US}" ]; then
      BY="${US}"
      ST="HELD"
      if [[ -z "${INSTNAME}" ]]; then
        return
      fi
    else
      ST="FREE"
    fi
  fi
  echo -e $"${IP}\x1f${ST}\x1f${BY}\x1f${INSTNAME}\x1f${PREEMPTIBLE}"
}

colo_node_status() {
  declare IP="${1}"
  __colo_node_status_result_normalize "$(colo_instance_run "${IP}" "$(__colo_node_status_script)")"
}

colo_node_status_all() {
  declare LINE
  while read -r LINE; do
    __colo_node_status_result_normalize "${LINE}"
  done < <(colo_instance_run_foreach "$(__colo_node_status_script)")
}

# Note: As part of enabling COLO_PARALLELIZE, this list will need to be maintained in a
# lockfile to work around `cloud_CreateInstance` being called in the background
# for validators
export COLO_RES_REQUISITIONED=()
colo_node_requisition() {
  declare IP=${1}
  # shellcheck disable=SC2034
  declare INSTANCE_NAME=${2}
  # shellcheck disable=SC2034
  declare SSH_PRIVATE_KEY="${3}"
  declare PREEMPTIBLE="${4}"

  declare INDEX
  INDEX=$(colo_res_index_from_ip "${IP}")
  declare RC=false

  colo_instance_run "${IP}" "$(cat <<EOF
SOLANA_LOCK_FILE="${SOLANA_LOCK_FILE}"
INSTANCE_NAME="${INSTANCE_NAME}"
PREEMPTIBLE="${PREEMPTIBLE}"
SSH_AUTHORIZED_KEYS='$("${__colo_here}"/add-datacenter-solana-user-authorized_keys.sh 2> /dev/null)'
SSH_PRIVATE_KEY_TEXT="$(<"${SSH_PRIVATE_KEY}")"
SSH_PUBLIC_KEY_TEXT="$(<"${SSH_PRIVATE_KEY}.pub")"
NETWORK_INFO="$(printNetworkInfo 2>/dev/null)"
CREATION_INFO="$(creationInfo 2>/dev/null)"
$(<"${__colo_here}"/colo-node-onacquire.sh)
EOF
  )"
  # shellcheck disable=SC2181
  if [[ 0 -eq $? ]]; then
    COLO_RES_REQUISITIONED+=("${INDEX}")
    RC=true
  fi
  ${RC}
}

colo_node_is_requisitioned() {
  declare INDEX="${1}"
  declare REQ
  declare RC=false
  for REQ in "${COLO_RES_REQUISITIONED[@]}"; do
    if [[ ${REQ} -eq ${INDEX} ]]; then
      RC=true
      break
    fi
  done
  ${RC}
}

colo_machine_types_compatible() {
  declare MAYBE_MACH="${1}"
  declare WANT_MACH="${2}"
  declare COMPATIBLE=false
  # Colo machine types are just GPU count ATM...
  if [[ "${MAYBE_MACH}" -ge "${WANT_MACH}" ]]; then
    COMPATIBLE=true
  fi
  ${COMPATIBLE}
}

colo_node_free() {
  declare IP=${1}
  declare FORCE_DELETE=${2}
  colo_instance_run "${IP}" "$(cat <<EOF
SOLANA_LOCK_FILE="${SOLANA_LOCK_FILE}"
SECONDARY_DISK_MOUNT_POINT="${SECONDARY_DISK_MOUNT_POINT}"
SSH_AUTHORIZED_KEYS='$("${__colo_here}"/add-datacenter-solana-user-authorized_keys.sh 2> /dev/null)'
FORCE_DELETE="${FORCE_DELETE}"
$(<"${__colo_here}"/colo-node-onfree.sh)
EOF
  )"
}


