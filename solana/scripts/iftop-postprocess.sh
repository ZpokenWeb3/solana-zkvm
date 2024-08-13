#!/usr/bin/env bash
#
# Reports network bandwidth usage
#
set -e

usage() {
  echo "Usage: $0 <iftop log file> <temp file for interediate data> [optional list of IP address mapping]"
  echo
  echo Processes iftop log file, and extracts latest bandwidth used by each connection
  echo
  echo
}

if [ "$#" -lt 2 ]; then
  usage
  exit 1
fi

cd "$(dirname "$0")"

awk '{ if ($3 ~ "=>") { print $2, $7 } else if ($2 ~ "<=") { print $1, $6 }} ' < "$1" \
  | awk 'NR%2{printf "%s ",$0;next;}1' \
  | awk '{ print "{ \"a\": \""$1"\", " "\"b\": \""$3"\", \"a_to_b\": \""$2"\", \"b_to_a\": \""$4"\"}," }' > "$2"

if [ "$#" -lt 3 ]; then
  solana-log-analyzer iftop -f "$2"
else
  list=$(cat "$3")
  solana-log-analyzer iftop -f "$2" map-IP --list "$list"
fi

exit 1
