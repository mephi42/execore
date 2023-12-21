#!/bin/bash
set -e -u -x -o pipefail

# shellcheck disable=SC2034
source_dir=$(cd "$(dirname "$0")"/.. && pwd)

execore=$1
shift
# shellcheck disable=SC2034
phoenix=$1
shift
execore_dir=$(cd "$(dirname "$execore")" && pwd)
export PATH=$execore_dir:$PATH

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT
cd "$workdir"
