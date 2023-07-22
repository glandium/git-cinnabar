#!/bin/sh
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

where=$(dirname $0)
clientId=$1
workerType=$2

[ -z "$clientId" -o -z "$workerType" ] && echo Usage: $0 clientId workerType >&2 && exit 1
[ -z "$secret" ] && echo Missing key >&2 && exit 1

token=$(openssl aes-256-cbc -k "$secret" -in $where/$workerType.token.enc -d -md sha256)

unset secret

cat > worker.config <<EOF
{
  "accessToken": "$token",
  "cachesDir": "caches",
  "cleanUpTaskDirs": true,
  "clientId": "project/git-cinnabar/$clientId",
  "disableReboots": true,
  "downloadsDir": "downloads",
  "ed25519SigningKeyLocation": "worker.key",
  "idleTimeoutSecs": 180,
  "provisionerId": "proj-git-cinnabar",
  "publicIP": "127.0.0.1",
  "requiredDiskSpaceMegabytes": 512,
  "tasksDir": "tasks",
  "rootURL": "https://community-tc.services.mozilla.com",
  "sentryProject": "",
  "shutdownMachineOnIdle": false,
  "shutdownMachineOnInternalError": false,
  "workerGroup": "proj-git-cinnabar",
  "workerId": "travis-$GITHUB_RUN_ID",
  "workerType": "$workerType"
}
EOF

env

curl -OL https://github.com/taskcluster/taskcluster/releases/download/v54.4.0/generic-worker-simple-darwin-amd64
chmod +x generic-worker-simple-darwin-amd64
mkdir tasks
./generic-worker-simple-darwin-amd64 new-ed25519-keypair --file worker.key
./generic-worker-simple-darwin-amd64 run --config worker.config
case $? in
0|68)
  ;;
*)
  exit $?
  ;;
esac
