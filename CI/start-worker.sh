#!/bin/sh
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

where=$(dirname $0)
clientId=$1
workerType=$2

[ -z "$clientId" -o -z "$workerType" ] && echo Usage: $0 clientId workerType >&2 && exit 1
[ -z "$secret" ] && echo Missing key >&2 && exit 1

openssl aes-256-cbc -k "$secret" -in $where/worker-key.enc -out worker.key -d -md sha256
token=$(openssl aes-256-cbc -k "$secret" -in $where/$workerType.token.enc -d -md sha256)

unset secret

cat > worker.config <<EOF
{
  "accessToken": "$token",
  "cachesDir": "caches",
  "certificate": "",
  "clientId": "project/git-cinnabar/$clientId",
  "disableReboots": true,
  "downloadsDir": "downloads",
  "idleTimeoutSecs": 180,
  "livelogSecret": " ",
  "provisionerId": "proj-git-cinnabar",
  "publicIP": "127.0.0.1",
  "requiredDiskSpaceMegabytes": 512,
  "signingKeyLocation": "worker.key",
  "tasksDir": "tasks",
  "rootURL": "https://community-tc.services.mozilla.com",
  "workerGroup": "proj-git-cinnabar",
  "workerId": "travis-$TRAVIS_BUILD_ID",
  "workerType": "$workerType"
}
EOF

curl -OL https://github.com/taskcluster/generic-worker/releases/download/v11.1.1/generic-worker-darwin-amd64
chmod +x generic-worker-darwin-amd64
mkdir tasks
./generic-worker-darwin-amd64 run --config worker.config
case $? in
0|68)
  ;;
*)
  exit $?
  ;;
esac
