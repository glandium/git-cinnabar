# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import json
import os

rootUrl = os.environ.get(
    "TASKCLUSTER_ROOT_URL", "https://community-tc.services.mozilla.com"
)

if "TC_PROXY" in os.environ:
    PROXY_URL = os.environ.get("TASKCLUSTER_PROXY_URL", "http://taskcluster")
else:
    PROXY_URL = rootUrl
PROXY_INDEX_URL = PROXY_URL + "/api/index/v1/task/{}"
ARTIFACT_URL = rootUrl + "/api/queue/v1/task/{}/artifacts/{}"


DEFAULT_DATA = {
    "repo_name": "git-cinnabar",
    "login": "glandium",
    "commit": os.environ.get("GITHUB_SHA", "HEAD"),
    "branch": os.environ.get("GITHUB_REF_NAME", ""),
    "decision_id": "",
}
DEFAULT_DATA["repo_url"] = "https://github.com/{}/{}".format(
    DEFAULT_DATA["login"], DEFAULT_DATA["repo_name"]
)
for k in ("repo_name", "login"):
    DEFAULT_DATA["base_{}".format(k)] = DEFAULT_DATA[k]

TC_DATA = json.loads(os.environ.get("TC_DATA", json.dumps(DEFAULT_DATA)))


def get(k):
    return TC_DATA.get(k, DEFAULT_DATA[k])


TC_LOGIN = get("login")
TC_REPO_NAME = get("repo_name")
TC_REPO_URL = get("repo_url")
TC_COMMIT = get("commit")
TC_BRANCH = get("branch")
TC_BASE_LOGIN = get("base_login")
TC_BASE_REPO_NAME = get("base_repo_name")

TC_ACTION = os.environ.get("TC_ACTION")

DEFAULT_REPO = "https://hg.mozilla.org/users/mh_glandium.org/jqplot"
REPO = os.environ.get("REPO", DEFAULT_REPO)

IS_GH = "GITHUB_RUN_ID" in os.environ
IS_TC = "TASK_GROUP_ID" in os.environ
if IS_TC:
    NO_INDEX = os.environ.get("NO_INDEX")
    TC_IS_PUSH = os.environ.get("TC_IS_PUSH") == "1"
    DETERMINISTIC = os.environ.get("DETERMINISTIC")
elif IS_GH:
    NO_INDEX = True
    TC_IS_PUSH = os.environ.get("GITHUB_EVENT_NAME") == "push"
    DETERMINISTIC = True
else:
    NO_INDEX = True
    TC_IS_PUSH = True
    DETERMINISTIC = True
