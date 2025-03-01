# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import functools
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

from variables import TC_BRANCH, TC_COMMIT, TC_LOGIN, TC_REPO_NAME


@functools.cache
def get_token():
    if token := os.environ.get("GITHUB_TOKEN"):
        return token
    if proxy_url := os.environ.get("TASKCLUSTER_PROXY_URL"):
        with urllib.request.urlopen(
            f"{proxy_url}/api/secrets/v1/secret/project/git-cinnabar/gha"
        ) as fh:
            return json.load(fh)["secret"]["token"]


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)


def urlopen(url):
    opener = urllib.request.build_opener(NoRedirectHandler)
    if urllib.parse.urlparse(url).hostname == "api.github.com":
        opener.addheaders.append(("Accept", "application/vnd.github+json"))
        opener.addheaders.append(("Authorization", f"token {get_token()}"))
    try:
        return opener.open(url)
    except urllib.error.HTTPError as e:
        if e.code in (301, 302, 303, 307, 308) and "Location" in e.headers:
            return urlopen(e.headers["Location"])
        raise


def wait_run(url, path, wait=5):
    while True:
        with urlopen(url) as fh:
            workflow = json.load(fh)
        for run in workflow.get("workflow_runs", []):
            if run.get("path") == path:
                return run
        time.sleep(wait)


def get_jobs(url, name):
    with urlopen(url) as fh:
        jobs = json.load(fh)
    return [job for job in jobs.get("jobs", []) if job.get("name", "").startswith(name)]


def wait_completion(url, name, wait=5):
    while True:
        jobs = get_jobs(url, name)
        if jobs and all(
            job.get("status") == "completed"
            or job.get("conclusion") not in (None, "success")
            for job in jobs
        ):
            break
        time.sleep(wait)
    return jobs


def runs_url():
    return f"https://api.github.com/repos/{TC_LOGIN}/{TC_REPO_NAME}/actions/runs?branch={TC_BRANCH}&event=push&head_sha={TC_COMMIT}"


def artifacts_url(name):
    return f"https://api.github.com/repos/{TC_LOGIN}/{TC_REPO_NAME}/actions/artifacts?name={name}"
