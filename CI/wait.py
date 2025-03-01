# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import sys

from gha import runs_url, wait_completion, wait_run


def main():
    run = wait_run(runs_url(), ".github/workflows/ci.yml")
    run_id = run["id"]
    url = run["jobs_url"]
    wait_completion(url, "decision")
    jobs = wait_completion(url, "build")
    if not all(job.get("conclusion") == "success" for job in jobs):
        print("Some build jobs failed.", file=sys.stderr)
        return 1

    with open("run_id", "w") as out:
        out.write(str(run_id))


if __name__ == "__main__":
    main()
