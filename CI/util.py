# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import os
import subprocess


def build_commit(head="HEAD"):
    return subprocess.check_output(
        [
            "git",
            "-C",
            os.path.join(os.path.dirname(__file__), ".."),
            "rev-parse",
            "--verify",
            head,
        ],
        text=True,
        stderr=open(os.devnull, "wb"),
    ).strip()
