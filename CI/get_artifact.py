# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import argparse
import json
import shutil
import tempfile
import zipfile

from gha import artifacts_url, urlopen

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("name")
    args = parser.parse_args()

    with urlopen(artifacts_url(args.name)) as fh:
        artifacts = json.load(fh)
    for artifact in artifacts.get("artifacts", []):
        if artifact.get("workflow_run", {}).get("id") == args.run_id:
            url = artifact.get("archive_download_url")
            with tempfile.TemporaryFile() as fh:
                shutil.copyfileobj(urlopen(url), fh)
                assert fh.tell() == artifact["size_in_bytes"]
                fh.seek(0)
                with zipfile.ZipFile(fh) as zip:
                    zip.extractall("artifacts")
