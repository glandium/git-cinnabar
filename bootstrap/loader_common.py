import os
import sys
import tarfile

input = int(os.environ["GIT_CINNABAR_BOOTSTRAP_FD"])
if sys.platform == 'win32':
    import msvcrt
    input = msvcrt.open_osfhandle(input, os.O_RDONLY)
tar = tarfile.open(fileobj=os.fdopen(input, 'rb'), mode='r|')
modules = {}
for f in tar:
    content = tar.extractfile(f).read().decode()
    modules['cinnabar/' + f.name] = content

del tar
