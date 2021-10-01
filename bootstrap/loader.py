import os
import sys
import tarfile
from importlib.abc import MetaPathFinder, ExecutionLoader
from importlib.util import spec_from_loader


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


class CinnabarLoader(ExecutionLoader):
    def get_filename(self, fullname):
        path = fullname.replace('.', '/') + '.py'
        if path not in modules:
            path = path[:-3] + '/__init__.py'
        return '/git-cinnabar::' + path

    def is_package(self, fullname):
        return self.get_filename(fullname).endswith('/__init__.py')

    def get_source(self, fullname):
        path = self.get_filename(fullname)[len('/git-cinnabar::'):]
        return modules[path]


loader = CinnabarLoader()


class Finder(MetaPathFinder):
    def find_spec(self, full_name, paths=None, target=None):
        if full_name.startswith('cinnabar'):
            return spec_from_loader(full_name, loader, origin=full_name)
        return None


sys.meta_path.insert(0, Finder())
