import coverage
import atexit


cov = coverage.Coverage()


def cleanup():
    import os
    cov.stop()
    data_file = cov.get_option("run:data_file")
    if os.path.exists(data_file):
        cov.combine(data_paths=[data_file])
    cov.save()


atexit.register(cleanup)
cov.start()
