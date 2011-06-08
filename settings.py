import os.path
import glob

try:
    PROJECT_ROOT
except NameError:
    PROJECT_ROOT = os.path.dirname(__file__)

conf_files_path = os.path.join(PROJECT_ROOT, 'settings', '*.conf')
conffiles = glob.glob(conf_files_path)
conffiles.sort()

for f in conffiles:
    execfile(os.path.abspath(f))
