#!/usr/bin/python
import os
import sys
import ctypes
import ctypes.util
import docker
from docker.api import image
import argparse
import multiprocessing.pool
import functools
import logging
import datetime
import time

# Setting up argument parser.
parser = argparse.ArgumentParser(description='A wrapper to mount overlay(only this supported at the moment) '
                                             'image layer and scan. Store result in directory for processing.',
                                 epilog='\nSample usage: --image-url=example.com/repo/myimage '
                                        '--image-tag=2.3.5 --image-mount=/mnt/scaprun-myimage-latest '
                                        '--result-dir=/openscap/results --scan-name=repo-myimage-latest-1',
                                 formatter_class=argparse.RawTextHelpFormatter)

parser.add_argument('--image-url', action='store', dest='image_url', help='The location of the image in upstream repo',
                    required=True)
parser.add_argument('--image-tag', action='store', dest='image_tag', help='The tag for the image',
                    required=True)
parser.add_argument('--result-dir', action='store', dest='result_dir', help='The parent directory for results.',
                    required=True)
parser.add_argument('--image-mount', action='store', dest='image_mount', help='The location of the overlay image mount '
                                                                              'point.',
                    required=True)
parser.add_argument('--scan-name', action='store', dest='scan_name', help='This scan runtime name.',
                    required=True)

options = parser.parse_args()

# Set up the date & logger
logging_directory = '/var/log/pyscanner'
if not os.path.isdir(logging_directory):
    os.mkdir(logging_directory)
todays_date = str(datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d--%H_%M'))
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
                    datefmt='%m-%d %H:%M',
                    filename='{}/pyscanner_{}.log'.format(logging_directory, todays_date),
                    filemode='w')
out = logging.StreamHandler()
out.setLevel(logging.INFO)
formatter = logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s')
out.setFormatter(formatter)
logging.getLogger('').addHandler(out)

# Defined where we should fetch the CVE OVAL
redhat_upstream_cve_oval = 'http://www.redhat.com/security/data/oval/com.redhat.rhsa-all.xml'
cve_oval_filename = 'com.redhat.rhsa-all.xml'

# Defined result shared parent directory.
results_parent_dir = options.result_dir

# Defined where should we download the OVAL files to.
oval_definition_file_dir = '/tmp'

# Defined how many seconds should we wait for pulling image.
image_pull_timer_secs = 300.0

# Defined how many seconds should we wait for scanning.
scanning_timer_secs = 1200.0

# Construct image name from arguments supplied.
image_name = '{}:{}'.format(options.image_url, options.image_tag)

# Initiate ctypes for mount and unmount image.
libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
libc.mount.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p)

# We need to run as root for sure.
if os.getuid() == 0:
    try:
        docker_api_client = docker.APIClient(base_url='unix://var/run/docker.sock')
    except docker.errors.APIError as err:
        raise err
else:
    logging.error("Opps: Root user required to interact with docker daemon. Terminating...")
    sys.exit(1)

# Create directory function
# noinspection PyShadowingNames
def make_dir(dirname):
    try:
        os.makedirs(dirname, 0744)
    except os.error as err:
        raise err


# Generic mount function using libc implementation.
# noinspection PyShadowingNames
def mount_img_layer(source, target, fs, options=''):
    ret = libc.mount(source, target, fs, 0, options)
    if ret < 0:
        errno = ctypes.get_errno()
        raise OSError(errno, "Error mounting {} ({}) on {} with options '{}': {}".
                      format(source, fs, target, options, os.strerror(errno)))


# Generic unmount function using libc implementation
def unmount_dir(target):
    ret = libc.umount(target)
    if ret != 0:
        logging.error("Unmount unsuccessful " + str(libc.errno))
        raise OSError(errno, "Unmount unsuccessful " + str(libc.errno))


# A decorator to raise timed out when max_timeout reached.
def timeout(max_timeout):
    # Defined a timeout decorator
    def timeout_decorator(item):
        # Wrap this functions."
        @functools.wraps(item)
        def func_wrapper(*args, **kwargs):
            pool = multiprocessing.pool.ThreadPool(processes=1)
            async_result = pool.apply_async(item, args, kwargs)
            return async_result.get(max_timeout)
        return func_wrapper
    return timeout_decorator


# Implement timer decorator for image pull function.
@timeout(image_pull_timer_secs)
def pull_image_registry(image_url, image_tag=None):
    try:
        docker_api_client.pull(image_url, tag=image_tag)
    except docker.errors.APIError as err:
        raise err


# Read image info and return overlay layer informations.
def get_image_info(img_name):
    try:
        image_response = docker_api_client.inspect_image(img_name)
        image_info = image_response['GraphDriver']['Data']
        return image_info
    except docker.errors.APIError as err:
        raise err

@timeout(scanning_timer_secs)
def run_oscap_scan(args):
    try:
        os.system(args)
    except OSError as err:
        raise err


if __name__ == "__main__":
    try:
        # Attempt to pull image now.
        logging.info("Pulling image from {} with 300.0 secs time-out. Please wait...".format(image_name))
        pull_image_registry(options.image_url, image_tag=options.image_tag)

        # Now we check, if the image we pull exists on local docker. If not exit with exit_code 1.
        if docker_api_client.images(image_name):
            logging.info("Image {} succesfully pulled to local docker...".format(image_name))

            # Iterate overlay image information and print in log file as debug information.
            for k, v in docker_api_client.images(image_name)[0].iteritems():
                logging.debug("{} : {}".format(k, v))

            # Get overlay image information to supply during mounting options later.
            image_info = get_image_info(image_name)
            img_upperdir = image_info['UpperDir']
            img_lowerdir = image_info['LowerDir']
            img_workdir = image_info['WorkDir']

            # We need to make sure that nothing is mount prior actual scanning and processing.
            # Using same options.scan_name will resulted in previous data to be removed forcefully.
            if os.path.ismount(options.image_mount):
                unmount_dir(options.image_mount)
            else:
                if not os.path.isdir(options.image_mount):
                    make_dir(options.image_mount)
            # Construct string for overlay fs mounting options.
            mount_opts = "lowerdir=%s,upperdir=%s,workdir=%s" % (img_lowerdir, img_upperdir, img_workdir)

            try:
                # Mount image layer as overlay mount.
                logging.debug("Attemping to mount image layer... ")
                mount_img_layer('overlay', options.image_mount, 'overlay', options=mount_opts)
                logging.info("Overlay image mounted on {}".format(options.image_mount))

                # Now let defined where we should put those scan result inside the parent result directory
                result_directory = "{}/{}".format(results_parent_dir, options.scan_name)

                # Ensure we have no OSError because of missing/existing directory
                if not os.path.isdir(results_parent_dir):
                    make_dir(results_parent_dir)
                    make_dir(result_directory)
                elif os.path.isdir(result_directory):
                    import shutil
                    shutil.rmtree(result_directory)
                    make_dir(result_directory)
                else:
                    make_dir(result_directory)


                try:
                    try:
                        # Now let`s get latest CVE OVAL definition
                        logging.info("Fetching latest CVE OVAL definition from Red Hat...")
                        # We turned on -N flag so wget will only get newer file and overwrite it.
                        oval_definition_file = '{}/{}'.format(oval_definition_file_dir, cve_oval_filename)
                        os.system('cd {}; wget --no-verbose -N  {}'.format(oval_definition_file_dir, redhat_upstream_cve_oval))
                    except OSError as err:
                        raise err

                    # Construct CLI to be executed on the system for scanning.
                    oscapd_cmd_args = "oscap-chroot {0} oval eval --results  " \
                                      "{1}/rhsa-results-oval.xml --report {1}/oval-report.html " \
                                      "{2}/com.redhat.rhsa-all.xml".format(options.image_mount, result_directory,
                                                                           oval_definition_file_dir)

                    # Let`s do the scanning now.
                    logging.info("Starting to run the scanner against {} overlay mount.Please be patient..."
                                 .format(image_name))
                    logging.debug("Executing command: {}".format(oscapd_cmd_args))
                    run_oscap_scan(oscapd_cmd_args)
                    logging.info("Finished scanning the overlay mount")

                    # We have finished let`s clean up the mount point.
                    logging.info("Umounting temporary overlay mount {}".format(options.image_mount))
                    unmount_dir(options.image_mount)
                    logging.info("Scan finished, result available here: {}".format(result_directory))

                    # If result placed in html, let`s fix the permission so Apache(uid=48) can read this folder.
                    if "/var/www/html" in result_directory:
                        os.system("chown apache.apache -R /var/www/html/")

                except os.error as err:
                    raise err
            except RuntimeError as err:
                raise err
        else:
            logging.error("Unable to pulled {} to local docker...".format(image_name))
            sys.exit(1)
    except RuntimeError as err:
        raise err

