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
parser.add_argument('--image-tag', action='store', dest='image_tag', help='The tag for the image to be scanned.',
                    required=True)
parser.add_argument('--result-dir', action='store', dest='result_dir', help='The parent directory for results. '
                                                                            'This host directory.', required=True)
parser.add_argument('--image-mount', action='store', dest='image_mount', help='The location of the overlay image mount '
                                                                              'point.', required=True)
parser.add_argument('--scan-name', action='store', dest='scan_name', help='This scan runtime name. '
                                                                          'Using same name will forcefully '
                                                                          'removed previous result.', required=True)
options = parser.parse_args()

# Set up the date & logger
logging_directory = '/var/log/pyscanner'
if not os.path.isdir(logging_directory):
    os.mkdir(logging_directory)
todays_date = str(datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d--%H_%M'))
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(levelname)-8s %(message)s',
                    datefmt='%m-%d %H:%M',
                    filename='{}/pyscanner_{}.log'.format(logging_directory, todays_date),
                    filemode='w')
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter('%(levelname)-8s %(message)s')
console.setFormatter(formatter)
logging.getLogger('').addHandler(console)

# Defined which openscap image we going to use.
openscap_image = "registry.access.redhat.com/rhel7/openscap:latest"

# Defined result shared parent directory.
results_parent_dir = options.result_dir

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
        # Instantiate Docker APIClient and connect to docker Unix socket.
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
        os.makedirs(dirname)
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
    def timeout_decorator(item):
        # Wrap this functions.
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
    # noinspection PyShadowingNames
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
def run_image_scan(openscap_image_name, volume_bind_dict, **kwargs):

    try:
        # Instantiate docker CLI. Some method like containers.run is not available from APIClient class.
        docker_cli_client = docker.from_env()
        docker_container_cli = docker_cli_client.containers
        docker_container_cli.run(openscap_image_name, tty=kwargs['tty'], remove=kwargs['remove'],
                                 command=kwargs['command'], volumes=volume_bind_dict,)
    except docker.errors.ContainerError or docker.errors.ImageNotFound or docker.errors.APIError as err:
        raise err


# We are not being imported, run directly as "__main__" script.
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
                logging.info("Attemping to mount image layer for {}...".format(image_name))
                mount_img_layer('overlay', options.image_mount, 'overlay', options=mount_opts)
                logging.info("Overlay image mounted on {}".format(options.image_mount))

                # Build up command to be passed to container.
                docker_cmd_args = "oscapd-evaluate scan --no-standard-compliance " \
                                  "--targets chroot:///scanin --output /scanout -j2"

                # Now let defined where we should put those scan result inside the parent result directory.
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

                # Construct volume dict to be mounted on the openscap container.
                docker_vol_dict = {'/etc/localtime': {'bind': '/etc/locatime', 'mode': 'ro'},
                                   options.image_mount: {'bind': '/scanin', 'mode': 'rw'},
                                   result_directory: {'bind': '/scanout', 'mode': 'rw,Z'},
                                   '/etc/oscapd': {'bind': '/etc/oscapd', 'mode': 'ro'}}

                try:

                    # Now we run a openscap container and auto removed it when container exit.
                    logging.info("Scanning against {} overlay mount...".format(image_name))
                    run_image_scan(openscap_image, docker_vol_dict, tty=True, remove=True, command=docker_cmd_args)
                    logging.info("Finished scanning the overlay mount...")

                    # Now we have finished, let`s clean up the mount point.
                    logging.info("Umounting temporary overlay mount {}...".format(options.image_mount))
                    unmount_dir(options.image_mount)

                    # Let`s print out where to get the results.
                    logging.info("Scan finished, result available here: {}...".format(result_directory))

                except RuntimeError as err:
                    raise err

            except RuntimeError as err:
                raise err

        else:
            logging.error("Unable to pulled {} to local docker...".format(image_name))
            sys.exit(1)

    except RuntimeError as err:
        raise err
