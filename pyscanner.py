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

parser = argparse.ArgumentParser(description='A wrapper to mount overlay(only this supported at the moment) '
                                             'image layer and scan. Store result in directory for processing.',
                                 epilog='%s \nSample usage: --image-url=<image_url|example.com/repo/image> '
                                        '--image-tag=<image_tag|latest> --image-mount=<image_mount_dir>',
                                 formatter_class=argparse.RawTextHelpFormatter)

parser.add_argument('--image-url', action='store', dest='image_url', help='The location of the image in upstream repo',
                    required=True)
parser.add_argument('--image-tag', action='store', dest='image_tag', help='The tag for the image',
                    required=True)
parser.add_argument('--image-mount', action='store', dest='image_mount', help='The location of the overlay image mount '
                                                                              'point.',
                    required=True)
parser.add_argument('--scan-name', action='store', dest='scan_name', help='This scan runtime name.',
                    required=True)

options = parser.parse_args()

# Set up the date & logger
todays_date = str(datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d--%H_%M'))
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
                    datefmt='%m-%d %H:%M',
                    filename='/var/log/pyscanner_%s.log' % todays_date,
                    filemode='w')
# define a Handler which writes INFO messages or higher to the sys.stderr
console = logging.StreamHandler()
console.setLevel(logging.INFO)
# set a format which is simpler for console use
formatter = logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s')
console.setFormatter(formatter)
logging.getLogger('').addHandler(console)

openscap_image = "registry.access.redhat.com/rhel7/openscap:latest"
results_parent_dir = '/openscap/scanner_results'
image_pull_timer_secs = 300.0
image_name = '{}:{}'.format(options.image_url, options.image_tag)
libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
libc.mount.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p)

if os.getuid() == 0:
    try:
        docker_apiclient = docker.APIClient(base_url='unix://var/run/docker.sock')
    except docker.errors.APIError as err:
        raise err
else:
    logging.error("Opps: Root user required to interact with docker daemon. Terminating...")
    sys.exit(1)


def make_dir(dirname):
    try:
        os.makedirs(dirname, 0744)
    except os.error as err:
        raise err


def mount_img_layer(source, target, fs, options=''):
    ret = libc.mount(source, target, fs, 0, options)
    if ret < 0:
        errno = ctypes.get_errno()
        raise OSError(errno, "Error mounting {} ({}) on {} with options '{}': {}".
                      format(source, fs, target, options, os.strerror(errno)))


def unmount_dir(target):
    ret = libc.umount(target)
    if ret != 0:
        logging.error("Unmount unsuccessful " + str(libc.errno))
        raise OSError(errno, "Unmount unsuccessful " + str(libc.errno))


def timeout(max_timeout):
    # Defined a timeout decorator
    def timeout_decorator(item):
        """Wrap the original function."""
        @functools.wraps(item)
        def func_wrapper(*args, **kwargs):
            """Closure for function."""
            pool = multiprocessing.pool.ThreadPool(processes=1)
            async_result = pool.apply_async(item, args, kwargs)
            # raises a TimeoutError if execution exceeds max_timeout
            return async_result.get(max_timeout)
        return func_wrapper
    return timeout_decorator


@timeout(image_pull_timer_secs)
def pull_image_registry(image_url, image_tag=None):
    try:
        docker_apiclient.pull(image_url, tag=image_tag)
    except docker.errors.APIError as err:
        raise err


def get_image_info(img_name):
    try:
        image_response = docker_apiclient.inspect_image(img_name)
        image_info = image_response['GraphDriver']['Data']
        return image_info
    except docker.errors.APIError as err:
        raise err


if __name__ == "__main__":
    try:
        logging.info("Pulling image from {} with 300.0 secs time-out. Please wait...".format(image_name))
        pull_image_registry(options.image_url, image_tag=options.image_tag)
        if docker_apiclient.images(image_name):
            logging.info("Image {} succesfully pulled to local docker...".format(image_name))
            for k, v in docker_apiclient.images(image_name)[0].iteritems():
                logging.info("{} : {}".format(k, v))
            image_info = get_image_info(image_name)
            img_upperdir = image_info['UpperDir']
            img_lowerdir = image_info['LowerDir']
            img_workdir = image_info['WorkDir']
            if os.path.ismount(options.image_mount):
                unmount_dir(options.image_mount)
            else:
                if not os.path.isdir(options.image_mount):
                    make_dir(options.image_mount)
            mount_opts = "lowerdir=%s,upperdir=%s,workdir=%s" % (img_lowerdir, img_upperdir, img_workdir)
            try:
                logging.debug("Attemping to mount image layer... ")
                mount_img_layer('overlay', options.image_mount, 'overlay', options=mount_opts)
                logging.info("Overlay image mounted on {}".format(options.image_mount,))

                docker_cliclient = docker.from_env()
                docker_cmd_args = "oscapd-evaluate scan --no-standard-compliance " \
                                  "--targets chroot:///scanin --output /scanout -j1"
                result_directory = "{}/{}".format(results_parent_dir, options.scan_name)
                if not os.path.isdir(results_parent_dir):
                    make_dir(results_parent_dir)
                    make_dir(result_directory)
                docker_vol_dict = {'/etc/localtime': {'bind': '/etc/locatime', 'mode': 'ro'},
                                   options.image_mount: {'bind': '/scanin', 'mode': 'rw'},
                                   result_directory: {'bind': '/scanout', 'mode': 'rw,Z'},
                                   '/etc/oscapd': {'bind': '/etc/oscapd', 'mode': 'ro'}}
                try:
                    logging.info("Starting to run the scanner against {} overlay mount...".format(image_name))
                    docker_cliclient.containers.run(openscap_image, tty=True, remove=True, command=docker_cmd_args,
                                                    volumes=docker_vol_dict)
                    logging.info("Finished scanning the overlay mount")
                    logging.info("Umounting temporary overlay mount {}".format(options.image_mount))
                    unmount_dir(options.image_mount)
                    logging.info("Scan finished, result available here: {}".format(result_directory))
                except docker.errors.ContainerError or docker.errors.ImageNotFound or docker.errors.APIError as err:
                    raise err
            except RuntimeError as err:
                raise err
        else:
            logging.error("Unable to pulled {} to local docker...".format(image_name))
            sys.exit(1)
    except RuntimeError as err:
        raise err