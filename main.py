#!/usr/bin/env python3
import argparse
import fcntl
import os
from io import TextIOWrapper
from os import close

import pty
import pylxd
import random
import redis
import signal
import sys
import subprocess
import string
import threading
import time

# TODO implement proper locking to avoid race conditions

MAX_INSTANCES = 10

# Create a multiprocess lock
class Lock:
    def __init__(self, filename: str):
        self.filename = filename
        self.f = open(filename, "w+")

    def __del__(self):
        self.f.close()

    def acquire(self):
        fcntl.flock(self.f, fcntl.LOCK_EX)

    def release(self):
        fcntl.flock(self.f, fcntl.LOCK_UN)

# Use this signal handler before we do anything substantial
def base_handler(sig, frame):
    sys.exit(0)

def parse_args():
    parser = argparse.ArgumentParser(description="LXD Shell")
    parser.add_argument("lab", type=str, help="The name of the lab to run")
    parser.add_argument("--timeout", "-t", type=int, default=60, help="The number of minutes a lab can run for")
    parser.add_argument("--endpoint", "-e", type=str, default=None, help="The LXD server endpoint")
    parser.add_argument("--client-cert", "-c", type=str, required=False, help="The client cert for authentication")
    parser.add_argument("--client-key", "-k", type=str, required=False, help="The client key for authentication")
    parser.add_argument("--server-cert", "-s", type=str, default=False, required=False, help="The server cert for verification")
    return vars(parser.parse_args())

def create_instance(lock: Lock, lxd_client: pylxd.Client, redis_client: redis.Redis, args: dict) -> str:
    instance_name = f"lab-{args['lab']}-{''.join(random.choice(string.ascii_lowercase) for i in range(6))}"
    lock.acquire()
    # Regenerate the name as long as we need to get a unique one
    while redis_client.get(instance_name):
        instance_name = f"lab-{args['lab']}-{''.join(random.choice(string.ascii_lowercase) for i in range(6))}"
    lock.release()

    # Add a sig handler for cleanup since we might not finish
    def handle(sig, frame):
        cleanup(lock, lxd_client, redis_client, instance_name)

    signal.signal(signal.SIGINT, lambda sig, frame : None)
    signal.signal(signal.SIGTERM, handle)

    # Add the instance to the DB
    lock.acquire()
    num_instances = int(redis_client.get("num_instances"))
    if num_instances < int(redis_client.get("max_instances")):
        # Add a new instance
        redis_client.set(instance_name, 1)
        redis_client.set("num_instances", num_instances + 1)
    else:
        lock.release()
        print("Too many instances")
        sys.exit(1)

    # Create and start the instance
    instance = lxd_client.instances.create(
        {
            "name": instance_name,
            "type": "container",
            "architecture": "x86_64",
            "ephemeral": True,
            "profiles": [args["lab"]],
            "source": {
                'type': 'image',
                "mode": "pull",
                "server": "https://cloud-images.ubuntu.com/releases/",
                "protocol": "simplestreams",
                'alias': 'n',
            }
        },
        wait=True
    )
    lock.release()
    instance.start(wait=True)

    return instance_name

def read_output(shell: subprocess.Popen):
    while True:
        output = shell.stdout.readline()
        if output:
            print(output, end='')
        elif shell.poll() is not None:
            return

def write_input(shell: subprocess.Popen):
    while True:
        try:
            user_input = input()
        except EOFError:
            shell.send_signal(signal.SIGTERM)
            return
        if user_input:
            shell.stdin.write(user_input + "\n")
            shell.stdin.flush()

def clean_exit():
    print("Gracefully shutting down")
    sys.exit(0)


def cleanup(lock: Lock, lxd_client: pylxd.Client, redis_client: redis.Redis, name: str):
    lock.acquire()
    # The instance doesn't exist yet, so just exit
    if not redis_client.get(name):
        lock.release()
        clean_exit()

    # Remove the instance from redis because we don't need it anymore
    redis_client.delete(name)
    redis_client.set("num_instances", int(redis_client.get("num_instances")) - 1)

    # Get the instance
    instance = lxd_client.instances.get(name)
    lock.release()
    if instance is None:
        clean_exit()

    # Delete the instance
    instance.stop(wait=True)
    try:
        instance.delete(wait=True)
    except AttributeError:
        pass
    clean_exit()

def setup(lock: Lock, redis_client: redis.Redis):
    lock.acquire()
    if redis_client.get("max_instances") is None:
        redis_client.set("max_instances", MAX_INSTANCES)
    if redis_client.get("num_instances") is None:
        redis_client.set("num_instances", 0)
    lock.release()

def main():
    signal.signal(signal.SIGINT, base_handler)
    signal.signal(signal.SIGTERM, base_handler)
    args = parse_args()

    # Setup the LXD client
    if args["endpoint"] is None:
       lxd_client = pylxd.Client()
    elif args["client_cert"] is None or args["client_key"] is None:
        print("Must supply a client cert and key path when using a remote endpoint")
        sys.exit(1)
    else:
        lxd_client = pylxd.Client(
            endpoint=args["endpoint"],
            cert=(args["client_cert"], args["client_key"]),
            verify=args["server_cert"]
        )

    # Define a lock on our resources
    lock = Lock("/tmp/lxd_shell_lock")

    # Setup Redis
    redis_client = redis.Redis(host="localhost", port=6379, decode_responses=True)
    setup(lock, redis_client)

    # Create the instance
    instance = create_instance(lock, lxd_client, redis_client, args)

    # Create a timer so that the instance must be stopped after configured timeout
    def timeout():
        time.sleep(args["timeout"]*60)
        cleanup(lock, lxd_client, redis_client, instance)

    timeout_thread = threading.Thread(target=timeout)
    timeout_thread.daemon = True
    timeout_thread.start()

    # Spawn a shell for the instance
    pty.spawn(["lxc", "shell", instance])

    # Call the cleanup since we are done with the instance
    cleanup(lock, lxd_client, redis_client, instance)


if __name__ == "__main__":
    main()
