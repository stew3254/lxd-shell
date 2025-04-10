#!/usr/bin/env python3
import argparse
import time
from threading import Thread
from typing import Tuple

import pylxd
import random
import redis
import signal
import sys
import subprocess
import string
import threading

MAX_INSTANCES = 10

# Use this signal handler before we do anything substantial
def base_handler(sig, frame):
    sys.exit(0)

def parse_args():
    parser = argparse.ArgumentParser(description="LXD Shell")
    parser.add_argument("lab", type=str, help="The name of the lab to run")
    parser.add_argument("--time", "-t", type=int, default=60, help="The number of minutes a lab can run for")
    parser.add_argument("--endpoint", "-e", type=str, default=None, help="The LXD server endpoint")
    parser.add_argument("--client-cert", "-c", type=str, required=False, help="The client cert for authentication")
    parser.add_argument("--client-key", "-k", type=str, required=False, help="The client key for authentication")
    parser.add_argument("--server-cert", "-s", type=str, default=False, required=False, help="The server cert for verification")
    return vars(parser.parse_args())

# def setup_redis(client: redis.Redis):
#     client.set("max_instances", 10)

def read_output(shell: subprocess.Popen):
    while True:
        output = shell.stdout.readline()
        if output:
            print(output.decode(), end='')
        elif shell.poll() is not None:
            break

def write_input(shell: subprocess.Popen):
    while True:
        user_input = input()
        if user_input:
            shell.stdin.write(user_input + "\n")
            shell.stdin.flush()


def create_instance(lxd_client: pylxd.Client, redis_client: redis.Redis, args: dict) -> tuple[str, int]:
    instance_name = f"lab-{args['lab']}-{''.join(random.choice(string.ascii_lowercase) for i in range(6))}"

    # Add a sig handler for cleanup since we might not finish
    def handle(sig, frame):
        cleanup(lxd_client, redis_client, instance_name)

    signal.signal(signal.SIGINT, lambda sig, frame : None)
    signal.signal(signal.SIGTERM, handle)

    # Add the instance to the DB
    if redis_client.llen("instances") < MAX_INSTANCES:
        index = redis_client.lpush("instances", instance_name)
    else:
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
    instance.start(wait=True)

    return instance_name, index

def spawn_shell(instance: str) -> tuple[Thread, Thread]:
    shell = subprocess.Popen(
        ["lxc", "shell", instance],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text = True,
        bufsize = 1,
        universal_newlines = True
    )

    # Create the read thread
    read_thread = threading.Thread(target=read_output, args=(shell,))
    # Ensure the thread exits when the main program exits
    read_thread.daemon = True
    read_thread.start()

    # Create the write thread
    write_thread = threading.Thread(target=write_input, args=(shell,))
    # Ensure the thread exits when the main program exits
    write_thread.daemon = True
    write_thread.start()

    return read_thread, write_thread

def cleanup(lxd_client: pylxd.Client, redis_client: redis.Redis, name: str, index: int):
    redis_instance_name = redis_client.lindex("instances", index)
    # The instance must not exist yet, so just exit
    if redis_instance_name != name:
        return

    # TODO don't use a redis list, it's better to have a counter and separate variables
    redis_client.l

    # Get the instance
    instance = lxd_client.instances.get(name)
    if instance is None:



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

    # Setup Redis
    redis_client = redis.Redis(host="localhost", port=6379, decode_responses=True)
    # setup_redis(REDIS_CLIENT)

    # Create the instance
    instance, index = create_instance(lxd_client, redis_client, args)

    # Spawn a shell for the instance
    read_thread, write_thread = spawn_shell(instance)

    # Create a timer so that the instance must be stopped after configured timeout
    def timeout():
        time.sleep(args["timeout"]*60)
        cleanup(lxd_client, redis_client, instance, index)

    timeout_thread = threading.Thread(target=timeout)
    timeout_thread.start()

    # Wait for the write thread to finish
    write_thread.join()

    # Call the cleanup since we are done with the instance
    cleanup(lxd_client, redis_client, instance, index)


if __name__ == "__main__":
    main()
