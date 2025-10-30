from dataclasses import dataclass
import os
import invoke
from fabric import Connection
import subprocess

@dataclass
class Node:
    name: str
    public_ip: str
    private_ip: str
    tee_type: str
    region_id: int
    is_client: bool
    is_coordinator: bool
    port: int = 22

    def __hash__(self) -> int:
        return hash(self.name)


def run_local(cmds: list, hide=True, asynchronous=False):
    results = []
    for cmd in cmds:
        res = invoke.run(cmd, hide=hide, asynchronous=asynchronous)
        results.append(res)

    if not asynchronous:
        return [res.stdout.strip() for res in results]
    else:
        return [res.join().stdout.strip() for res in results]
    

def run_remote_public_ip(cmds: list, ssh_user, ssh_key, host: Node, hide=True):
    results = []
    conn = Connection(
        host=host.public_ip,
        user=ssh_user,
        port=host.port,
        connect_kwargs={
            "key_filename": ssh_key
        }
    )
    for cmd in cmds:
        try:
            print(cmd)
            res = conn.run(cmd, hide=hide, pty=True)
            results.append(res.stdout.strip())
        except Exception as e:
            print(e)
            results.append(str(e))

    conn.close()

    return results



def copy_remote_public_ip(src, dest, ssh_user, ssh_key, host: Node):
    '''
    Copy file from local to remote
    '''
    conn = Connection(
        host=host.public_ip,
        port=host.port,
        user=ssh_user,
        connect_kwargs={
            "key_filename": ssh_key
        }
    )

    conn.put(src, remote=dest)

    conn.close()



def copy_file_from_remote_public_ip(src, dest, ssh_user, ssh_key, host: Node):
    '''
    Copy file from remote to local
    '''
    conn = Connection(
        host=host.public_ip,
        port=host.port,
        user=ssh_user,
        connect_kwargs={
            "key_filename": ssh_key
        }
    )

    try:
        conn.get(src, local=dest, preserve_mode=True)
    except Exception as e:
        print(e)

    conn.close()


def copy_dir_from_remote_public_ip(src, dest, ssh_user, ssh_key, host: Node):
    conn = Connection(
        host=host.public_ip,
        user=ssh_user,
        port=host.port,
        connect_kwargs={
            "key_filename": ssh_key
        }
    )

    fnames = [x.strip() for x in conn.run(f"find {src} -type f -maxdepth 1", hide=True)
                                    .stdout.strip().split("\n")]

    _dest = dest[:]
    if _dest[-1] != os.path.sep:
        _dest += os.path.sep
    
    for fname in fnames:
        print(fname, _dest)
        conn.get(fname, local=_dest, preserve_mode=False)

    conn.close()


# (Helper) Executes a bash command in Python. Takes in arguments as an array
# Returns the output. 
def execute_command_args(command):
    print("Executing command: ", command)
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode !=0: 
        ret = result.stderr
    else: 
        ret = result.stdout
    return ret.rstrip()

# (Helper) Execute a bash command in Python.  Takes in arguments as a string and
# splits arguments into an array. Note that for some commands, this can create issues.
# Using @executeCommandArgs is the recommended and more robust way to invoke a command.
def execute_command(command):
    return execute_command_args(command.split())

# (Helper) Sends file to remote host
def send_remote_file(local_file, user, h, remote_dir, key=None, port=None):
    port_string = "-P " + str(port)  + " " if port else " "
    if not key:
        cmd = "scp -O -o StrictHostKeyChecking=no  " + \
            local_file + " " + user + "@" + h + ":" + remote_dir
    else:
        cmd = "scp -O -o StrictHostKeyChecking=no -i " + key + \
            " " + port_string + local_file + " " + user + "@" + h + ":" + remote_dir
    return execute_command(cmd)

# (Helper) Executes command on remote host
def execute_remote_command(user, host, command, key=None, port=None):
    if not key:
        if port:
          cmd = ["ssh","-o", "StrictHostKeyChecking=no", "-t " , "-p",  str(port), user + "@" + host, "\"" + command + "\""]
        else: 
          cmd = ["ssh","-o", "StrictHostKeyChecking=no", "-t ", user + "@" + host, "\"" + command + "\""]
    else:
        if port: 
          cmd = ["ssh", "-o", "StrictHostKeyChecking=no", "-t", "-i", 
            key, "-p", str(port), user + "@" + host,  "\"" + command + "\""]
        else:
          cmd = ["ssh", "-o", "StrictHostKeyChecking=no", "-t", "-i", 
                key, user + "@" + host,  "\"" + command + "\""]
    print("Executing remote command: ", cmd)
    result = subprocess.run(cmd, capture_output=True, text=True)
    print ("Result: ", result)
    if result.returncode !=0: 
        ret = result.stderr
    else: 
        ret = result.stdout
    return ret.rstrip()