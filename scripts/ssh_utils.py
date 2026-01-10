from dataclasses import dataclass
import os
import invoke
from fabric import Connection

@dataclass
class Node:
    name: str
    public_ip: str
    private_ip: str
    tee_type: str
    region_id: int
    is_client: bool
    is_coordinator: bool

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
    

def run_remote_public_ip(cmds: list, ssh_user, ssh_key, host: Node|str, hide=True, timeout=None):
    results = []

    if isinstance(host, Node):
        host = host.public_ip

    conn = Connection(
        host=host,
        user=ssh_user,
        connect_timeout=timeout,
        connect_kwargs={
            "key_filename": ssh_key
        }
    )
    for cmd in cmds:
        try:
            res = conn.run(cmd, hide=hide, pty=True, timeout=timeout)
            results.append(res.stdout.strip())
        except Exception as e:
            results.append(str(e))

    conn.close()

    return results



def copy_remote_public_ip(src, dest, ssh_user, ssh_key, host: Node):
    '''
    Copy file from local to remote
    '''
    conn = Connection(
        host=host.public_ip,
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
