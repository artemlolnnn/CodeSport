import os
import signal
import subprocess
import time

'''  Проверяем код на опаснные действия..  '''

try:
    import resource
    import pwd
    HAS_RLIMIT = os.name == 'posix'
except ImportError:
    resource = None
    pwd = None
    HAS_RLIMIT = False


class SandboxResult:
    __slots__ = ('returncode', 'stdout', 'stderr', 'timed_out', 'error')

    def __init__(self, returncode=None, stdout='', stderr='',
                 timed_out=False, error=None):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.timed_out = timed_out
        self.error = error


def _nobody_ids():
    """(uid, gid) непривилегированного пользователя, если мы root."""
    if not HAS_RLIMIT or os.getuid() != 0:
        return None, None
    for name in ('nobody', 'daemon', 'www-data'):
        try:
            e = pwd.getpwnam(name)
            return e.pw_uid, e.pw_gid
        except KeyError:
            continue
    return None, None


def _make_preexec(mem_mb, cpu_sec, fsize_mb, nproc, uid, gid):
    def preexec():
        # Своя process group — можно убить всё дерево процессов на таймауте
        os.setsid()

        if resource is not None:
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_sec, cpu_sec + 1))

            # Адресное пространство = защита от fork-bomb по памяти
            mem = mem_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (mem, mem))

            # Максимальный размер файла — защита от забивания диска
            fsize = fsize_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize))

            # Максимум процессов/потоков — защита от fork-bomb
            resource.setrlimit(resource.RLIMIT_NPROC, (nproc, nproc))

            # Никаких core-дампов (иначе сольёт память на диск)
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

            # Максимум открытых файлов
            try:
                resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
            except (ValueError, OSError):
                pass

        # Drop privileges — ПОСЛЕ всех setrlimit
        if uid is not None:
            try:
                os.setgroups([])
                os.setgid(gid)
                os.setuid(uid)
            except OSError:
                pass

    return preexec


def _kill_group(proc):
    try:
        pgid = os.getpgid(proc.pid)
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except Exception:
            pass


def run_sandboxed(cmd, input_data, timeout, workdir,
                  mem_mb=256, cpu_sec=None, fsize_mb=16, nproc=32,
                  env=None):
    """
    Запускает cmd с:
      - собственной process group (таймаут убивает всё дерево)
      - rlimits на CPU / память / размер файла / число процессов
      - сбросом привилегий до nobody, если мы root
      - cwd = workdir (изолированная временная папка)
      - чистым env без секретов проекта
    """
    if cpu_sec is None:
        cpu_sec = max(1, int(timeout) + 1)

    uid, gid = _nobody_ids()

    # workdir должен принадлежать nobody и быть приватным
    if uid is not None:
        try:
            os.chown(workdir, uid, gid)
            os.chmod(workdir, 0o700)
        except OSError:
            pass

    base_env = {
        'PATH': '/usr/local/bin:/usr/bin:/bin',
        'LANG': 'C.UTF-8',
        'LC_ALL': 'C.UTF-8',
        'HOME': workdir,
        'TMPDIR': workdir,
        'PYTHONDONTWRITEBYTECODE': '1',
        'PYTHONUNBUFFERED': '1',
    }
    if env:
        base_env.update(env)

    preexec = _make_preexec(mem_mb, cpu_sec, fsize_mb, nproc, uid, gid) \
        if os.name == 'posix' else None

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8',
            errors='replace',
            cwd=workdir,
            env=base_env,
            preexec_fn=preexec,
        )
    except FileNotFoundError as e:
        return SandboxResult(error=f'executable not found: {e}')
    except Exception as e:
        return SandboxResult(error=f'failed to start: {e}')

    try:
        out, err = proc.communicate(input=input_data, timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_group(proc)
        try:
            proc.communicate(timeout=1)
        except Exception:
            pass
        return SandboxResult(timed_out=True)

    return SandboxResult(
        returncode=proc.returncode,
        stdout=(out or '').strip(),
        stderr=(err or '').strip(),
    )