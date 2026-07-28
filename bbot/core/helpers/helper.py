import os
import asyncio
import signal
import ctypes
import ctypes.util
import logging
from contextlib import suppress
from pathlib import Path
import multiprocessing as mp
from functools import partial
from concurrent.futures import ProcessPoolExecutor

from . import misc
from .dns import DNSHelper
from .web import WebHelper
from .diff import HttpCompare
from .regex import RegexHelper
from .wordcloud import WordCloud
from .interactsh import Interactsh
from .yara_helper import YaraHelper
from .depsinstaller import DepsInstaller
from .async_helpers import get_event_loop

from bbot.scanner.target import BaseTarget

log = logging.getLogger("bbot.core.helpers")

_PR_SET_PDEATHSIG = 1


def _pool_worker_init():
    """Arrange for Linux process-pool workers to exit with their parent."""
    if not hasattr(os, "uname") or os.uname().sysname != "Linux":
        return
    try:
        libc_path = ctypes.util.find_library("c")
        if not libc_path:
            return
        libc = ctypes.CDLL(libc_path, use_errno=True)
        # SIGKILL cannot be intercepted by ProcessPoolExecutor's worker loop,
        # so workers cannot survive a suddenly-dead parent as zombies.
        libc.prctl(_PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0)
    except (AttributeError, OSError):
        # Worker startup must remain portable even on unusual libc builds.
        return


class ConfigAwareHelper:
    """
    Centralized helper class that provides unified access to various helper functions.

    This class serves as a convenient interface for accessing helper methods across different files.
    It is designed to be configuration-aware, allowing helper functions to utilize scan-specific
    configurations like rate-limits. The class leverages Python's `__getattribute__` magic method
    to provide seamless access to helper functions across various namespaces.

    Attributes:
        config (dict): Configuration settings for the BBOT scan instance.
        _scan (Scan): A BBOT scan instance.
        bbot_home (Path): Home directory for BBOT.
        cache_dir (Path): Directory for storing cache files.
        temp_dir (Path): Directory for storing temporary files.
        tools_dir (Path): Directory for storing tools, e.g. compiled binaries.
        lib_dir (Path): Directory for storing libraries.
        scans_dir (Path): Directory for storing scan results.
        wordlist_dir (Path): Directory for storing wordlists.
        current_dir (Path): The current working directory.
        keep_old_scans (int): The number of old scans to keep.

    Examples:
        >>> helper = ConfigAwareHelper(config)
        >>> ips = helper.dns.resolve("www.evilcorp.com")
    """

    from . import ntlm
    from . import regexes
    from . import validators
    from .files import tempfile, feed_pipe, _feed_pipe, tempfile_tail
    from .cache import cache_get, cache_put, cache_filename, is_cached
    from .command import run, run_live, _spawn_proc, _prepare_command_kwargs

    def __init__(self, preset):
        self.preset = preset
        self.bbot_home = self.preset.bbot_home
        self.cache_dir = self.bbot_home / "cache"
        self.temp_dir = self.bbot_home / "temp"
        self.tools_dir = self.bbot_home / "tools"
        self.lib_dir = self.bbot_home / "lib"
        self.scans_dir = self.bbot_home / "scans"
        self.wordlist_dir = Path(__file__).parent.parent.parent / "wordlists"
        self.current_dir = Path.cwd()
        self.keep_old_scans = self.config.get("keep_scans", 20)
        self.mkdir(self.cache_dir)
        self.mkdir(self.temp_dir)
        self.mkdir(self.tools_dir)
        self.mkdir(self.lib_dir)

        self._loop = None

        # multiprocessing thread pool
        start_method = mp.get_start_method()
        if start_method != "spawn":
            self.warning(f"Multiprocessing spawn method is set to {start_method}.")

        # we spawn 1 fewer processes than cores
        # this helps to avoid locking up the system or competing with the main python process for cpu time
        num_processes = max(1, mp.cpu_count() - 1)
        self._process_pool_workers = num_processes
        self.process_pool = self._create_process_pool()
        self._pool_reset_lock = asyncio.Lock()

        self._cloud = None

        self.re = RegexHelper(self)
        self.yara = YaraHelper(self)
        self._dns = None
        self._web = None
        self._cloudcheck = None
        self.config_aware_validators = self.validators.Validators(self)
        self.depsinstaller = DepsInstaller(self)
        self.word_cloud = WordCloud(self)
        self.dummy_modules = {}

    @property
    def dns(self):
        if self._dns is None:
            self._dns = DNSHelper(self)
        return self._dns

    @property
    def web(self):
        if self._web is None:
            self._web = WebHelper(self)
        return self._web

    @property
    def cloudcheck(self):
        if self._cloudcheck is None:
            from cloudcheck import CloudCheck

            self._cloudcheck = CloudCheck()
        return self._cloudcheck

    def bloom_filter(self, size):
        from .bloom import BloomFilter

        return BloomFilter(size)

    def interactsh(self, *args, **kwargs):
        return Interactsh(self, *args, **kwargs)

    def http_compare(
        self,
        url,
        allow_redirects=False,
        include_cache_buster=True,
        headers=None,
        cookies=None,
        method="GET",
        data=None,
        json=None,
        timeout=10,
    ):
        return HttpCompare(
            url,
            self,
            allow_redirects=allow_redirects,
            include_cache_buster=include_cache_buster,
            headers=headers,
            cookies=cookies,
            timeout=timeout,
            method=method,
            data=data,
            json=json,
        )

    def temp_filename(self, extension=None):
        """
        temp_filename() --> Path("/home/user/.bbot/temp/pgxml13bov87oqrvjz7a")
        """
        filename = self.rand_string(20)
        if extension is not None:
            filename = f"{filename}.{extension}"
        return self.temp_dir / filename

    def clean_old_scans(self):
        def _filter(x):
            return x.is_dir() and self.regexes.scan_name_regex.match(x.name)

        self.clean_old(self.scans_dir, keep=self.keep_old_scans, filter=_filter)

    def make_target(self, *targets, **kwargs):
        return BaseTarget(*targets, **kwargs)

    @property
    def config(self):
        return self.preset.config

    @property
    def web_config(self):
        return self.preset.web_config

    @property
    def scan(self):
        return self.preset.scan

    @property
    def loop(self):
        """
        Get the current event loop
        """
        if self._loop is None:
            self._loop = get_event_loop()
        return self._loop

    def run_in_executor(self, callback, *args, **kwargs):
        """
        Run a synchronous task in the event loop's default thread pool executor

        Examples:
            Execute callback:
            >>> result = await self.helpers.run_in_executor(callback_fn, arg1, arg2)
        """
        callback = partial(callback, **kwargs)
        return self.loop.run_in_executor(None, callback, *args)

    def _create_process_pool(self):
        return ProcessPoolExecutor(max_workers=self._process_pool_workers, initializer=_pool_worker_init)

    @staticmethod
    def _terminate_process_pool(pool):
        """Terminate process-pool workers without waiting for a stuck task."""
        workers = list((getattr(pool, "_processes", None) or {}).values())
        for process in workers:
            if process.is_alive():
                with suppress(OSError):
                    process.terminate()
        with suppress(Exception):
            pool.shutdown(wait=False, cancel_futures=True)
        for process in workers:
            if process.is_alive():
                with suppress(OSError):
                    process.kill()

    async def _reset_process_pool(self, timed_out_pool):
        """Replace a timed-out pool once, even when several tasks time out together."""
        async with self._pool_reset_lock:
            if self.process_pool is not timed_out_pool:
                return
            self.process_pool = self._create_process_pool()
            self._terminate_process_pool(timed_out_pool)

    def run_in_executor_mp(self, callback, *args, **kwargs):
        """
        Same as run_in_executor() except with a process pool executor
        Use only in cases where callback is CPU-bound.

        A timeout prevents a dead child from occupying a worker forever. If a
        task times out, the affected pool is terminated and replaced. Pass
        ``_timeout=None`` to disable the default 300-second timeout.

        Examples:
            Execute callback:
            >>> result = await self.helpers.run_in_executor_mp(callback_fn, arg1, arg2)
        """
        timeout = kwargs.pop("_timeout", 300)
        callback = partial(callback, **kwargs)
        pool = self.process_pool
        future = self.loop.run_in_executor(pool, callback, *args)
        return self.loop.create_task(self._await_process_pool_future(future, pool, timeout))

    async def _await_process_pool_future(self, future, pool, timeout):
        try:
            done, _ = await asyncio.wait((future,), timeout=timeout)
        except asyncio.CancelledError:
            future.cancel()
            raise
        if future not in done:
            future.cancel()
            log.warning(f"Process pool task timed out after {timeout}s, killing stuck workers and replacing pool")
            await self._reset_process_pool(pool)
            raise asyncio.TimeoutError(f"Process pool task timed out after {timeout}s")
        return await future

    @property
    def in_tests(self):
        return os.environ.get("BBOT_TESTING", "") == "True"

    def __getattribute__(self, attr):
        """
        Do not be afraid, the angel said.

        Overrides Python's built-in __getattribute__ to provide convenient access to helper methods.

        This method first attempts to find an attribute within this class itself. If unsuccessful,
        it then looks in the 'misc', 'dns', and 'web' helper modules, in that order. If the attribute
        is still not found, an AttributeError is raised.

        Args:
            attr (str): The attribute name to look for.

        Returns:
            Any: The attribute value, if found.

        Raises:
            AttributeError: If the attribute is not found in any of the specified places.
        """
        try:
            # first try self
            return super().__getattribute__(attr)
        except AttributeError:
            try:
                # then try misc
                return getattr(misc, attr)
            except AttributeError:
                try:
                    # then try dns
                    return getattr(self.dns, attr)
                except AttributeError:
                    try:
                        # then try web
                        return getattr(self.web, attr)
                    except AttributeError:
                        try:
                            # then try validators
                            return getattr(self.validators, attr)
                        except AttributeError:
                            # then die
                            raise AttributeError(f'Helper has no attribute "{attr}"')
