import asyncio
import hashlib
import itertools
import mmap
import os
import secrets
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncGenerator, Callable, Dict, List, Optional, Set
from textual import work
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, Grid
from textual.widgets import Button, Footer, Header, Input, Label, Static, DataTable, TabbedContent, TabPane
import psutil
import pyzipper
@dataclass
class CrackResult:
    success: bool
    password: Optional[str] = None
    error: Optional[str] = None
@dataclass
class TaskInfo:
    id: str
    type: str
    target: str
    status: str
    progress: float
    speed: float
    eta: str
class ZipCracker:
    def __init__(self, zip_path: str, max_workers: int = 4):
        self.zip_path = zip_path
        self.max_workers = max_workers
        self._stop_event = threading.Event()
        self.attempts = 0
        self.start_time = 0
    def stop(self):
        self._stop_event.set()
    def _try_password(self, password: str) -> bool:
        if self._stop_event.is_set():
            return False
        try:
            with pyzipper.AESZipFile(self.zip_path) as zf:
                zf.pwd = password.encode('utf-8')
                zf.testzip()
            return True
        except RuntimeError:
            return False
        except Exception:
            return False
    def crack(self, wordlist_path: str) -> CrackResult:
        self.start_time = time.time()
        self.attempts = 0
        self._stop_event.clear()
        with open(wordlist_path, 'rb') as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                passwords = iter(mm.readline, b"")
                with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                    future_to_pass = {}
                    batch_size = self.max_workers * 2
                    batch = []
                    for pwd_line in passwords:
                        if self._stop_event.is_set():
                            return CrackResult(success=False, error="Stopped by user")
                        pwd = pwd_line.rstrip(b'\n\r').decode('utf-8', errors='ignore')
                        batch.append(pwd)
                        if len(batch) >= batch_size:
                            for p in batch:
                                future_to_pass[executor.submit(self._try_password, p)] = p
                            for future in as_completed(list(future_to_pass.keys())):
                                pwd = future_to_pass[future]
                                self.attempts += 1
                                if future.result():
                                    return CrackResult(success=True, password=pwd)
                            batch.clear()
                    for p in batch:
                        future_to_pass[executor.submit(self._try_password, p)] = p
                    for future in as_completed(list(future_to_pass.keys())):
                        pwd = future_to_pass[future]
                        self.attempts += 1
                        if future.result():
                            return CrackResult(success=True, password=pwd)
        return CrackResult(success=False, error="Password not found")
class HashCracker:
    def __init__(self, target_hash: str, algorithm: str = 'md5', max_workers: int = 4):
        self.target_hash = target_hash.lower()
        self.algorithm = algorithm
        self.max_workers = max_workers
        self._stop_event = threading.Event()
        self.attempts = 0
        self.start_time = 0
    def stop(self):
        self._stop_event.set()
    def _hash_password(self, password: str) -> str:
        if self.algorithm == 'md5':
            return hashlib.md5(password.encode()).hexdigest()
        elif self.algorithm == 'sha1':
            return hashlib.sha1(password.encode()).hexdigest()
        elif self.algorithm == 'sha256':
            return hashlib.sha256(password.encode()).hexdigest()
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")
    def _try_hash(self, password: str) -> bool:
        if self._stop_event.is_set():
            return False
        try:
            return self._hash_password(password) == self.target_hash
        except Exception:
            return False
    def crack(self, wordlist_path: str) -> CrackResult:
        self.start_time = time.time()
        self.attempts = 0
        self._stop_event.clear()
        with open(wordlist_path, 'rb') as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                passwords = iter(mm.readline, b"")
                with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                    future_to_pass = {}
                    batch_size = self.max_workers * 2
                    batch = []
                    for pwd_line in passwords:
                        if self._stop_event.is_set():
                            return CrackResult(success=False, error="Stopped by user")
                        pwd = pwd_line.rstrip(b'\n\r').decode('utf-8', errors='ignore')
                        batch.append(pwd)
                        if len(batch) >= batch_size:
                            for p in batch:
                                future_to_pass[executor.submit(self._try_hash, p)] = p
                            for future in as_completed(list(future_to_pass.keys())):
                                pwd = future_to_pass[future]
                                self.attempts += 1
                                if future.result():
                                    return CrackResult(success=True, password=pwd)
                            batch.clear()
                    for p in batch:
                        future_to_pass[executor.submit(self._try_hash, p)] = p
                    for future in as_completed(list(future_to_pass.keys())):
                        pwd = future_to_pass[future]
                        self.attempts += 1
                        if future.result():
                            return CrackResult(success=True, password=pwd)
        return CrackResult(success=False, error="Password not found")
class PwdCrackApp(App):
    TITLE = "RedTeam PwdCrack"
    SUB_TITLE = "Advanced Password & Hash Cracker"
    CSS_PATH = "style.tcss"
    def __init__(self):
        super().__init__()
        self.current_task: Optional[TaskInfo] = None
        self.cracker: Optional[ZipCracker] = None
        self.hash_cracker: Optional[HashCracker] = None
        self.executor = ThreadPoolExecutor(max_workers=8)
        self.crack_results = []
    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent():
            with TabPane("ZIP Cracker"):
                yield Vertical(
                    Label("ZIP File Cracker", classes="section-title"),
                    Horizontal(
                        Label("ZIP File:"),
                        Input(placeholder="path/to/file.zip", id="zip_target"),
                    ),
                    Horizontal(
                        Label("Wordlist:"),
                        Input(placeholder="path/to/wordlist.txt", id="zip_wordlist"),
                    ),
                    Horizontal(
                        Button("Start ZIP Cracking", id="start_zip"),
                        Button("Stop ZIP Cracking", id="stop_zip"),
                    ),
                    Static("", id="zip_status"),
                    Static("", id="zip_progress"),
                    Static("", id="zip_speed"),
                    Static("", id="zip_eta"),
                )
            with TabPane("Hash Cracker"):
                yield Vertical(
                    Label("Hash Cracker", classes="section-title"),
                    Horizontal(
                        Label("Hash:"),
                        Input(placeholder="hash value", id="hash_value"),
                    ),
                    Horizontal(
                        Label("Algorithm:"),
                        Input(placeholder="md5/sha1/sha256", id="hash_algo"),
                    ),
                    Horizontal(
                        Label("Wordlist:"),
                        Input(placeholder="path/to/wordlist.txt", id="hash_wordlist"),
                    ),
                    Horizontal(
                        Button("Start Hash Cracking", id="start_hash"),
                        Button("Stop Hash Cracking", id="stop_hash"),
                    ),
                    Static("", id="hash_status"),
                    Static("", id="hash_progress"),
                    Static("", id="hash_speed"),
                    Static("", id="hash_eta"),
                )
        with Grid(classes="stats-grid"):
            yield Static("CPU: --%", id="cpu_usage", classes="stat-box")
            yield Static("RAM: --%", id="ram_usage", classes="stat-box")
            yield Static("Attempts: 0", id="attempts", classes="stat-box")
            yield Static("Workers: 4", id="workers", classes="stat-box")
        yield DataTable(id="results_table", classes="results-table")
        yield Footer()
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "start_zip":
            self.start_zip_cracking()
        elif event.button.id == "stop_zip":
            self.stop_cracking()
        elif event.button.id == "start_hash":
            self.start_hash_cracking()
        elif event.button.id == "stop_hash":
            self.stop_cracking()
    @work(thread=True)
    def start_zip_cracking(self):
        wordlist = self.query_one("#zip_wordlist", Input).value
        target = self.query_one("#zip_target", Input).value
        if not wordlist or not target:
            self.call_from_thread(lambda: self.query_one("#zip_status").update("Error: Missing wordlist or target"))
            return
        self.cracker = ZipCracker(target)
        result = self.cracker.crack(wordlist)
        if result.success:
            self.call_from_thread(lambda: self.query_one("#zip_status").update(f"Success! Password: {result.password}"))
            self.add_result("ZIP", target, result.password)
        else:
            self.call_from_thread(lambda: self.query_one("#zip_status").update(f"Failed: {result.error}"))
    @work(thread=True)
    def start_hash_cracking(self):
        wordlist = self.query_one("#hash_wordlist", Input).value
        target_hash = self.query_one("#hash_value", Input).value
        algorithm = self.query_one("#hash_algo", Input).value or "md5"
        if not wordlist or not target_hash:
            self.call_from_thread(lambda: self.query_one("#hash_status").update("Error: Missing wordlist or hash"))
            return
        self.hash_cracker = HashCracker(target_hash, algorithm)
        result = self.hash_cracker.crack(wordlist)
        if result.success:
            self.call_from_thread(lambda: self.query_one("#hash_status").update(f"Success! Password: {result.password}"))
            self.add_result("HASH", target_hash, result.password)
        else:
            self.call_from_thread(lambda: self.query_one("#hash_status").update(f"Failed: {result.error}"))
    def stop_cracking(self):
        if self.cracker:
            self.cracker.stop()
        if self.hash_cracker:
            self.hash_cracker.stop()
        self.query_one("#zip_status").update("Stopped by user")
        self.query_one("#hash_status").update("Stopped by user")
    def call_from_thread(self, func: Callable[[], Any]) -> None:
        self.call_later(func)
    def on_mount(self) -> None:
        self.set_interval(0.5, self.update_stats)
        table = self.query_one("#results_table", DataTable)
        table.add_columns("Type", "Target", "Password")
    def update_stats(self) -> None:
        cpu_percent = psutil.cpu_percent()
        ram_percent = psutil.virtual_memory().percent
        self.query_one("#cpu_usage").update(f"CPU: {cpu_percent}%")
        self.query_one("#ram_usage").update(f"RAM: {ram_percent}%")
        if self.cracker and self.cracker.start_time:
            elapsed = time.time() - self.cracker.start_time
            speed = self.cracker.attempts / elapsed if elapsed > 0 else 0
            self.query_one("#attempts").update(f"Attempts: {self.cracker.attempts}")
            self.query_one("#zip_speed").update(f"Speed: {speed:.0f}/s")
        elif self.hash_cracker and self.hash_cracker.start_time:
            elapsed = time.time() - self.hash_cracker.start_time
            speed = self.hash_cracker.attempts / elapsed if elapsed > 0 else 0
            self.query_one("#attempts").update(f"Attempts: {self.hash_cracker.attempts}")
            self.query_one("#hash_speed").update(f"Speed: {speed:.0f}/s")
    def add_result(self, type_: str, target: str, password: str):
        table = self.query_one("#results_table", DataTable)
        table.add_row(type_, target, password)
if __name__ == "__main__":
    app = PwdCrackApp()
    app.run()
