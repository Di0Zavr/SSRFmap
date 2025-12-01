import argparse
import time
import threading
import logging
import socket
import subprocess
from core.ssrf import SSRF
from pathlib import Path

import pytest

# NOTE: before running tests run examples/example.py flask server
# python3 examples/example.py

REPO_ROOT = Path(__file__).resolve().parents[0]
SSRF_PATH = Path.joinpath(REPO_ROOT, "ssrfmap.py")

def get_none_args():
    args = argparse.Namespace(
        reqfile=None,
        param=None,
        modules=None,
        handler=None,
        verbose=False,
        lhost=None,
        lport=None,
        ldomain=None,
        targetfiles=None,
        useragent=None,
        ssl=None,
        proxy=None,
        level=1,
        logfile=None
    )
    return args

def wait_for_port(host, port, timeout=5.0):
    start_time = time.time()
    while time.time() - start_time < timeout:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            try:
                s.connect((host, port))
                return True
            except Exception:
                time.sleep(0.1)
    return False


def run_ssrfmap(args, timeout=60.0):
    ssrfmap = subprocess.Popen(
        args = ["python3", SSRF_PATH] + args,
        cwd = REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        out, err = ssrfmap.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        ssrfmap.kill()
        out, err = ssrfmap.communicate()
    
    return ssrfmap.returncode, out.decode(errors="ignore"), err.decode(errors="ignore")

def start_http_echo_server(port, stop_event):
    from http.server import HTTPServer, BaseHTTPRequestHandler

    class EchoHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")

        def log_message(self, format, *args):
            return

    httpd = HTTPServer(("127.0.0.1", port), EchoHandler)
    while not stop_event.is_set():
        httpd.handle_request()
    httpd.server_close()

def run_test_port(test_port, stop_event):
    t = threading.Thread(target=start_http_echo_server, args=(test_port, stop_event))
    t.start()

@pytest.mark.endtoend
def test_using_readfiles_and_portscan_modules_successfully():
    test_port = 6969
    stop_event = threading.Event()
    run_test_port(test_port, stop_event)

    test_file = "/etc/passwd"
    args = [
        "-r",
        Path.joinpath(REPO_ROOT, "examples", "request.txt"),
        "-p",
        "url",
        "-m",
        "readfiles,portscan",
        "--rfiles",
        "/etc/passwd"
    ]
    try:
        returncode, out, err = run_ssrfmap(args)
        output = out + "\n" + err
        
        assert returncode == 0
        # readfiles checks
        assert "Module 'readfiles' launched !" in output
        assert test_file in output
        assert "root:x:0:0::/root:/usr/bin/bash" in output
        # portscan checks
        assert wait_for_port("127.0.0.1", test_port, timeout=4.0)
        assert "Module 'portscan' launched !" in output
        assert f"Found \033[32mopen     \033[0m port n°{test_port}" in output
    finally:
        stop_event.set()

@pytest.mark.endtoend
def test_using_readfiles_and_portscan_modules_on_secure_endpoint():
    test_port = 6969
    stop_event = threading.Event()
    run_test_port(test_port, stop_event)

    test_file = "/etc/passwd"
    args = [
        "-r",
        Path.joinpath(REPO_ROOT, "examples", "request7.txt"),
        "-p",
        "url",
        "-m",
        "readfiles,portscan",
        "--rfiles",
        "/etc/passwd"
    ]
    try:
        returncode, out, err = run_ssrfmap(args)
        output = out + "\n" + err
        print(output.encode())
        
        assert returncode == 0
        # readfiles checks
        assert "Module 'readfiles' launched !" in output
        assert test_file not in output
        assert "root:x:0:0::/root:/usr/bin/bash" not in output
        # portscan checks
        assert wait_for_port("127.0.0.1", test_port, timeout=4.0)
        assert "Module 'portscan' launched !" in output
        assert f"Found \033[31mfiltered\033[0m  port n°{test_port}" in output
    finally:
        stop_event.set()