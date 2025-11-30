import argparse
import time
import socket
import tempfile
import threading
import logging
from core.ssrf import SSRF
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[0]

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

def run_test_port(test_port, stop_event):
    t = threading.Thread(target=start_http_echo_server, args=(test_port, stop_event))
    t.start()

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

# run on linux :)
@pytest.mark.integr
def test_injection_in_post_param_with_readfiles_module(caplog):
    caplog.set_level(logging.INFO)
    test_file = "/etc/passwd"
    req_path = Path.joinpath(REPO_ROOT, "examples", "request.txt")
    if not req_path.exists():
        pytest.skip("request file not found")

    args = get_none_args()
    args.reqfile = req_path
    args.param = "url"
    args.modules = "readfiles"
    args.targetfiles = test_file
    SSRF(args)
    output = caplog.text

    assert "Module 'readfiles' launched !" in output
    assert test_file in output
    assert "root:x:0:0::/root:/usr/bin/bash" in output

@pytest.mark.integr
def test_portscan_module_detects_open_port(caplog, capsys):
    caplog.set_level(logging.INFO)
    test_port = 6969
    stop_event = threading.Event()

    req_path = Path.joinpath(REPO_ROOT, "examples", "request.txt")
    args = get_none_args()
    args.reqfile = req_path
    args.param = "url"
    args.modules = "portscan"

    try:
        run_test_port(test_port, stop_event)
        SSRF(args)
        log_output = caplog.text
        print_output = capsys.readouterr()

        assert wait_for_port("127.0.0.1", test_port, timeout=4.0)
        assert "Module 'portscan' launched !" in log_output
        assert f"Found \033[32mopen     \033[0m port n°{test_port}" in print_output.out
    finally:
        stop_event.set()

@pytest.mark.integr
def test_injection_in_get_param_readfiles_module(caplog):
    caplog.set_level(logging.INFO)
    test_file = "/etc/passwd"
    req_path = Path.joinpath(REPO_ROOT, "examples", "request3.txt")
    if not req_path.exists():
        pytest.skip("request file not found")

    args = get_none_args()
    args.reqfile = req_path
    args.param = "url"
    args.modules = "readfiles"
    args.targetfiles = test_file
    SSRF(args)
    output = caplog.text

    assert "Module 'readfiles' launched !" in output
    assert test_file in output
    assert "root:x:0:0::/root:/usr/bin/bash" in output


@pytest.mark.integr
def test_injection_in_header_readfiles_module(caplog):
    caplog.set_level(logging.INFO)
    test_file = "/etc/passwd"
    req_path = Path.joinpath(REPO_ROOT, "examples", "request6.txt")
    if not req_path.exists():
        pytest.skip("request file not found")

    args = get_none_args()
    args.reqfile = req_path
    args.param = "X-Custom-Header"
    args.modules = "readfiles"
    args.targetfiles = test_file
    SSRF(args)
    output = caplog.text

    assert "Module 'readfiles' launched !" in output
    assert test_file in output
    assert "root:x:0:0::/root:/usr/bin/bash" in output

@pytest.mark.integr
def test_secure_endpoint(caplog):
    caplog.set_level(logging.INFO)
    test_file = "/etc/passwd"
    req_path = Path.joinpath(REPO_ROOT, "examples", "request7.txt")
    if not req_path.exists():
        pytest.skip("request file not found")

    args = get_none_args()
    args.reqfile = req_path
    args.param = "url"
    args.modules = "readfiles"
    args.targetfiles = test_file
    SSRF(args)
    output = caplog.text

    assert "Module 'readfiles' launched !" in output
    assert test_file not in output
    assert "root:x:0:0::/root:/usr/bin/bash" not in output
