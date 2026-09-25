#!/usr/bin/env python3
"""Exercise the real native executable without a JVM or production services."""
import base64
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request


def health_requests(metrics):
    total = 0.0
    for line in metrics.splitlines():
        match = re.match(r'^http_server_requests_seconds_count\{([^}]*)\}\s+([\d.eE+-]+)', line)
        if match and re.search(r'uri="/actuator/health[^"]*"', match[1]):
            total += float(match[2])
    return total


def main():
    binary = Path(sys.argv[1] if len(sys.argv) > 1 else 'build/native/nativeCompile/iam-login').resolve()
    with binary.open('rb') as source:
        if source.read(4) != b'\x7fELF':
            raise RuntimeError('Expected a Linux native ELF executable')
    report_dir = Path('build/reports/native-smoke')
    report_dir.mkdir(parents=True, exist_ok=True)
    log_path = report_dir / 'application.log'
    result_path = report_dir / 'result.json'
    result_path.unlink(missing_ok=True)
    password = secrets.token_urlsafe(32)
    env = os.environ.copy()
    env.update(SPRING_SECURITY_USER_NAME='native-smoke', SPRING_SECURITY_USER_PASSWORD=password)
    started = time.monotonic()
    process = None
    try:
        with log_path.open('w') as log:
            process = subprocess.Popen([
                str(binary), '--server.address=127.0.0.1', '--server.port=0',
            ], env=env, stdout=log, stderr=subprocess.STDOUT)
            deadline = started + 60
            while True:
                if process.poll() is not None:
                    raise RuntimeError(f'Native process exited before startup; see {log_path}')
                match = re.search(r'Tomcat started on port (\d+)', log_path.read_text(errors='replace'))
                if match:
                    break
                if time.monotonic() > deadline:
                    raise RuntimeError(f'Native startup timed out; see {log_path}')
                time.sleep(0.1)
            base_url = f'http://127.0.0.1:{match[1]}'
            basic = base64.b64encode(f'native-smoke:{password}'.encode()).decode()
            # Keep loopback traffic independent of developer proxy settings.
            client = urllib.request.build_opener(urllib.request.ProxyHandler({}))

            def request(path, authenticated=False):
                headers = {'Accept': 'text/plain' if authenticated and path == '/actuator/prometheus' else 'application/json'}
                if authenticated:
                    headers['Authorization'] = f'Basic {basic}'
                req = urllib.request.Request(base_url + path, headers=headers)
                try:
                    with client.open(req, timeout=10) as response:
                        return response.status, response.read().decode()
                except urllib.error.HTTPError as error:
                    return error.code, error.read().decode()

            while True:
                status, body = request('/actuator/health/liveness')
                if status == 200 and json.loads(body)['status'] == 'UP':
                    break
                if time.monotonic() > deadline:
                    raise RuntimeError('Liveness endpoint did not become UP')
                time.sleep(0.1)
            ready_seconds = time.monotonic() - started
            assert request('/actuator/prometheus')[0] == 401, 'Anonymous metrics must be rejected'
            assert request('/')[0] == 401, 'Anonymous application access must be rejected'
            assert request('/preview')[0] == 404, 'UI preview must be disabled by default'
            status, before = request('/actuator/prometheus', authenticated=True)
            assert status == 200, 'Authenticated Prometheus scrape failed'
            for _ in range(3):
                assert request('/actuator/health/liveness')[0] == 200
            metric_deadline = time.monotonic() + 5
            while True:
                status, after = request('/actuator/prometheus', authenticated=True)
                assert status == 200
                delta = health_requests(after) - health_requests(before)
                if delta >= 3:
                    break
                if time.monotonic() > metric_deadline:
                    raise RuntimeError(f'HTTP metric did not count health requests: {delta}')
                time.sleep(0.1)
            memory = Path(f'/proc/{process.pid}/status').read_text()
            rss = re.search(r'^VmRSS:\s+(\d+) kB', memory, re.MULTILINE)
            report = {
                'binary_bytes': binary.stat().st_size,
                'ready_seconds': round(ready_seconds, 3),
                'rss_after_requests_kib': int(rss[1]) if rss else None,
                'health_request_count_delta': delta,
                'liveness': 'UP',
                'anonymous_application_and_metrics': 401,
                'authenticated_metrics': 200,
                'scope': 'native bootstrap only; no directory readiness, AD/MFA/Hydra or trace-export validation',
            }
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    runtime_log = log_path.read_text(errors='replace')
    if re.search(r'MissingReflectionRegistrationError|MissingResourceRegistrationError|UnsupportedFeatureError', runtime_log):
        raise RuntimeError(f'Native runtime registration error, including during shutdown; see {log_path}')
    result_path.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
