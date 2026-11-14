"""Bounded worker lifecycle and credential-free command output."""
import argparse
import contextlib
import io
import itertools
import json
import queue
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from xmplayer.core.legacy_cli import cmd_cloud_id_login_probe, _cloud_id_login_worker


class FakeEvents:
    def __init__(self, messages):
        self.messages = iter(messages)
        self.closed = False

    def get(self, timeout):
        try:
            return next(self.messages)
        except StopIteration:
            raise queue.Empty from None

    def close(self):
        self.closed = True


class FakeProcess:
    def __init__(self):
        self.started = False
        self.terminated = False

    def start(self):
        self.started = True

    def is_alive(self):
        return not self.terminated

    def terminate(self):
        self.terminated = True

    def join(self, timeout):
        pass


class CloudIdCliTests(unittest.TestCase):
    def run_command(self, messages, deadline=1):
        events, process = FakeEvents(messages), FakeProcess()
        context = SimpleNamespace(Queue=lambda: events, Process=lambda **kwargs: process)
        args = argparse.Namespace(device_id='PRIVATECAMERA12345678', device_user='private-user',
                                  channel=0, timeout=7, deadline=deadline, insecure=False, out=None)
        stdout, stderr = io.StringIO(), io.StringIO()
        ticks = itertools.count()
        with patch('multiprocessing.get_context', return_value=context), patch(
                'time.monotonic', side_effect=lambda: next(ticks) / 10), patch(
                'xmplayer.core.legacy_cli.getpass.getpass', return_value='private-password'), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cmd_cloud_id_login_probe(args)
        for secret in (args.device_id, args.device_user, 'private-password'):
            self.assertNotIn(secret, stdout.getvalue() + stderr.getvalue())
        return code, json.loads(stdout.getvalue()), process, events

    def test_stalled_worker_is_terminated_at_deadline(self):
        code, result, process, events = self.run_command([{'stage': 'relay_connect_request'}])
        self.assertEqual(code, 1)
        self.assertEqual(result['error'], 'deadline')
        self.assertEqual(result['last_stage'], 'relay_connect_request')
        self.assertFalse(result['authenticated'])
        self.assertTrue(process.started)
        self.assertTrue(process.terminated)
        self.assertTrue(events.closed)

    def test_completed_worker_returns_device_result(self):
        code, result, process, events = self.run_command([
            {'result': {'authenticated': True, 'login_ret': 100, 'account_login_used': False}}])
        self.assertEqual(code, 0)
        self.assertEqual(result['login_ret'], 100)
        self.assertFalse(result['account_login_used'])
        self.assertTrue(process.terminated)
        self.assertTrue(events.closed)

    def test_worker_does_not_forward_exception_text(self):
        events = queue.Queue()
        options = {'timeout': 7, 'ssl_verify': True, 'cloud_id': 'PRIVATECAMERA12345678',
                   'username': 'private-user', 'password': 'private-password', 'channel': 0}
        with patch('xmplayer.core.cloud_id.CloudIdClient.probe_login',
                   side_effect=RuntimeError('private-password PRIVATECAMERA12345678')):
            _cloud_id_login_worker(events, options)
        result = events.get_nowait()['result']
        self.assertFalse(result['authenticated'])
        self.assertEqual(result['error_type'], 'RuntimeError')
        self.assertNotIn('private-password', json.dumps(result))
        self.assertNotIn(options['cloud_id'], json.dumps(result))


if __name__ == '__main__':
    unittest.main()
