"""Security boundaries and one-hour access lifecycle, using real HTTP dispatch and SQLite."""
import datetime
import sqlite3
import time
import unittest
import test_ios_server as ios_tests
s = ios_tests.s

class TunnelTests(unittest.TestCase):
    setUp = ios_tests.IOSAPITests.setUp
    tearDown = ios_tests.IOSAPITests.tearDown
    call = ios_tests.IOSAPITests.call

    def status(self, **changes):
        return dict(hostname='daughter.local', state='disabled', sshReady=True, remotePort=22001, message='', **changes)

    def control(self, enabled=True, revision=0):
        return dict(hostname='daughter.local', enabled=enabled, revision=revision)

    def test_remote_access_defaults_off_after_setup_and_restart(self):
        endpoint = '/api/device/remote-access?hostname=daughter.local'
        initial = self.call(endpoint, s.DEVICE)[1]
        self.assertFalse(initial['enabled'])
        self.assertIsNone(initial['expiresAt'])
        self.assertEqual(initial['revision'], 0)
        # Installing a ready helper must not create an enable request.
        self.assertEqual(self.call('/api/device/tunnel-status', s.DEVICE, self.status())[0], 200)
        s.init_db()  # Simulate the server restarting after initial provisioning.
        self.assertFalse(self.call(endpoint, s.DEVICE)[1]['enabled'])
        self.assertFalse(self.call('/api/admin/remote-access', s.ADMIN)[1]['devices'][0]['enabled'])
        # Even a device claiming to be connected cannot enable its own access.
        claimed = self.status(); claimed['state'] = 'connected'
        self.call('/api/device/tunnel-status', s.DEVICE, claimed)
        self.assertFalse(self.call(endpoint, s.DEVICE)[1]['enabled'])

    def test_explicit_disable_survives_restart_and_helper_reconnection(self):
        self.call('/api/device/tunnel-status', s.DEVICE, self.status())
        self.assertEqual(self.call('/api/admin/remote-access', s.ADMIN, self.control())[0], 200)
        self.assertEqual(self.call('/api/admin/remote-access', s.ADMIN, self.control(False, 1))[0], 200)
        s.init_db()
        self.call('/api/device/tunnel-status', s.DEVICE, self.status())
        control = self.call('/api/device/remote-access?hostname=daughter.local', s.DEVICE)[1]
        self.assertFalse(control['enabled'])
        self.assertIsNone(control['expiresAt'])

    def test_credentials_cannot_be_interchanged(self):
        for token in (s.DEVICE, s.BROWSER, s.ACTIVITY, s.IOS, ''):
            self.assertEqual(self.call('/api/admin/remote-access', token)[0], 401)
            self.assertEqual(self.call('/api/admin/remote-access', token, self.control())[0], 401)
        for token in (s.ADMIN, s.BROWSER, s.ACTIVITY, s.IOS, ''):
            self.assertEqual(self.call('/api/device/tunnel-status', token, self.status())[0], 401)
            self.assertEqual(self.call('/api/device/remote-access?hostname=daughter.local', token)[0], 401)
        s.ADMIN = ''
        self.assertEqual(self.call('/api/admin/remote-access', '')[0], 503)

    def test_setup_required_and_expiry_survives_restart(self):
        self.assertEqual(self.call('/api/admin/remote-access', s.ADMIN, self.control())[0], 400)
        self.call('/api/device/tunnel-status', s.DEVICE, self.status())
        before = time.time()
        code, result = self.call('/api/admin/remote-access', s.ADMIN, self.control())
        self.assertEqual(code, 200)
        initial = result['devices'][0]
        self.assertTrue(initial['enabled'])
        expiry = datetime.datetime.fromisoformat(initial['expiresAt']).timestamp()
        self.assertAlmostEqual(expiry - before, 3600, delta=2)
        self.assertEqual(self.call('/api/admin/remote-access', s.ADMIN, self.control())[0], 409)
        s.init_db()
        with sqlite3.connect(s.DB) as conn:
            self.assertTrue(s.tunnel_control(conn, 'daughter.local', before + 1800)['enabled'])
            self.assertFalse(s.tunnel_control(conn, 'daughter.local', expiry)['enabled'])
            self.assertFalse(s.tunnel_control(conn, 'daughter.local', expiry + 1)['enabled'])
        after = self.call('/api/device/remote-access?hostname=daughter.local', s.DEVICE)[1]
        self.assertEqual(after['expiresAt'], initial['expiresAt'], 'Restart and polling cannot extend the original deadline')

    def test_old_unbounded_requests_fail_closed(self):
        with sqlite3.connect(s.DB) as conn:
            conn.execute('INSERT INTO remote_access VALUES (?,?,?,?)', ('daughter.local', 1, 1, 0))
        self.assertFalse(self.call('/api/device/remote-access?hostname=daughter.local', s.DEVICE)[1]['enabled'])

    def test_status_is_reported_independently_of_requested_setting(self):
        self.call('/api/device/tunnel-status', s.DEVICE, self.status())
        requested = self.call('/api/admin/remote-access', s.ADMIN, self.control())[1]['devices'][0]
        self.assertTrue(requested['enabled'])
        self.assertEqual(requested['status']['state'], 'disabled')
        connected = self.status(); connected['state'] = 'connected'
        self.call('/api/device/tunnel-status', s.DEVICE, connected)
        reported = self.call('/api/admin/remote-access', s.ADMIN)[1]['devices'][0]
        self.assertTrue(reported['fresh'])
        self.assertIsNotNone(reported['lastSeen'])
        self.assertEqual(reported['status']['state'], 'connected')
        with sqlite3.connect(s.DB) as conn:
            conn.execute('UPDATE tunnel_status SET seen=?', (time.time() - 41,))
        stale = self.call('/api/admin/remote-access', s.ADMIN)[1]['devices'][0]
        self.assertFalse(stale['fresh'])
        # Historical connected reports remain historical; requested-off is not proof of closure.
        self.assertEqual(stale['status']['state'], 'connected')

    def test_stale_helper_cannot_enable_but_can_disable(self):
        self.call('/api/device/tunnel-status', s.DEVICE, self.status())
        self.call('/api/admin/remote-access', s.ADMIN, self.control())
        with sqlite3.connect(s.DB) as conn:
            conn.execute('UPDATE tunnel_status SET seen=?', (time.time() - 100,))
        self.assertEqual(self.call('/api/admin/remote-access', s.ADMIN, self.control(True, 1))[0], 400)
        self.assertEqual(self.call('/api/admin/remote-access', s.ADMIN, self.control(False, 1))[0], 200)

    def test_rejects_arbitrary_commands_and_malformed_hosts(self):
        self.assertFalse(self.call('/api/device/remote-access?hostname=unprovisioned', s.DEVICE)[1]['enabled'])
        for query in ('hostname=x&hostname=y', 'hostname=-bad', 'hostname=x&command=sh', 'hostname='):
            self.assertEqual(self.call('/api/device/remote-access?' + query, s.DEVICE)[0], 400)
        self.assertEqual(self.call('/api/admin/remote-access', s.ADMIN, dict(self.control(), command='sh'))[0], 400)
        for bad in (True, 22, 65536, '22001'):
            payload = self.status(); payload['remotePort'] = bad
            self.assertEqual(self.call('/api/device/tunnel-status', s.DEVICE, payload)[0], 400)

    def test_deleting_mac_cancels_lease(self):
        self.call('/api/device/tunnel-status', s.DEVICE, self.status())
        self.call('/api/admin/remote-access', s.ADMIN, self.control())
        with sqlite3.connect(s.DB) as conn: s.delete_connection(conn, 'daughter.local')
        self.assertFalse(self.call('/api/device/remote-access?hostname=daughter.local', s.DEVICE)[1]['enabled'])

if __name__ == '__main__': unittest.main()
