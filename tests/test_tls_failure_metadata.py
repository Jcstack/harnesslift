"""Keep native TLS bootstrap diagnostics from disclosing private stderr."""

import json
from types import SimpleNamespace
import unittest

from tests.probe_tls_initialization import tls_failure_metadata


class TLSFailureMetadataTests(unittest.TestCase):
    def test_only_fixed_classes_and_known_acl_codes_leave_private_output(self):
        secret = b"PRIVATE_SENTINEL C:/PRIVATE/user S-1-5-21-PRIVATE"
        for code in (-1, 21, 22, 23, 24, 777):
            result = SimpleNamespace(returncode=1, stdout=secret,
                stderr=f"runtime NTFS ACL verification failed (check {code}) ".encode() + secret)
            row = tls_failure_metadata(result)
            self.assertEqual(row['acl_check_code'], code if code != 777 else None)
            self.assertEqual(row['failure_classes'], ['ntfs_acl'])
            self.assertNotIn('PRIVATE', json.dumps(row))
        row = tls_failure_metadata(SimpleNamespace(returncode=1, stdout=b'', stderr=secret))
        self.assertEqual(row, {'returncode': 1, 'acl_check_code': None, 'failure_classes': []})


if __name__ == '__main__':
    unittest.main()
