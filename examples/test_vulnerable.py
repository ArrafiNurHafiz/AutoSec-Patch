import unittest
from examples.vulnerable_app import init_db, get_user_vulnerable

class TestVulnerableApp(unittest.TestCase):
    def test_legitimate_user(self):
        conn = init_db()
        user = get_user_vulnerable(conn, "alice")
        self.assertIsNotNone(user)
        self.assertEqual(user[1], "alice")
        self.assertEqual(user[2], "user")

    def test_nonexistent_user(self):
        conn = init_db()
        user = get_user_vulnerable(conn, "bob")
        self.assertIsNone(user)

    def test_sql_injection_protection(self):
        """Under secure implementation, injection returns None."""
        conn = init_db()
        sqli_payload = "' OR '1'='1"
        user = get_user_vulnerable(conn, sqli_payload)
        # If secure parameterized query is used, this user does not exist
        self.assertIsNone(user)

if __name__ == "__main__":
    unittest.main()
