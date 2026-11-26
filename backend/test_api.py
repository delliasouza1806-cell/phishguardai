import unittest
from fastapi.testclient import TestClient

import main


class PhishGuardAPITest(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(main.app)
        self.client.delete("/reports")

    def test_web_console_and_demo_routes(self) -> None:
        home = self.client.get("/")
        self.assertEqual(home.status_code, 200)
        self.assertIn("PhishGuard AI", home.text)

        demo = self.client.get("/demo")
        self.assertEqual(demo.status_code, 200)
        self.assertIn("Workspace Inbox Demo", demo.text)

    def test_cors_preflight_allows_chrome_extension(self) -> None:
        resp = self.client.options(
            "/scan",
            headers={
                "Origin": "chrome-extension://abcdefghijklmnop",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            },
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get("access-control-allow-origin"), "*")

    def test_detects_genai_bec_phish_and_redacts_pii(self) -> None:
        phish = (
            "I hope this message finds you well. Kindly note that I am in back-to-back board meetings "
            "and need your urgent assistance with an immediate vendor settlement before 4:00 PM today. "
            "Keep this confidential and confirm the wire transfer at http://198.51.100.42/auth/sso-verify?tok=secret123 "
            "with your OTP verification code. Reply to ceo@spoofed.example.com and account 1234567890."
        )
        resp = self.client.post(
            "/scan",
            json={"text": phish, "source_url": "https://mail.google.com/mail/u/0/#inbox"},
            headers={"Origin": "chrome-extension://abcdefghijklmnop"},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["verdict"], "high_risk")
        self.assertGreaterEqual(data["risk_score"], 65)
        self.assertGreater(data["breakdown"]["heuristics"], 0)
        self.assertGreater(data["breakdown"]["regex"], 0)
        self.assertGreater(data["breakdown"]["ai_semantic"], 0)
        self.assertTrue(len(data["matched_phrases"]) >= 2)
        self.assertEqual(data["inspected_links"][0]["status"], "malicious")

        reports_resp = self.client.get("/reports").json()
        self.assertEqual(reports_resp["stats"]["high_risk"], 1)
        preview = reports_resp["reports"][0]["preview"]
        self.assertNotIn("ceo@spoofed.example.com", preview)
        self.assertNotIn("1234567890", preview)
        self.assertNotIn("secret123", preview)

    def test_detects_brand_domain_mismatch(self) -> None:
        msg = "Action required: Your Microsoft SSO session will be suspended today. Sign in at https://login-check.xyz/auth"
        resp = self.client.post("/scan", json={"text": msg})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        codes = {s["code"] for s in data["signals"]}
        self.assertIn("brand_domain_mismatch", codes)
        self.assertIn("risky_tld", codes)
        self.assertEqual(data["attack_vector"], "Credential & MFA Harvesting")
        self.assertGreaterEqual(data["risk_score"], 65)

    def test_detects_crypto_and_zero_width_evasion(self) -> None:
        msg = "Urgent\u200b: Claim your reward before it expires today — connect your wallet at https://claim-airdrop.top/wallet and verify your seed phrase."
        resp = self.client.post("/scan", json={"text": msg})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        codes = {s["code"] for s in data["signals"]}
        self.assertIn("zero_width_obfuscation", codes)
        self.assertIn("crypto_wallet_lure", codes)
        self.assertEqual(data["attack_vector"], "Web3 / Wallet Drain Lure")
        self.assertEqual(data["verdict"], "high_risk")

    def test_safe_message_scores_low(self) -> None:
        safe = "Hey team, moving our sprint demo to Thursday at 2 PM in Room B. No action needed before then."
        resp = self.client.post("/scan", json={"text": safe})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["verdict"], "safe")
        self.assertEqual(data["attack_vector"], "Benign Workspace Communication")
        self.assertLess(data["risk_score"], 30)

    def test_batch_scan_endpoint(self) -> None:
        resp = self.client.post(
            "/scan/batch",
            json={
                "source_url": "https://www.linkedin.com/messaging/",
                "items": [
                    {"id": "m1", "text": "Hi! Looking forward to catching up next Tuesday at coffee."},
                    {
                        "id": "m2",
                        "text": "Impressed by your background! Exclusive role—please verify your portfolio and OTP via https://bit.ly/verify-nda immediately.",
                    },
                ],
            },
        )
        self.assertEqual(resp.status_code, 200)
        results = resp.json()
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["verdict"], "safe")
        self.assertIn(results[1]["verdict"], ("caution", "high_risk"))


if __name__ == "__main__":
    unittest.main()
