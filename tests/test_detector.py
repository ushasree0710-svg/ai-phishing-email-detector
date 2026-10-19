import unittest
from pathlib import Path

from phishing_detector import analyze_email
from phishing_detector.brands import brand_abuse, levenshtein
from phishing_detector.cli import parse_email_text
from phishing_detector.links import extract_links, registered_domain

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def score_file(name):
    s, b, f = parse_email_text((SAMPLES / name).read_text(encoding="utf-8"))
    return analyze_email(s, b, f)


class TestSamples(unittest.TestCase):
    def test_phishing_samples_score_high(self):
        for name in (
            "phishing_paypal.txt",
            "phishing_html_mismatch.txt",
            "phishing_prize.txt",
        ):
            with self.subTest(name=name):
                self.assertGreaterEqual(score_file(name).score, 50, name)

    def test_legit_samples_score_low(self):
        for name in ("legit_newsletter.txt", "legit_meeting.txt"):
            with self.subTest(name=name):
                self.assertLess(score_file(name).score, 25, name)


class TestIndicators(unittest.TestCase):
    def cats(self, subject, body, sender=""):
        return {
            f.category
            for f in analyze_email(subject, body, sender).findings
        }

    def test_urgency(self):
        self.assertIn(
            "urgency",
            self.cats(
                "Urgent action required",
                "Your account will be suspended within 24 hours",
            ),
        )

    def test_credentials(self):
        self.assertIn(
            "credentials",
            self.cats("Hi", "Please verify your password and enter your PIN"),
        )

    def test_ip_link(self):
        self.assertIn(
            "links",
            self.cats("Hi", "Open http://192.168.4.5/login now"),
        )

    def test_link_text_mismatch(self):
        body = '<a href="http://evil.example.xyz/x">https://www.paypal.com</a>'
        titles = [
            f.title for f in analyze_email("Hi", body).findings
        ]
        self.assertTrue(any("does not match" in t for t in titles))

    def test_lookalike_domain(self):
        self.assertIsNotNone(brand_abuse("paypa1-login.com"))
        self.assertIsNotNone(brand_abuse("microsooft.com"))
        self.assertIsNone(brand_abuse("paypal.com"))
        self.assertIsNone(brand_abuse("mail.google.com"))
        self.assertIsNone(brand_abuse("apply.example.com"))

    def test_sender_impersonation(self):
        cats = self.cats(
            "Your Amazon order",
            "Thanks for shopping",
            "Amazon Support <help@randomshop.biz>",
        )
        self.assertIn("impersonation", cats)

    def test_clean_email_zero(self):
        r = analyze_email("Lunch?", "Want to grab lunch at 1 PM tomorrow?")
        self.assertEqual(r.score, 0)
        self.assertEqual(r.level, "LOW")

    def test_empty_input_does_not_crash(self):
        self.assertEqual(analyze_email("", "").score, 0)

    def test_score_bounded(self):
        body = (
            SAMPLES / "phishing_html_mismatch.txt"
        ).read_text(encoding="utf-8")
        r = analyze_email("URGENT!!! FINAL NOTICE", body)
        self.assertTrue(0 <= r.score <= 100)


class TestHelpers(unittest.TestCase):
    def test_levenshtein(self):
        self.assertEqual(levenshtein("kitten", "sitting"), 3)

    def test_registered_domain(self):
        self.assertEqual(
            registered_domain("a.b.example.co.uk"), "example.co.uk"
        )
        self.assertEqual(registered_domain("login.paypal.com"), "paypal.com")

    def test_extract_links(self):
        links = extract_links(
            '<a href="http://a.com">x</a> and visit www.b.org/page.'
        )
        self.assertEqual(
            [l.url for l in links],
            ["http://a.com", "www.b.org/page"],
        )


if __name__ == "__main__":
    unittest.main()
