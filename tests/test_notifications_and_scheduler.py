"""
Unit and integration tests for ServerMon notification handling,
SMTP email dispatch, and scheduler insurance checks state machine.
"""

import os
import smtplib
import ssl
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from PySide6.QtCore import QCoreApplication

# Ensure project root is on sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import notifier
from notifier import (
    parse_recipients,
    format_down_alert,
    format_recovery_alert,
    format_test_email,
    send_smtp_email,
    EmailWorker,
    AlertNotifier
)
from scheduler import ServerScheduler
from settings_manager import SettingsManager, DEFAULT_SETTINGS


from PySide6.QtWidgets import QApplication

# Create a single QApplication offscreen instance for Qt tests
app = QApplication.instance() or QApplication(["--platform", "offscreen"])


class TestRecipientsParser(unittest.TestCase):
    """Tests email recipient address parsing and sanitation."""

    def test_single_recipient(self):
        result = parse_recipients("admin@example.com")
        self.assertEqual(result, ["admin@example.com"])

    def test_comma_delimited(self):
        result = parse_recipients("admin@example.com, oncall@domain.org, ops@infra.net")
        self.assertEqual(result, ["admin@example.com", "oncall@domain.org", "ops@infra.net"])

    def test_semicolon_and_newline_delimited(self):
        raw = "alice@corp.com; bob@corp.com\ncharlie@corp.com\r\ndavid@corp.com"
        result = parse_recipients(raw)
        self.assertEqual(result, ["alice@corp.com", "bob@corp.com", "charlie@corp.com", "david@corp.com"])

    def test_deduplication(self):
        raw = "alert@test.com, ALERT@test.com, other@test.com, alert@test.com"
        result = parse_recipients(raw)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0].lower(), "alert@test.com")
        self.assertEqual(result[1].lower(), "other@test.com")

    def test_invalid_emails_filtered(self):
        raw = "valid@test.com, not-an-email, @missing-user.com, missing-domain@, good@domain.co.uk"
        result = parse_recipients(raw)
        self.assertEqual(result, ["valid@test.com", "good@domain.co.uk"])

    def test_empty_and_none_input(self):
        self.assertEqual(parse_recipients(""), [])
        self.assertEqual(parse_recipients(None), [])
        self.assertEqual(parse_recipients("   ; , \n  "), [])

    def test_list_input(self):
        raw = ["admin@a.com, ops@a.com", "lead@b.com; dev@b.com"]
        result = parse_recipients(raw)
        self.assertEqual(result, ["admin@a.com", "ops@a.com", "lead@b.com", "dev@b.com"])

    def test_recipient_display_name_format(self):
        raw = "Admin User <admin@corp.com>, DevOps Team <ops@infra.org>, <plain@test.net>"
        result = parse_recipients(raw)
        self.assertEqual(result, ["admin@corp.com", "ops@infra.org", "plain@test.net"])


class TestAlertFormatting(unittest.TestCase):
    """Tests message formatting for down alerts, recovery, and test emails."""

    def setUp(self):
        self.sample_target = {
            "id": "target-1234",
            "name": "Production Database",
            "host": "db.internal.lan",
            "port": 5432,
            "check_type": "TCP",
            "error": "Connection refused (port closed)",
            "response_time_ms": 12.5
        }

    def test_down_alert_format(self):
        subject, text_body, html_body = format_down_alert(self.sample_target, failure_count=3)
        self.assertIn("Production Database", subject)
        self.assertIn("db.internal.lan", subject)
        self.assertIn("[ALERT]", subject)
        self.assertIn("5432", text_body)
        self.assertIn("3 consecutive failed attempts", text_body)
        self.assertIn("Connection refused", text_body)
        self.assertIn("<html>", html_body)
        self.assertIn("Production Database", html_body)

    def test_recovery_alert_format(self):
        subject, text_body, html_body = format_recovery_alert(self.sample_target)
        self.assertIn("Production Database", subject)
        self.assertIn("[RESOLVED]", subject)
        self.assertIn("ONLINE", text_body)
        self.assertIn("12.5 ms", text_body)
        self.assertIn("<html>", html_body)

    def test_test_email_format(self):
        subject, text_body, html_body = format_test_email(recipient_count=2)
        self.assertIn("Test Alert", subject)
        self.assertIn("2 configured address(es)", text_body)
        self.assertIn("<html>", html_body)


class TestSmtpDispatch(unittest.TestCase):
    """Tests synchronous and mock-based SMTP email dispatching."""

    def test_missing_host_validation(self):
        config = {"smtp_host": "", "smtp_port": 587}
        success, msg = send_smtp_email(config, ["test@example.com"], "Subject", "Body")
        self.assertFalse(success)
        self.assertIn("Host", msg)

    def test_missing_recipients_validation(self):
        config = {"smtp_host": "smtp.example.com", "smtp_port": 587}
        success, msg = send_smtp_email(config, [], "Subject", "Body")
        self.assertFalse(success)
        self.assertIn("recipient", msg.lower())

    @patch("smtplib.SMTP")
    def test_starttls_successful_send(self, mock_smtp_cls):
        mock_server = MagicMock()
        mock_smtp_cls.return_value = mock_server

        config = {
            "smtp_host": "smtp.testmail.com",
            "smtp_port": 587,
            "smtp_security": "STARTTLS",
            "smtp_user": "bot@testmail.com",
            "smtp_password": "secret_password",
            "smtp_sender": "Alerts <bot@testmail.com>"
        }
        recipients = ["admin@company.com", "ops@company.com"]

        success, msg = send_smtp_email(config, recipients, "Test Subject", "Test Body")

        self.assertTrue(success)
        mock_smtp_cls.assert_called_once_with("smtp.testmail.com", 587, timeout=12.0)
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once_with("bot@testmail.com", "secret_password")
        mock_server.send_message.assert_called_once()
        mock_server.quit.assert_called_once()

    @patch("smtplib.SMTP_SSL")
    def test_ssl_successful_send(self, mock_smtp_ssl_cls):
        mock_server = MagicMock()
        mock_smtp_ssl_cls.return_value = mock_server

        config = {
            "smtp_host": "smtp.testmail.com",
            "smtp_port": 465,
            "smtp_security": "SSL/TLS",
            "smtp_user": "bot@testmail.com",
            "smtp_password": "secret_password"
        }
        recipients = ["admin@company.com"]

        success, msg = send_smtp_email(config, recipients, "SSL Test", "SSL Body")

        self.assertTrue(success)
        mock_smtp_ssl_cls.assert_called_once()
        mock_server.login.assert_called_once_with("bot@testmail.com", "secret_password")
        mock_server.send_message.assert_called_once()

    @patch("smtplib.SMTP")
    def test_auth_failure_handling(self, mock_smtp_cls):
        mock_server = MagicMock()
        mock_server.login.side_effect = smtplib.SMTPAuthenticationError(535, b"Authentication failed")
        mock_smtp_cls.return_value = mock_server

        config = {
            "smtp_host": "smtp.testmail.com",
            "smtp_port": 587,
            "smtp_security": "STARTTLS",
            "smtp_user": "wrong@user.com",
            "smtp_password": "bad_password"
        }

        success, msg = send_smtp_email(config, ["admin@co.com"], "Subject", "Body")
        self.assertFalse(success)
        self.assertIn("Authentication failed", msg)

    @patch("smtplib.SMTP")
    def test_timeout_handling(self, mock_smtp_cls):
        mock_smtp_cls.side_effect = TimeoutError("Connection timed out")

        config = {
            "smtp_host": "10.255.255.1",
            "smtp_port": 587,
            "smtp_security": "STARTTLS",
        }

        success, msg = send_smtp_email(config, ["admin@co.com"], "Subject", "Body")
        self.assertFalse(success)
        self.assertIn("timed out", msg)


class TestServerSchedulerInsuranceFlow(unittest.TestCase):
    """
    Tests the insurance checks state machine in ServerScheduler:
    check -> fail -> subsequent insurance checks -> only then message.
    """

    def setUp(self):
        self.scheduler = ServerScheduler(
            normal_interval_ms=60000,
            offline_interval_ms=30000,
            insurance_retries=2,
            insurance_delay_ms=200
        )
        self.target = {
            "id": "srv-prod-1",
            "name": "Web Front End",
            "host": "web.example.com",
            "check_type": "TCP",
            "port": 443,
            "status": "ONLINE"
        }

    def tearDown(self):
        self.scheduler.stop_all()

    def test_initial_success_remains_online(self):
        """A successful check on an online server returns ONLINE and emits no down signal."""
        down_emitted = []
        self.scheduler.server_down.connect(lambda t, r: down_emitted.append((t, r)))

        result = {"status": "ONLINE", "response_time_ms": 25.0, "error": None}
        outcome = self.scheduler.handle_check_result(self.target, result)

        self.assertEqual(outcome, "ONLINE")
        self.assertEqual(len(down_emitted), 0)
        self.assertEqual(self.scheduler.failure_counts.get("srv-prod-1", 0), 0)

    def test_first_failure_enters_insurance_checking(self):
        """When an online server fails once, it enters INSURANCE_CHECKING without firing an alert."""
        down_emitted = []
        attempts_emitted = []
        self.scheduler.server_down.connect(lambda t, r: down_emitted.append(t))
        self.scheduler.insurance_attempt.connect(lambda t, cur, tot: attempts_emitted.append((cur, tot)))

        result = {"status": "OFFLINE", "response_time_ms": None, "error": "Timed out"}
        outcome = self.scheduler.handle_check_result(self.target, result)

        self.assertEqual(outcome, "INSURANCE_CHECKING")
        self.assertEqual(len(down_emitted), 0, "Must not fire down alert on first failure!")
        self.assertEqual(self.scheduler.failure_counts["srv-prod-1"], 1)
        self.assertIn("srv-prod-1", self.scheduler.in_insurance)

    def test_insurance_retry_success_recovers_to_online(self):
        """If an insurance check succeeds after an initial failure, false alarm is prevented."""
        down_emitted = []
        self.scheduler.server_down.connect(lambda t, r: down_emitted.append(t))

        # Check 1: Fails
        res_fail = {"status": "OFFLINE", "error": "Timed out"}
        outcome1 = self.scheduler.handle_check_result(self.target, res_fail)
        self.assertEqual(outcome1, "INSURANCE_CHECKING")

        # Insurance Check 1: Succeeds!
        res_ok = {"status": "ONLINE", "response_time_ms": 30.0, "error": None}
        outcome2 = self.scheduler.handle_check_result(self.target, res_ok)

        self.assertEqual(outcome2, "ONLINE")
        self.assertEqual(len(down_emitted), 0, "No down alert should ever be emitted!")
        self.assertEqual(self.scheduler.failure_counts["srv-prod-1"], 0)
        self.assertNotIn("srv-prod-1", self.scheduler.in_insurance)

    def test_all_insurance_checks_fail_declares_confirmed_down(self):
        """
        With insurance_retries=2:
        Fail 1 -> INSURANCE_CHECKING (attempt 1/2 queued)
        Fail 2 -> INSURANCE_CHECKING (attempt 2/2 queued)
        Fail 3 -> CONFIRMED_DOWN and server_down emitted!
        """
        down_emitted = []
        self.scheduler.server_down.connect(lambda t, r: down_emitted.append((t, r)))

        res_fail = {"status": "OFFLINE", "error": "Connection refused"}

        # Attempt 1: Initial failure
        out1 = self.scheduler.handle_check_result(self.target, res_fail)
        self.assertEqual(out1, "INSURANCE_CHECKING")
        self.assertEqual(len(down_emitted), 0)

        # Attempt 2: Insurance retry 1 fails
        out2 = self.scheduler.handle_check_result(self.target, res_fail)
        self.assertEqual(out2, "INSURANCE_CHECKING")
        self.assertEqual(len(down_emitted), 0)

        # Attempt 3: Insurance retry 2 fails -> CONFIRMED DOWN!
        out3 = self.scheduler.handle_check_result(self.target, res_fail)
        self.assertEqual(out3, "CONFIRMED_DOWN")
        self.assertEqual(len(down_emitted), 1, "Must emit server_down once all insurance checks fail!")
        self.assertEqual(down_emitted[0][0]["id"], "srv-prod-1")
        self.assertEqual(self.scheduler.server_states["srv-prod-1"], "OFFLINE")

    def test_already_offline_server_does_not_spam_alerts(self):
        """When a server is already OFFLINE, subsequent periodic checks do not re-emit down alerts."""
        down_emitted = []
        self.scheduler.server_down.connect(lambda t, r: down_emitted.append((t, r)))

        res_fail = {"status": "OFFLINE", "error": "Host down"}

        # Bring server to confirmed OFFLINE
        self.scheduler.handle_check_result(self.target, res_fail)  # 1
        self.scheduler.handle_check_result(self.target, res_fail)  # 2
        self.scheduler.handle_check_result(self.target, res_fail)  # 3: Confirmed DOWN
        self.assertEqual(len(down_emitted), 1)

        # Next periodic 30-sec check fires while still offline:
        out_subsequent = self.scheduler.handle_check_result(self.target, res_fail)
        self.assertEqual(out_subsequent, "STILL_OFFLINE")
        self.assertEqual(len(down_emitted), 1, "Must not emit another down alert!")

    def test_recovery_from_offline_emits_server_recovered(self):
        """When a confirmed OFFLINE server responds ONLINE, server_recovered signal is emitted."""
        recovered_emitted = []
        self.scheduler.server_recovered.connect(lambda t, r: recovered_emitted.append((t, r)))

        # Mark server confirmed OFFLINE
        self.scheduler.server_states["srv-prod-1"] = "OFFLINE"

        res_ok = {"status": "ONLINE", "response_time_ms": 15.0}
        outcome = self.scheduler.handle_check_result(self.target, res_ok)

        self.assertEqual(outcome, "RECOVERED")
        self.assertEqual(len(recovered_emitted), 1)
        self.assertEqual(self.scheduler.server_states["srv-prod-1"], "ONLINE")

    def test_zero_retries_declares_down_immediately(self):
        """If user sets insurance_retries=0, first failure immediately declares DOWN."""
        self.scheduler.set_insurance_config(retries=0)
        down_emitted = []
        self.scheduler.server_down.connect(lambda t, r: down_emitted.append((t, r)))

        res_fail = {"status": "OFFLINE", "error": "Immediate fail"}
        outcome = self.scheduler.handle_check_result(self.target, res_fail)

        self.assertEqual(outcome, "CONFIRMED_DOWN")
        self.assertEqual(len(down_emitted), 1)

    def test_update_status_does_not_corrupt_server_state(self):
        """
        Verify that calling update_status does NOT corrupt self.server_states.
        An external status update to OFFLINE must not make the scheduler treat the next failure as STILL_OFFLINE.
        """
        self.scheduler.start_server_scheduler(self.target)
        self.assertEqual(self.scheduler.get_server_state("srv-prod-1"), "ONLINE")

        # Simulate interval update
        self.scheduler.update_status("srv-prod-1", "OFFLINE")

        # Scheduled check fails -> must enter INSURANCE_CHECKING, NOT STILL_OFFLINE!
        outcome = self.scheduler.handle_check_result(self.target, {"status": "OFFLINE"})
        self.assertEqual(outcome, "INSURANCE_CHECKING")
        self.assertEqual(self.scheduler.get_server_state("srv-prod-1"), "VERIFYING")

    def test_update_status_does_not_reactivate_timer_during_insurance(self):
        """Calling update_status while a server is undergoing insurance must not restart recurring timer."""
        self.scheduler.start_server_scheduler(self.target)
        # First failure enters insurance
        self.scheduler.handle_check_result(self.target, {"status": "OFFLINE"})
        self.assertFalse(self.scheduler.timers["srv-prod-1"].isActive())

        # Attempting to update interval must not prematurely reactivate recurring timer
        self.scheduler.update_status("srv-prod-1", "ONLINE")
        self.assertFalse(self.scheduler.timers["srv-prod-1"].isActive())

    def test_get_server_state_method(self):
        """Verifies get_server_state returns ONLINE, OFFLINE, VERIFYING, and UNKNOWN."""
        self.assertEqual(self.scheduler.get_server_state("non-existent"), "UNKNOWN")
        self.scheduler.start_server_scheduler(self.target)
        self.assertEqual(self.scheduler.get_server_state("srv-prod-1"), "ONLINE")

        self.scheduler.handle_check_result(self.target, {"status": "OFFLINE"})
        self.assertEqual(self.scheduler.get_server_state("srv-prod-1"), "VERIFYING")


class TestEdgeCasesAndRobustness(unittest.TestCase):
    """Deep edge-case and boundary value verification."""

    def test_recipient_subtle_edge_cases(self):
        raw = "<tag.user+alert@sub.example.co.uk>, , ; \n <normal@test.org> "
        recipients = parse_recipients(raw)
        self.assertEqual(len(recipients), 2)
        self.assertIn("tag.user+alert@sub.example.co.uk", recipients)
        self.assertIn("normal@test.org", recipients)

    def test_plain_smtp_mode(self):
        with patch("smtplib.SMTP") as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value = mock_server

            config = {
                "smtp_host": "localhost",
                "smtp_port": 25,
                "smtp_security": "None",
                "smtp_user": "",
                "smtp_password": ""
            }
            success, msg = send_smtp_email(config, ["local@test.com"], "Subject", "Body")
            self.assertTrue(success)
            mock_server.starttls.assert_not_called()
            mock_server.login.assert_not_called()
            mock_server.send_message.assert_called_once()

    def test_smtp_disconnected_error(self):
        with patch("smtplib.SMTP") as mock_smtp:
            mock_server = MagicMock()
            mock_server.send_message.side_effect = smtplib.SMTPServerDisconnected("Server dropped connection")
            mock_smtp.return_value = mock_server

            config = {
                "smtp_host": "smtp.example.com",
                "smtp_port": 587,
                "smtp_security": "STARTTLS"
            }
            success, msg = send_smtp_email(config, ["admin@test.com"], "Subject", "Body")
            self.assertFalse(success)
            self.assertIn("closed", msg)

    def test_scheduler_target_without_id(self):
        sched = ServerScheduler()
        outcome = sched.handle_check_result({}, {"status": "ONLINE"})
        self.assertEqual(outcome, "UNKNOWN")

    def test_scheduler_stop_cancels_pending_insurance(self):
        sched = ServerScheduler(insurance_retries=2, insurance_delay_ms=500)
        target = {"id": "target-to-cancel", "name": "Cancel Me", "status": "ONLINE"}
        sched.handle_check_result(target, {"status": "OFFLINE"})
        self.assertIn("target-to-cancel", sched.in_insurance)
        self.assertIn("target-to-cancel", sched.insurance_timers)

        # Stop target
        sched.stop_server_scheduler("target-to-cancel")
        self.assertNotIn("target-to-cancel", sched.in_insurance)
        self.assertNotIn("target-to-cancel", sched.insurance_timers)
        self.assertNotIn("target-to-cancel", sched.failure_counts)

    def test_none_target_and_result_inputs(self):
        sched = ServerScheduler()
        self.assertEqual(sched.handle_check_result(None, {"status": "ONLINE"}), "UNKNOWN")
        self.assertEqual(sched.handle_check_result({"id": "1"}, None), "UNKNOWN")
        self.assertEqual(sched.handle_check_result("invalid", "invalid"), "UNKNOWN")

    @patch("smtplib.SMTP")
    def test_explicit_envelope_addressing(self, mock_smtp_cls):
        mock_server = MagicMock()
        mock_smtp_cls.return_value = mock_server

        config = {
            "smtp_host": "smtp.company.com",
            "smtp_port": 587,
            "smtp_security": "STARTTLS",
            "smtp_sender": "ServerMon Alerts <alerts@company.com>"
        }
        recipients = ["DevOps Lead <devops@company.com>", "ops@company.com"]

        success, msg = send_smtp_email(config, recipients, "Subject", "Body")
        self.assertTrue(success)

        # Confirm send_message was called with explicit from_addr and to_addrs
        call_kwargs = mock_server.send_message.call_args[1]
        self.assertEqual(call_kwargs["from_addr"], "alerts@company.com")
        self.assertEqual(call_kwargs["to_addrs"], ["devops@company.com", "ops@company.com"])

    @patch("smtplib.SMTP_SSL")
    def test_ssl_cert_verification_error(self, mock_smtp_ssl_cls):
        mock_smtp_ssl_cls.side_effect = ssl.SSLCertVerificationError(1, "[SSL: CERTIFICATE_VERIFY_FAILED]")
        config = {
            "smtp_host": "smtp.internal.selfsigned",
            "smtp_port": 465,
            "smtp_security": "SSL/TLS"
        }
        success, msg = send_smtp_email(config, ["admin@test.com"], "Subject", "Body")
        self.assertFalse(success)
        self.assertIn("Certificate verification failed", msg)

    def test_alert_notifier_stop_all(self):
        notifier_obj = AlertNotifier()
        mock_worker = MagicMock()
        mock_worker.isRunning.return_value = True
        notifier_obj.active_workers.append(mock_worker)

        notifier_obj.stop_all(timeout_ms=100)
        mock_worker.wait.assert_called_once_with(100)
        self.assertEqual(len(notifier_obj.active_workers), 0)


class TestSettingsManagerIntegration(unittest.TestCase):
    """Tests settings defaults and helper methods."""

    def test_default_settings_contain_email_and_insurance_keys(self):
        for key in [
            "insurance_retries",
            "insurance_delay_ms",
            "email_alerts_enabled",
            "smtp_host",
            "smtp_port",
            "smtp_user",
            "smtp_password",
            "smtp_security",
            "smtp_sender",
            "email_recipients",
        ]:
            self.assertIn(key, DEFAULT_SETTINGS)

    def test_get_smtp_config_helper(self):
        test_file = BASE_DIR / "config" / "test_tmp_settings.json"
        try:
            mgr = SettingsManager(filepath=str(test_file))
            mgr.set("smtp_host", "smtp.mymail.com")
            mgr.set("smtp_port", 465)
            mgr.set("smtp_security", "SSL/TLS")
            mgr.set("email_recipients", "ops@domain.com, it@domain.com")
            mgr.set("email_alerts_enabled", True)

            cfg = mgr.get_smtp_config()
            self.assertEqual(cfg["smtp_host"], "smtp.mymail.com")
            self.assertEqual(cfg["smtp_port"], 465)
            self.assertEqual(cfg["smtp_security"], "SSL/TLS")
            self.assertTrue(cfg["email_alerts_enabled"])
            self.assertEqual(cfg["email_recipients"], "ops@domain.com, it@domain.com")
        finally:
            if test_file.exists():
                test_file.unlink()


if __name__ == "__main__":
    unittest.main()
