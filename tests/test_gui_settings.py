"""
Verification test for NetworkMonitorUI Settings Page construction and controls.
Runs offscreen without displaying a window.
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock
from PySide6.QtWidgets import QApplication, QMessageBox
from PySide6.QtCore import Qt

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from gui import NetworkMonitorUI


class TestGuiSettingsPage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Create offscreen Qt application
        cls.app = QApplication.instance() or QApplication(["--platform", "offscreen"])

    def setUp(self):
        self._orig_warning = QMessageBox.warning
        self._orig_info = QMessageBox.information
        QMessageBox.warning = MagicMock()
        QMessageBox.information = MagicMock()
        self.ui = NetworkMonitorUI(str(BASE_DIR / "gui.ui"))

    def tearDown(self):
        self.ui.scheduler.stop_all()
        QMessageBox.warning = self._orig_warning
        QMessageBox.information = self._orig_info

    def test_settings_widgets_initialized(self):
        """Verify all settings widgets exist and are populated with config."""
        self.assertIsNotNone(self.ui.txt_workers)
        self.assertIsNotNone(self.ui.spn_timeout)
        self.assertIsNotNone(self.ui.spn_online_interval)
        self.assertIsNotNone(self.ui.spn_offline_interval)
        self.assertIsNotNone(self.ui.spn_insurance_retries)
        self.assertIsNotNone(self.ui.cmb_monitor_speed)

        # Email & alert controls
        self.assertIsNotNone(self.ui.chk_email_enabled)
        self.assertIsNotNone(self.ui.txt_smtp_host)
        self.assertIsNotNone(self.ui.spn_smtp_port)
        self.assertIsNotNone(self.ui.cmb_smtp_security)
        self.assertIsNotNone(self.ui.txt_smtp_user)
        self.assertIsNotNone(self.ui.txt_smtp_password)
        self.assertIsNotNone(self.ui.txt_smtp_sender)
        self.assertIsNotNone(self.ui.txt_email_recipients)
        self.assertIsNotNone(self.ui.btn_save_email)
        self.assertIsNotNone(self.ui.btn_test_email)

    def test_insurance_retries_change_handler(self):
        """Verify updating insurance retries spinbox updates settings and scheduler."""
        self.ui.spn_insurance_retries.setValue(3)
        self.assertEqual(self.ui.insurance_retries, 3)
        self.assertEqual(self.ui.scheduler.insurance_retries, 3)
        self.assertEqual(self.ui.settings.get("insurance_retries"), 3)

    def test_save_email_settings_handler(self):
        """Verify saving email settings persists all fields to settings manager."""
        self.ui.chk_email_enabled.setChecked(True)
        self.ui.txt_smtp_host.setText("smtp.internal.corp")
        self.ui.spn_smtp_port.setValue(465)
        self.ui.cmb_smtp_security.setCurrentIndex(1) # SSL/TLS
        self.ui.txt_smtp_user.setText("alerts@corp.com")
        self.ui.txt_smtp_password.setText("SuperSecretToken")
        self.ui.txt_smtp_sender.setText("ServerMon <alerts@corp.com>")
        self.ui.txt_email_recipients.setPlainText("admin@corp.com; oncall@corp.com")

        self.ui.handle_save_email_settings()

        cfg = self.ui.settings.get_smtp_config()
        self.assertTrue(cfg["email_alerts_enabled"])
        self.assertEqual(cfg["smtp_host"], "smtp.internal.corp")
        self.assertEqual(cfg["smtp_port"], 465)
        self.assertEqual(cfg["smtp_user"], "alerts@corp.com")
        self.assertEqual(cfg["smtp_password"], "SuperSecretToken")
        self.assertEqual(cfg["smtp_sender"], "ServerMon <alerts@corp.com>")
        self.assertEqual(cfg["email_recipients"], "admin@corp.com; oncall@corp.com")
        self.assertIn("Saved", self.ui.lbl_email_feedback.text())

    def test_save_email_settings_missing_host_validation(self):
        """Verify saving with email enabled but empty host gives warning feedback."""
        self.ui.chk_email_enabled.setChecked(True)
        self.ui.txt_smtp_host.setText("")
        self.ui.txt_email_recipients.setPlainText("admin@domain.com")
        self.ui.handle_save_email_settings()
        self.assertIn("Host is required", self.ui.lbl_email_feedback.text())

    def test_batch_check_failure_initiates_insurance_verification(self):
        """Verify that a batch check failure on an online target triggers insurance verification flow."""
        test_target = {
            "id": "batch-test-1",
            "name": "Batch Target",
            "host": "192.168.1.50",
            "check_type": "TCP",
            "port": 80,
            "status": "ONLINE"
        }
        self.ui.targets.append(test_target)
        self.ui.target_lookup["batch-test-1"] = test_target
        self.ui.scheduler.start_server_scheduler(test_target)

        # Simulate batch check worker finished for this target with failure
        payload = {
            "target_id": "batch-test-1",
            "result": {"status": "OFFLINE", "error": "Connection refused", "check_type": "TCP", "response_time_ms": None, "resolved_ip": None},
            "timestamp": "2026-10-10 12:00:00"
        }
        self.ui.handle_target_checked(payload)

        # Server must enter VERIFYING state, NOT immediately OFFLINE!
        self.assertEqual(test_target["status"], "VERIFYING")
        self.assertIn("batch-test-1", self.ui.scheduler.in_insurance)

    def test_audit_logs_receive_alert_and_dispatch_events(self):
        """Verify that live audit logs receive server down alerts and email dispatch events."""
        test_target = {"id": "log-test-1", "name": "Log Server", "host": "10.0.0.1"}
        self.ui._on_insurance_attempt(test_target, 1, 2)
        logs = self.ui.window.txt_audit_logs.toPlainText()
        self.assertIn("INSURANCE: Log Server", logs)

        self.ui._on_email_dispatched(True, "Mock dispatch success")
        logs_after_email = self.ui.window.txt_audit_logs.toPlainText()
        self.assertIn("EMAIL DISPATCH: Mock dispatch success", logs_after_email)


if __name__ == "__main__":
    unittest.main()
