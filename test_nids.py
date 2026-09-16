import unittest
import os
import sys

# Ensure root directory in path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.models.multi_model_engine import consensus_engine
from src.xai.explainer import NIDSExplainer
from src.capture.flow_tracker import generate_simulated_flow
from src.db.database import (
    init_db, log_alert, get_recent_alerts, get_threat_summary,
    create_incident, update_incident_status, get_incidents,
    add_to_blocklist, get_blocklist, record_false_positive
)
from src.threat_intel.geoip import get_geoip_info
from src.edr.endpoint_monitor import get_host_metrics, correlate_edr_threat
from src.incident_response.playbook import execute_incident_response
from src.reports.pdf_generator import generate_security_pdf_report

class TestSentinelNetEnterprise(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()
        cls.engine = consensus_engine
        cls.explainer = NIDSExplainer()

    def test_01_models_loaded(self):
        """Verify that multi-model consensus engine is ready."""
        self.assertTrue(self.engine.is_ready)
        self.assertIsNotNone(self.engine.preprocessor)

    def test_02_multi_model_prediction(self):
        """Verify multi-model concurrent execution and voting."""
        flow = generate_simulated_flow("dos_syn_flood")
        res = self.engine.predict_flow(flow)
        self.assertIn("attack_type", res)
        self.assertIn("threat_score", res)
        self.assertIn("severity", res)
        self.assertIn("model_verdicts", res)
        # Check that individual models produced verdicts
        verdicts = res["model_verdicts"]
        self.assertIn("Random Forest", verdicts)
        self.assertIn("Autoencoder", verdicts)

    def test_03_zero_day_detection(self):
        """Verify zero-day anomaly detection and reconstruction loss."""
        flow = generate_simulated_flow("zero_day_anomaly")
        res = self.engine.predict_flow(flow)
        self.assertGreaterEqual(res["threat_score"], 70.0)
        self.assertIn(res["severity"], ["HIGH", "CRITICAL"])
        self.assertGreater(res["reconstruction_error"], 0.0)

    def test_04_geoip_resolution(self):
        """Verify Geo-IP, ASN, and abuse intelligence lookup."""
        geo = get_geoip_info("45.155.205.233")
        self.assertEqual(geo["country"], "Russia")
        self.assertEqual(geo["code"], "RU")
        self.assertIn("lat", geo)
        self.assertIn("lon", geo)

    def test_05_endpoint_edr_metrics(self):
        """Verify psutil host metrics and threat correlation."""
        metrics = get_host_metrics()
        self.assertIn("cpu_percent", metrics)
        self.assertIn("ram_percent", metrics)
        corr = correlate_edr_threat(75.0, metrics["cpu_percent"])
        self.assertIn("combined_risk_score", corr)

    def test_06_incident_response_playbook(self):
        """Verify automated ticket creation, Geo-IP, and containment blocklist."""
        flow = generate_simulated_flow("dos_syn_flood")
        res = self.engine.predict_flow(flow)
        playbook_res = execute_incident_response(res)
        self.assertTrue(playbook_res["ticket_id"].startswith("INC-2026-"))
        # Check incident in database
        incidents = get_incidents()
        self.assertGreater(len(incidents), 0)

    def test_07_incident_workflow_and_false_positive(self):
        """Verify incident ticketing workflow and false-positive learning loop."""
        ticket_id = create_incident({
            "src_ip": "192.168.1.100", "dst_ip": "192.168.1.1", "dst_port": 80,
            "attack_type": "Probe", "threat_score": 55.0, "severity": "MEDIUM",
            "confidence": 0.88, "status": "New"
        })
        # Transition status
        update_incident_status(ticket_id, "Investigating")
        # Record false positive
        record_false_positive({"src_ip": "192.168.1.100"}, "Probe", user_notes="Authorized pen-test")
        update_incident_status(ticket_id, "False Positive")
        incidents = get_incidents(status_filter="False Positive")
        self.assertTrue(any(i["ticket_id"] == ticket_id for i in incidents))

    def test_08_pdf_report_generation(self):
        """Verify ReportLab PDF generation."""
        pdf_path = generate_security_pdf_report("enterprise_test_report.pdf")
        self.assertTrue(os.path.exists(pdf_path))
        self.assertGreater(os.path.getsize(pdf_path), 1000)

    def test_09_url_threat_scanner(self):
        """Verify URL & Web Link threat detection and auto-containment."""
        from src.threat_intel.url_scanner import scan_url
        res_safe = scan_url("https://google.com")
        self.assertEqual(res_safe["severity"], "LOW")
        self.assertEqual(res_safe["verdict"], "SAFE & CLEAN LINK")

        res_bad = scan_url("http://malicious-login-update.xyz/paypal/login.php")
        self.assertIn(res_bad["severity"], ["HIGH", "CRITICAL"])
        self.assertIn("PHISHING", res_bad["verdict"])
        self.assertGreaterEqual(res_bad["threat_score"], 70.0)

if __name__ == "__main__":
    unittest.main()
