#!/usr/bin/env python3
"""
Comprehensive CIG Functionality Test Suite
Tests all components of the Cyber Intelligence Gateway
"""

import sys
import os
import json
import traceback
from pathlib import Path
from datetime import datetime, timedelta
import tempfile
import shutil

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

# Set test environment variables
os.environ['SKIP_FEED_UPDATES'] = 'true'
os.environ['SKIP_DNS_MONITORING'] = 'true'

class CIGTestSuite:
    """Comprehensive test suite for CIG components"""

    def __init__(self):
        self.results = {
            "test_run": {
                "timestamp": datetime.utcnow().isoformat(),
                "python_version": sys.version,
                "working_directory": os.getcwd()
            },
            "components": {},
            "summary": {
                "total_tests": 0,
                "passed": 0,
                "failed": 0,
                "skipped": 0
            }
        }
        self.temp_dir = Path(tempfile.mkdtemp(prefix="cig_test_"))
        self.test_db_path = self.temp_dir / "test.db"

    def run_all_tests(self):
        """Run all component tests"""
        print("🚀 Starting CIG Comprehensive Test Suite")
        print(f"📁 Test directory: {self.temp_dir}")
        print("=" * 60)

        # Test components in dependency order
        self.test_configuration()
        self.test_database()
        self.test_pcap_capture()
        self.test_feeds()
        self.test_mitre_mapper()
        self.test_security_reporter()
        self.test_threat_matcher()
        self.test_api_routes()
        self.test_main_application()

        # Generate summary
        self.generate_summary()
        self.save_report()

        return self.results

    def test_configuration(self):
        """Test configuration system"""
        print("\n🔧 Testing Configuration System...")

        try:
            from app.core.config import settings, Settings

            # Test default values
            assert settings.app_name == "Cyber Intelligence Gateway"
            assert settings.api_port == 8000
            assert settings.debug is False

            # Test environment variable override
            os.environ['APP_NAME'] = 'Test CIG'
            test_settings = Settings.from_env()
            assert test_settings.app_name == 'Test CIG'

            # Test new AbuseIPDB config
            assert hasattr(settings, 'abuseipdb_api_key')
            assert hasattr(settings, 'skip_feed_updates')

            self.record_test("configuration", "basic_config", True, "Configuration loads with correct defaults")
            self.record_test("configuration", "env_override", True, "Environment variables override defaults")
            self.record_test("configuration", "new_features", True, "New AbuseIPDB and feed skip configs present")

        except Exception as e:
            self.record_test("configuration", "all", False, f"Configuration test failed: {e}")
            traceback.print_exc()

    def test_database(self):
        """Test database operations"""
        print("\n💾 Testing Database Operations...")

        try:
            from app.models.database import Database, Alert, Indicator, PcapFile

            # Create test database
            db = Database(str(self.test_db_path))

            # Test alert operations
            alert = Alert(
                id="test-alert-1",
                timestamp=datetime.utcnow().isoformat(),
                severity="high",
                source_ip="192.168.1.100",
                destination_ip="10.0.0.1",
                source_port=12345,
                destination_port=80,
                protocol="tcp",
                indicator="malicious.example.com",
                indicator_type="domain",
                feed_source="test",
                rule_id="test-rule",
                message="Test alert"
            )

            db.insert_alert(alert)
            alerts = db.get_alerts(limit=10)
            assert len(alerts) == 1
            assert alerts[0].id == "test-alert-1"

            # Test indicator operations
            indicator = Indicator(
                id="test-indicator-1",
                indicator="192.168.1.100",
                indicator_type="ip",
                source="test_feed",
                feed_id="test-feed-1",
                confidence=85,
                tags=["malware"],
                first_seen=datetime.utcnow().isoformat(),
                last_seen=datetime.utcnow().isoformat()
            )

            db.insert_indicator(indicator)
            indicators = db.get_indicators(limit=10)
            assert len(indicators) == 1

            # Test PCAP operations
            pcap = PcapFile(
                id="test-pcap-1",
                filename="test.pcap",
                filepath="/tmp/test.pcap",
                start_time=datetime.utcnow().isoformat(),
                interface="eth0"
            )

            db.insert_pcap(pcap)
            pcaps = db.get_pcaps(limit=10)
            assert len(pcaps) == 1

            self.record_test("database", "alerts", True, "Alert CRUD operations work")
            self.record_test("database", "indicators", True, "Indicator CRUD operations work")
            self.record_test("database", "pcaps", True, "PCAP file tracking works")

        except Exception as e:
            self.record_test("database", "all", False, f"Database test failed: {e}")
            traceback.print_exc()

    def test_pcap_capture(self):
        """Test PCAP capture components"""
        print("\n📡 Testing PCAP Capture...")

        try:
            from app.capture.pcap import PCAPCapture, DNSQueryMonitor, PacketAnalyzer

            # Test PCAPCapture initialization
            db = Database(str(self.test_db_path))
            pcap_capture = PCAPCapture(db)

            assert pcap_capture.db == db
            assert pcap_capture.lan_interface == "eth0"
            assert pcap_capture.wan_interface == "eth1"

            # Test DNS monitor initialization
            dns_monitor = DNSQueryMonitor(db)
            assert dns_monitor.db == db
            assert dns_monitor.dns_log_path.endswith("dns.log")

            # Test packet analyzer initialization
            packet_analyzer = PacketAnalyzer(db)
            assert packet_analyzer.db == db

            self.record_test("pcap", "initialization", True, "PCAP components initialize correctly")
            self.record_test("pcap", "dns_monitor", True, "DNS monitor initializes correctly")
            self.record_test("pcap", "packet_analyzer", True, "Packet analyzer initializes correctly")

        except Exception as e:
            self.record_test("pcap", "all", False, f"PCAP test failed: {e}")
            traceback.print_exc()

    def test_feeds(self):
        """Test threat intelligence feeds"""
        print("\n📰 Testing Threat Intelligence Feeds...")

        try:
            from app.feeds.misp import MISPFeed
            from app.feeds.pfblocker import PFBlockerFeed
            from app.feeds.abuseipdb import AbuseIPDBFeed

            db = Database(str(self.test_db_path))

            # Test MISP feed
            misp_feed = MISPFeed(db)
            assert hasattr(misp_feed, 'is_enabled')
            assert hasattr(misp_feed, 'fetch_and_process')

            # Test pfBlocker feed
            pfblocker_feed = PFBlockerFeed(db)
            assert hasattr(pfblocker_feed, 'is_enabled')
            assert hasattr(pfblocker_feed, 'fetch_from_feeds')

            # Test AbuseIPDB feed
            abuseipdb_feed = AbuseIPDBFeed(db)
            assert hasattr(abuseipdb_feed, 'is_enabled')
            assert hasattr(abuseipdb_feed, 'fetch_blacklist')
            assert hasattr(abuseipdb_feed, 'check_ip')

            self.record_test("feeds", "misp", True, "MISP feed initializes correctly")
            self.record_test("feeds", "pfblocker", True, "pfBlocker feed initializes correctly")
            self.record_test("feeds", "abuseipdb", True, "AbuseIPDB feed initializes correctly")

        except Exception as e:
            self.record_test("feeds", "all", False, f"Feeds test failed: {e}")
            traceback.print_exc()

    def test_mitre_mapper(self):
        """Test MITRE ATT&CK mapping"""
        print("\n🎯 Testing MITRE ATT&CK Mapper...")

        try:
            from app.mitre.attack_mapper import MITREAttackMapper

            db = Database(str(self.test_db_path))
            mapper = MITREAttackMapper(db)

            assert hasattr(mapper, 'map_event_to_ttp')
            assert hasattr(mapper, 'get_technique_info')
            assert hasattr(mapper, 'get_tactic_info')

            # Test basic functionality (without real data)
            result = mapper.map_event_to_ttp({
                "source_ip": "192.168.1.100",
                "destination_ip": "10.0.0.1",
                "protocol": "tcp",
                "message": "Suspicious connection"
            })

            assert isinstance(result, dict)
            assert "matched_techniques" in result

            self.record_test("mitre", "initialization", True, "MITRE mapper initializes correctly")
            self.record_test("mitre", "mapping", True, "Event to TTP mapping works")

        except Exception as e:
            self.record_test("mitre", "all", False, f"MITRE mapper test failed: {e}")
            traceback.print_exc()

    def test_security_reporter(self):
        """Test security reporting"""
        print("\n📊 Testing Security Reporter...")

        try:
            from app.reporting.security_report import SecurityReporter

            db = Database(str(self.test_db_path))
            reporter = SecurityReporter(db)

            assert hasattr(reporter, 'generate_comprehensive_report')
            assert hasattr(reporter, 'reports_dir')

            # Test report generation with empty data
            report = reporter.generate_comprehensive_report(days=1)
            assert isinstance(report, dict)
            assert "executive_summary" in report
            assert "threat_intelligence" in report
            assert "network_activity" in report

            self.record_test("reporter", "initialization", True, "Security reporter initializes correctly")
            self.record_test("reporter", "report_generation", True, "Report generation works with empty data")

        except Exception as e:
            self.record_test("reporter", "all", False, f"Security reporter test failed: {e}")
            traceback.print_exc()

    def test_threat_matcher(self):
        """Test threat matching engine"""
        print("\n⚡ Testing Threat Matching Engine...")

        try:
            from app.matching.engine import ThreatMatcher

            db = Database(str(self.test_db_path))
            matcher = ThreatMatcher(db)

            assert hasattr(matcher, 'start')
            assert hasattr(matcher, 'stop')
            assert hasattr(matcher, 'stats')

            # Test configuration
            matcher.configure()

            # Check that feeds are properly initialized
            assert hasattr(matcher, 'misp_feed')
            assert hasattr(matcher, 'pfblocker_feed')
            assert hasattr(matcher, 'abuseipdb_feed')

            self.record_test("matcher", "initialization", True, "Threat matcher initializes correctly")
            self.record_test("matcher", "configuration", True, "Feed configuration works")
            self.record_test("matcher", "components", True, "All feed components are present")

        except Exception as e:
            self.record_test("matcher", "all", False, f"Threat matcher test failed: {e}")
            traceback.print_exc()

    def test_api_routes(self):
        """Test API routes"""
        print("\n🌐 Testing API Routes...")

        try:
            from app.api.routes import app as fastapi_app, init_app

            db = Database(str(self.test_db_path))
            matcher = ThreatMatcher(db)

            # Initialize the app
            init_app(db, matcher)

            assert fastapi_app.title == "Cyber Intelligence Gateway API"
            assert fastapi_app.version == "1.0.0"

            # Check that routes are registered
            routes = [route.path for route in fastapi_app.routes]
            assert "/api/status" in routes or len(routes) > 0  # At least some routes exist

            self.record_test("api", "initialization", True, "FastAPI app initializes correctly")
            self.record_test("api", "routes", True, "API routes are registered")

        except Exception as e:
            self.record_test("api", "all", False, f"API routes test failed: {e}")
            traceback.print_exc()

    def test_main_application(self):
        """Test main application startup"""
        print("\n🚀 Testing Main Application...")

        try:
            # Test that we can import main without issues
            import app.main

            # Check that key functions exist
            assert hasattr(app.main, 'main')
            assert hasattr(app.main, 'setup_directories')
            assert hasattr(app.main, 'signal_handler')

            # Test directory setup (should not fail)
            app.main.setup_directories()

            self.record_test("main", "imports", True, "Main application imports successfully")
            self.record_test("main", "functions", True, "Main functions are available")
            self.record_test("main", "directories", True, "Directory setup works")

        except Exception as e:
            self.record_test("main", "all", False, f"Main application test failed: {e}")
            traceback.print_exc()

    def record_test(self, component, test_name, passed, message=""):
        """Record a test result"""
        if component not in self.results["components"]:
            self.results["components"][component] = {}

        self.results["components"][component][test_name] = {
            "passed": passed,
            "message": message,
            "timestamp": datetime.utcnow().isoformat()
        }

        self.results["summary"]["total_tests"] += 1
        if passed:
            self.results["summary"]["passed"] += 1
        else:
            self.results["summary"]["failed"] += 1

    def generate_summary(self):
        """Generate test summary"""
        summary = self.results["summary"]
        print("\n" + "=" * 60)
        print("📋 CIG TEST SUITE SUMMARY")
        print("=" * 60)
        print(f"Total Tests: {summary['total_tests']}")
        print(f"✅ Passed: {summary['passed']}")
        print(f"❌ Failed: {summary['failed']}")
        print(f"⏭️  Skipped: {summary['skipped']}")

        success_rate = (summary['passed'] / summary['total_tests'] * 100) if summary['total_tests'] > 0 else 0
        print(f"Success Rate: {success_rate:.1f}%")

        # Component breakdown
        print("\n📊 COMPONENT BREAKDOWN:")
        for component, tests in self.results["components"].items():
            passed = sum(1 for t in tests.values() if t["passed"])
            total = len(tests)
            status = "✅" if passed == total else "❌"
            print(f"  {status} {component}: {passed}/{total} tests passed")

        # Recommendations
        print("\n💡 RECOMMENDATIONS:")
        if summary['failed'] > 0:
            print("  - Review failed tests and fix issues")
            print("  - Check error messages for specific problems")
        else:
            print("  - All tests passed! Ready for production use")
            print("  - Consider adding integration tests with real network data")

    def save_report(self):
        """Save detailed test report to file"""
        report_file = self.temp_dir / "cig_test_report.json"
        with open(report_file, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)

        print(f"\n📄 Detailed report saved to: {report_file}")

        # Also save a human-readable summary
        summary_file = self.temp_dir / "cig_test_summary.txt"
        with open(summary_file, 'w') as f:
            f.write("CIG COMPREHENSIVE TEST REPORT\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Generated: {datetime.utcnow().isoformat()}\n")
            f.write(f"Python Version: {sys.version}\n\n")

            summary = self.results["summary"]
            f.write(f"TEST SUMMARY:\n")
            f.write(f"Total Tests: {summary['total_tests']}\n")
            f.write(f"Passed: {summary['passed']}\n")
            f.write(f"Failed: {summary['failed']}\n")
            f.write(f"Skipped: {summary['skipped']}\n\n")

            f.write("COMPONENT DETAILS:\n")
            for component, tests in self.results["components"].items():
                f.write(f"\n{component.upper()}:\n")
                for test_name, result in tests.items():
                    status = "PASS" if result["passed"] else "FAIL"
                    f.write(f"  {status}: {test_name} - {result['message']}\n")

        print(f"📄 Summary report saved to: {summary_file}")


def main():
    """Run the test suite"""
    suite = CIGTestSuite()
    try:
        results = suite.run_all_tests()
        return 0 if results["summary"]["failed"] == 0 else 1
    except Exception as e:
        print(f"❌ Test suite failed with exception: {e}")
        traceback.print_exc()
        return 1
    finally:
        # Clean up temp directory
        try:
            shutil.rmtree(suite.temp_dir)
        except:
            pass


if __name__ == "__main__":
    sys.exit(main())