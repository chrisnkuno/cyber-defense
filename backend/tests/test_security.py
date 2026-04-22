import unittest

import engine
import scanner


class EngineModelTests(unittest.TestCase):
    def test_higher_risk_state_increases_breach_probability(self):
        safer = engine.default_state(
            {
                "passwordReuse": 0.1,
                "phishingExposure": 0.1,
                "patchLatency": 0.1,
                "networkExposure": 0.1,
                "deviceHygiene": 0.1,
                "mfaCoverage": 0.9,
                "backupReadiness": 0.9,
                "securityFatigue": 0.1,
                "dataExposure": 0.1,
            }
        )
        riskier = engine.default_state(
            {
                "passwordReuse": 0.8,
                "phishingExposure": 0.75,
                "patchLatency": 0.72,
                "networkExposure": 0.7,
                "deviceHygiene": 0.68,
                "mfaCoverage": 0.2,
                "backupReadiness": 0.22,
                "securityFatigue": 0.71,
                "dataExposure": 0.8,
            }
        )

        self.assertGreater(
            engine.calculate_breach_probability(riskier),
            engine.calculate_breach_probability(safer),
        )
        self.assertGreater(engine.calculate_risk_score(riskier), engine.calculate_risk_score(safer))

    def test_recommendations_are_ranked_for_exposed_users(self):
        state = engine.default_state(
            {
                "passwordReuse": 0.7,
                "phishingExposure": 0.62,
                "patchLatency": 0.58,
                "networkExposure": 0.6,
                "deviceHygiene": 0.55,
                "mfaCoverage": 0.3,
                "backupReadiness": 0.4,
                "securityFatigue": 0.65,
                "dataExposure": 0.61,
            }
        )

        scenarios = engine.calculate_scenario_likelihoods(state)
        recommendations = engine.build_recommendations(state, scenarios)

        self.assertGreater(len(recommendations), 0)
        self.assertGreaterEqual(
            recommendations[0]["priorityScore"],
            recommendations[-1]["priorityScore"],
        )


class ScannerTests(unittest.TestCase):
    def test_sensitive_file_risk_uses_threshold_map(self):
        findings = scanner.SecurityScanner.check_file_permissions(["/etc/passwd", "~/.bash_history"])
        by_path = {item["path"]: item for item in findings}

        self.assertEqual(by_path["/etc/passwd"]["sensitivity"], "baseline")
        self.assertIn(by_path["/etc/passwd"]["risk"], {"Info", "Medium"})
        self.assertEqual(by_path["~/.bash_history"]["sensitivity"], "sensitive")


if __name__ == "__main__":
    unittest.main()
