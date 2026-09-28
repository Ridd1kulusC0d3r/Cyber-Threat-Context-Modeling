import unittest

from fastapi.testclient import TestClient

from tce.webapp import create_app


class WebAppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(create_app("examples/cases/enterprise-identity"))

    def test_home(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Do contexto", response.text)
        self.assertIn("GLiNER", response.text)

    def test_health(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")

    def test_case_summary(self):
        response = self.client.get("/api/case")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertGreaterEqual(data["counts"]["scenarios"], 1)
        self.assertIn("coverage", data)

    def test_graph(self):
        response = self.client.get("/api/graph")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("nodes", data)
        self.assertIn("edges", data)


if __name__ == "__main__":
    unittest.main()
