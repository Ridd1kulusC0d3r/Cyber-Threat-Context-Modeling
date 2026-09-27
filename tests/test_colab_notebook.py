import json
import unittest
from pathlib import Path


class ColabNotebookTests(unittest.TestCase):
    def test_setup_cell_refreshes_clone_and_injects_src(self):
        path = Path("colab/TCE_v0_3_AI_Knowledge_Graph.ipynb")
        notebook = json.loads(path.read_text(encoding="utf-8"))
        code = "\n".join(
            "".join(cell.get("source", []))
            for cell in notebook.get("cells", [])
            if cell.get("cell_type") == "code"
        )
        self.assertIn("sys.path.insert(0, str(SRC))", code)
        self.assertIn("importlib.invalidate_caches()", code)
        self.assertIn("git', '-C', str(ROOT), 'fetch'", code)
        self.assertIn("import tce", code)


if __name__ == "__main__":
    unittest.main()
