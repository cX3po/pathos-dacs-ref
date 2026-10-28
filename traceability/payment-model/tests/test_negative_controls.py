"""Runnable regression controls for inventory integrity and selected misreadings."""
from pathlib import Path
import importlib.util
import json
import sys
import subprocess
import tempfile
from unittest.mock import patch
from copy import deepcopy
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("traceability_check", ROOT / "check.py")
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


class NegativeControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        m = check.model()
        mapping = json.loads((ROOT / "mapping.json").read_text())
        elements, _ = check.inventory(m)
        cls.mapping, cls.source = check.synthetic_fixture(mapping)
        cls.elements = elements
        cls.results = dict(check.probes(m, mapping, elements))

    def test_deleted_mapping_is_rejected(self):
        self.assertTrue(self.results["unmapped_model_element"])

    def test_wrong_clause_span_is_rejected(self):
        self.assertTrue(self.results["wrong_clause_span"])

    def test_changed_pinned_spec_is_rejected(self):
        self.assertTrue(self.results["changed_spec"])

    def test_stale_does_not_allow_delivery(self):
        self.assertTrue(self.results["PIPE-3_native_STALE_is_not_included"])

    def test_missing_is_not_definitive_non_execution(self):
        self.assertTrue(self.results["assumption_MISSING_is_not_failed_proven"])

    def test_synthetic_baseline_is_valid(self):
        self.assertEqual(check.validate(self.mapping, self.elements, self.source), [])

    def test_missing_spec_dir_is_refused(self):
        run = subprocess.run([sys.executable, str(ROOT/'check.py')], capture_output=True)
        self.assertEqual(run.returncode, 2)

    def test_wrong_commit_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, 'commit differs'):
                check.load_spec(directory, self.mapping,
                                revision_reader=lambda root: (root, '0' * 40))

    def test_missing_checkout_is_refused(self):
        def missing_checkout(root):
            raise subprocess.CalledProcessError(128, ['git', 'rev-parse'])
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(subprocess.CalledProcessError) as caught:
                check.load_spec(directory, self.mapping, revision_reader=missing_checkout)
            self.assertEqual(caught.exception.returncode, 128)

    def test_wrong_checkout_root_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, 'checkout root'):
                check.load_spec(directory, self.mapping,
                                revision_reader=lambda root: (root.parent, check.PIN))

    def test_wrong_clause_id_is_refused(self):
        bad = deepcopy(self.mapping)
        next(iter(bad['elements'].values()))['refs'][0]['clause_id'] = 'wrong'
        self.assertTrue(check.validate(bad, self.elements, self.source))

    def test_model_drift_is_rejected_before_import_for_all_callers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'model').mkdir()
            (root/'mapping.json').write_text(json.dumps(self.mapping))
            (root/'model/explore.py').write_text('raise AssertionError("unverified model executed")')
            with patch.object(check, 'ROOT', root):
                with self.assertRaisesRegex(ValueError, 'model bytes changed'):
                    check.model()


if __name__ == "__main__":
    unittest.main()
