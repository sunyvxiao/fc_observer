"""
test_tuning.py — TuningLoader 调优参数加载器单元测试

测试内容:
1. TuningLoader: YAML 加载、默认值回退、缓存机制、reload
2. get_tuning(): 全局单例
3. _deep_merge(): 递归合并逻辑
4. 边界条件: 文件不存在、空 YAML、部分字段覆盖
"""

import sys
import os
import unittest
import tempfile
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from observer_core.judgment.tuning_loader import TuningLoader, get_tuning


class TestTuningLoaderDefaults(unittest.TestCase):
    """TuningLoader 默认值测试（无 tuning.yaml 场景）"""

    def test_load_without_file_returns_defaults(self):
        """文件不存在时返回硬编码默认值"""
        loader = TuningLoader("/nonexistent/tuning.yaml")
        params = loader.load()
        self.assertIn("scoring", params)
        self.assertIn("decision", params)
        self.assertIn("escalation", params)
        self.assertIn("baseline", params)
        self.assertIn("report_cache", params)

    def test_default_scoring_dimensions_exist(self):
        """默认评分维度包含四个维度"""
        loader = TuningLoader("/nonexistent/tuning.yaml")
        params = loader.load()
        dims = params["scoring"]["dimensions"]
        self.assertIn("rule_score", dims)
        self.assertIn("baseline_score", dims)
        self.assertIn("context_score", dims)
        self.assertIn("sequence_score", dims)

    def test_default_scoring_weights_sum_to_one(self):
        """默认评分权重之和为 1.0"""
        loader = TuningLoader("/nonexistent/tuning.yaml")
        params = loader.load()
        dims = params["scoring"]["dimensions"]
        total = sum(d["weight"] for d in dims.values())
        self.assertAlmostEqual(total, 1.0, delta=0.01)

    def test_default_decision_thresholds(self):
        """默认决策阈值合理"""
        loader = TuningLoader("/nonexistent/tuning.yaml")
        params = loader.load()
        d = params["decision"]
        self.assertTrue(d["enable_auto_escalation"])
        self.assertLess(d["thresholds"]["high_score"],
                        d["thresholds"]["critical_score"])

    def test_default_escalation_params(self):
        """默认升级参数"""
        loader = TuningLoader("/nonexistent/tuning.yaml")
        params = loader.load()
        e = params["escalation"]
        self.assertGreater(e["window_size_ns"], 0)
        self.assertGreater(e["tier1_escalate_threshold"], 0)
        self.assertGreater(e["tier2_escalate_threshold"], 0)

    def test_default_baseline_params(self):
        """默认基线参数"""
        loader = TuningLoader("/nonexistent/tuning.yaml")
        params = loader.load()
        b = params["baseline"]
        self.assertGreater(b["min_warm_events"], 0)
        self.assertTrue(len(b["baseline_dir"]) > 0)

    def test_default_report_cache_params(self):
        """默认报告缓存参数"""
        loader = TuningLoader("/nonexistent/tuning.yaml")
        params = loader.load()
        rc = params["report_cache"]
        self.assertGreater(rc["auto_interval"], 0)
        self.assertGreater(rc["max_segments"], 0)


class TestTuningLoaderWithYAML(unittest.TestCase):
    """TuningLoader YAML 加载与合并测试"""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="tuning_test_")

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _write_tuning(self, data: dict, filename="tuning.yaml") -> str:
        path = os.path.join(self._tmpdir, filename)
        with open(path, "w", encoding="utf-8") as f:
            yaml.dump(data, f)
        return path

    def test_load_valid_yaml(self):
        """加载有效的 YAML 文件"""
        path = self._write_tuning({
            "scoring": {
                "dimensions": {
                    "rule_score": {"weight": 0.50},
                }
            }
        })
        loader = TuningLoader(path)
        params = loader.load()
        self.assertEqual(params["scoring"]["dimensions"]["rule_score"]["weight"], 0.50)

    def test_partial_override_preserves_defaults(self):
        """部分覆盖不丢失未指定字段"""
        path = self._write_tuning({
            "scoring": {
                "dimensions": {
                    "rule_score": {"weight": 0.99},
                }
            }
        })
        loader = TuningLoader(path)
        params = loader.load()
        # 覆盖的字段
        self.assertEqual(params["scoring"]["dimensions"]["rule_score"]["weight"], 0.99)
        # 未覆盖的字段仍然存在
        self.assertIn("baseline_score", params["scoring"]["dimensions"])
        self.assertAlmostEqual(
            params["scoring"]["dimensions"]["baseline_score"]["weight"], 0.25)

    def test_empty_yaml_returns_defaults(self):
        """空 YAML 返回完整默认值"""
        path = self._write_tuning({})
        loader = TuningLoader(path)
        params = loader.load()
        self.assertIn("scoring", params)
        self.assertIn("decision", params)

    def test_deep_merge_nested(self):
        """深合并：嵌套字典递归合并"""
        path = self._write_tuning({
            "decision": {
                "thresholds": {
                    "critical_score": 0.99,
                }
            }
        })
        loader = TuningLoader(path)
        params = loader.load()
        # 覆盖的字段
        self.assertEqual(params["decision"]["thresholds"]["critical_score"], 0.99)
        # 同一父节点下的兄弟字段保留
        self.assertEqual(params["decision"]["thresholds"]["high_score"], 0.6)
        # 其他顶级字段保留
        self.assertTrue(params["decision"]["enable_auto_escalation"])

    def test_deep_merge_new_key(self):
        """深合并：新增顶级键"""
        path = self._write_tuning({"new_feature": {"enabled": True}})
        loader = TuningLoader(path)
        params = loader.load()
        self.assertTrue(params["new_feature"]["enabled"])
        # 原有字段保留
        self.assertIn("scoring", params)

    def test_cache_returns_same_object(self):
        """load() 默认使用缓存"""
        loader = TuningLoader("/nonexistent/tuning.yaml")
        p1 = loader.load()
        p2 = loader.load()
        self.assertIs(p1, p2)

    def test_force_reload_returns_new_object(self):
        """force_reload=True 忽略缓存"""
        path = self._write_tuning({"scoring": {"dimensions": {"rule_score": {"weight": 0.88}}}})
        loader = TuningLoader(path)
        p1 = loader.load()
        # 修改 YAML 文件
        self._write_tuning({"scoring": {"dimensions": {"rule_score": {"weight": 0.11}}}})
        p2 = loader.load(force_reload=True)
        self.assertEqual(p2["scoring"]["dimensions"]["rule_score"]["weight"], 0.11)
        # p1 不受影响（返回新的合并结果）
        self.assertEqual(p1["scoring"]["dimensions"]["rule_score"]["weight"], 0.88)

    def test_reload_method(self):
        """reload() 方法强制重新加载"""
        path = self._write_tuning({"scoring": {"dimensions": {"rule_score": {"weight": 0.77}}}})
        loader = TuningLoader(path)
        p1 = loader.load()
        self._write_tuning({"scoring": {"dimensions": {"rule_score": {"weight": 0.33}}}})
        p2 = loader.reload()
        self.assertEqual(p2["scoring"]["dimensions"]["rule_score"]["weight"], 0.33)


class TestTuningLoaderEdgeCases(unittest.TestCase):
    """TuningLoader 边界条件测试"""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="tuning_edge_")

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_non_dict_leaf_override(self):
        """非字典叶子节点直接覆盖"""
        path = os.path.join(self._tmpdir, "tuning.yaml")
        with open(path, "w") as f:
            yaml.dump({"decision": {"enable_auto_escalation": False}}, f)
        loader = TuningLoader(path)
        params = loader.load()
        self.assertFalse(params["decision"]["enable_auto_escalation"])

    def test_deep_merge_list_override(self):
        """列表字段直接覆盖（非递归合并）"""
        path = os.path.join(self._tmpdir, "tuning.yaml")
        with open(path, "w") as f:
            yaml.dump({
                "scoring": {
                    "dimensions": {
                        "baseline_score": {
                            "safe_dirs": ["/custom/"],
                        }
                    }
                }
            }, f)
        loader = TuningLoader(path)
        params = loader.load()
        self.assertEqual(
            params["scoring"]["dimensions"]["baseline_score"]["safe_dirs"],
            ["/custom/"])

    def test_specific_tuning_path_constructor(self):
        """指定 tuning_path 构造"""
        path = os.path.join(self._tmpdir, "my_tuning.yaml")
        with open(path, "w") as f:
            yaml.dump({"decision": {"thresholds": {"high_score": 0.75}}}, f)
        loader = TuningLoader(path)
        params = loader.load()
        self.assertEqual(params["decision"]["thresholds"]["high_score"], 0.75)


if __name__ == "__main__":
    unittest.main()
