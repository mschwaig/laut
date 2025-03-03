import unittest
from typing import NamedTuple
from itertools import product

from trace_signatures.verification.verification import get_resolution_combinations 

class TestResolutionCombinations(unittest.TestCase):
    def test_simple_string_combinations(self):
        """Test with simple string keys and values"""
        test_input = {"a": {"b", "c"}}
        expected = [{"a": "b"}, {"a": "c"}]
        
        result = list(get_resolution_combinations(test_input))
        self.assertEqual(len(result), 2, "Should generate 2 combinations")
        self.assertCountEqual(result, expected)

    def test_multiple_keys(self):
        """Test with multiple keys, each with multiple values"""
        test_input = {"a": {"b", "c"}, "x": {"y", "z"}}
        expected = [
            {"a": "b", "x": "y"},
            {"a": "b", "x": "z"},
            {"a": "c", "x": "y"},
            {"a": "c", "x": "z"}
        ]
        
        result = list(get_resolution_combinations(test_input))
        self.assertEqual(len(result), 4, "Should generate 4 combinations")
        self.assertCountEqual(result, expected)

    def test_empty_set(self):
        """Test with an empty set for one key"""
        test_input = {"a": {"b", "c"}, "x": set()}
        result = list(get_resolution_combinations(test_input))
        self.assertEqual(len(result), 0, "Should generate 0 combinations when any set is empty")

    def test_empty_dict(self):
        """Test with an empty dictionary"""
        test_input = {}
        result = list(get_resolution_combinations(test_input))
        self.assertEqual(len(result), 1, "Should generate 1 combination (empty dict) for empty input")
        self.assertEqual(result[0], {})

    def test_with_custom_objects(self):
        """Test with custom object keys and values"""
        class Key(NamedTuple):
            id: str
        
        class Value(NamedTuple):
            data: str
        
        key1 = Key(id="key1")
        key2 = Key(id="key2")
        value1 = Value(data="val1")
        value2 = Value(data="val2")
        value3 = Value(data="val3")
        
        test_input = {
            key1: {value1, value2},
            key2: {value2, value3}
        }
        
        result = list(get_resolution_combinations(test_input))
        self.assertEqual(len(result), 4, "Should generate 4 combinations with custom objects")
        
        # Verify all combinations exist
        combinations = set()
        for res in result:
            combinations.add((res[key1].data, res[key2].data))
        
        expected_combinations = {
            ("val1", "val2"), 
            ("val1", "val3"), 
            ("val2", "val2"), 
            ("val2", "val3")
        }
        self.assertEqual(combinations, expected_combinations)

    def test_large_combination_count(self):
        """Test that we can efficiently handle a large number of combinations"""
        # 5 keys with 3 values each = 3^5 = 243 combinations
        test_input = {
            f"key{i}": {f"val{i}_{j}" for j in range(3)}
            for i in range(5)
        }
        
        result = list(get_resolution_combinations(test_input))
        self.assertEqual(len(result), 3**5, f"Should generate 3^5 = {3**5} combinations")