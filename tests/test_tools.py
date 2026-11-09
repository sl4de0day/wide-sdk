import os
import unittest
import tempfile
from pathlib import Path
from wide_sdk.tools import read_file_tool, write_file_tool, edit_file_tool, list_dir_tool, search_files_tool, tool
from wide_sdk.types import ToolResult

class TestTools(unittest.TestCase):
    def setUp(self) -> None:
        self.test_dir = tempfile.TemporaryDirectory()
        self.context = {"working_directory": self.test_dir.name}

    def tearDown(self) -> None:
        self.test_dir.cleanup()

    def test_write_and_read_file(self) -> None:
        write_res = write_file_tool.execute(
            {"path": "hello.txt", "content": "Line 1\nLine 2\nLine 3"},
            self.context
        )
        self.assertTrue(write_res.success)

        read_res = read_file_tool.execute(
            {"path": "hello.txt", "startLine": 2, "endLine": 3},
            self.context
        )
        self.assertTrue(read_res.success)
        self.assertIn("2: Line 2", read_res.output)
        self.assertIn("3: Line 3", read_res.output)

    def test_edit_file(self) -> None:
        write_file_tool.execute(
            {"path": "sample.py", "content": "def add(a, b):\n    return a - b\n"},
            self.context
        )
        edit_res = edit_file_tool.execute(
            {"path": "sample.py", "target": "return a - b", "replacement": "return a + b"},
            self.context
        )
        self.assertTrue(edit_res.success)
        read_res = read_file_tool.execute({"path": "sample.py"}, self.context)
        self.assertIn("return a + b", read_res.output)

    def test_list_dir(self) -> None:
        write_file_tool.execute({"path": "a.txt", "content": "a"}, self.context)
        write_file_tool.execute({"path": "sub/b.txt", "content": "b"}, self.context)
        list_res = list_dir_tool.execute({"path": ".", "maxDepth": 2}, self.context)
        self.assertTrue(list_res.success)
        self.assertIn("a.txt", list_res.output)

    def test_custom_tool_decorator(self) -> None:
        @tool(name="calc_sum", description="Calculate sum of two numbers")
        def calc_sum(x: int, y: int) -> ToolResult:
            return ToolResult(success=True, output=str(x + y))

        self.assertEqual(calc_sum.definition.name, "calc_sum")
        self.assertEqual(calc_sum.definition.parameters["properties"]["x"]["type"], "number")
        res = calc_sum.execute({"x": 5, "y": 7}, self.context)
        self.assertTrue(res.success)
        self.assertEqual(res.output, "12")

if __name__ == "__main__":
    unittest.main()
