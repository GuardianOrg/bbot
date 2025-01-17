
from .test_module_excavate import TestExcavateParameterExtraction


class TestParameters(TestExcavateParameterExtraction):
    modules_overrides = ["excavate", "httpx", "parameters"]

    def check(self, module_test, events):

        parameters_file = module_test.scan.home / "parameters.txt"
        with open(parameters_file) as f:
            data = f.read()

            assert "age" in data
            assert "fit" in data
            assert "id" in data
            assert "jqueryget" in data
            assert "jquerypost" in data
            assert "q1" in data
            assert "q2" in data
            assert "q3" in data
            assert "size" in data
            assert "test" in data

            # after lightfuzz is merged uncomment these additional parameters

            # assert "blog-post-author-display" in data
            # assert "csrf" in data

            
class TestParameters_include_count(TestParameters):
    config_overrides = {"web": {"spider_distance": 1, "spider_depth": 1}, "modules": {"parameters": {"include_count": True}}}

    def check(self, module_test, events):
        parameters_file = module_test.scan.home / "parameters.txt"
        with open(parameters_file) as f:
            assert "2:q" in data
            assert "1:age" in data
            assert "1:fit" in data
            assert "1:id" in data
            assert "1:jqueryget" in data
            assert "1:jquerypost" in data
            assert "1:size" in data
            assert "1:test" in data

            # after lightfuzz is merged, these will be the correct parameters to check

            # assert "3:test" in data
            # assert "2:blog-post-author-display" in data
            # assert "2:csrf" in data
            # assert "2:q2" in data
            # assert "1:age" in data
            # assert "1:fit" in data
            # assert "1:id" in data
            # assert "1:jqueryget" in data
            # assert "1:jquerypost" in data
            # assert "1:q1" in data
            # assert "1:q3" in data
            # assert "1:size" in data
