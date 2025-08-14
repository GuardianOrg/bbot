import pytest
import string
import random
from bbot.scanner import Scanner


class TestBloomFilterBenchmarks:
    """
    Benchmark tests for Bloom Filter operations.
    
    These tests measure the performance of bloom filter operations which are
    critical for DNS brute-forcing efficiency in BBOT.
    """

    def setup_method(self):
        """Setup common test data"""
        self.scan = Scanner()
        
        # Generate test data of different sizes
        self.items_small = self._generate_random_strings(1000)  # 1K items
        self.items_medium = self._generate_random_strings(10000)  # 10K items
        
    def _generate_random_strings(self, n, length=10):
        """Generate a list of n random strings."""
        return ["".join(random.choices(string.ascii_letters + string.digits, k=length)) for _ in range(n)]

    @pytest.mark.benchmark(group="bloom_add")
    def test_bloom_filter_add_1k_items(self, benchmark):
        """Benchmark adding 1,000 items to bloom filter"""
        def add_items():
            bloom_filter = self.scan.helpers.bloom_filter(size=8000000)  # 8M bits
            for item in self.items_small:
                bloom_filter.add(item)
            return len(self.items_small)
        
        result = benchmark(add_items)
        assert result == 1000

    @pytest.mark.benchmark(group="bloom_add")
    def test_bloom_filter_add_10k_items(self, benchmark):
        """Benchmark adding 10,000 items to bloom filter"""
        def add_items():
            bloom_filter = self.scan.helpers.bloom_filter(size=8000000)  # 8M bits
            for item in self.items_medium:
                bloom_filter.add(item)
            return len(self.items_medium)
        
        result = benchmark(add_items)
        assert result == 10000

    @pytest.mark.benchmark(group="bloom_check")
    def test_bloom_filter_check_1k_items(self, benchmark):
        """Benchmark checking 1,000 items in bloom filter (all should be found)"""
        # Pre-populate the filter
        bloom_filter = self.scan.helpers.bloom_filter(size=8000000)
        for item in self.items_small:
            bloom_filter.add(item)
            
        def check_items():
            found = 0
            for item in self.items_small:
                if item in bloom_filter:
                    found += 1
            return found
        
        result = benchmark(check_items)
        assert result == 1000  # All items should be found

    @pytest.mark.benchmark(group="bloom_check")
    def test_bloom_filter_check_10k_items(self, benchmark):
        """Benchmark checking 10,000 items in bloom filter (all should be found)"""
        # Pre-populate the filter
        bloom_filter = self.scan.helpers.bloom_filter(size=8000000)
        for item in self.items_medium:
            bloom_filter.add(item)
            
        def check_items():
            found = 0
            for item in self.items_medium:
                if item in bloom_filter:
                    found += 1
            return found
        
        result = benchmark(check_items)
        assert result == 10000  # All items should be found

    @pytest.mark.benchmark(group="bloom_mixed")
    def test_bloom_filter_mixed_operations(self, benchmark):
        """Benchmark mixed add/check operations simulating real DNS brute-force usage"""
        def mixed_operations():
            bloom_filter = self.scan.helpers.bloom_filter(size=8000000)
            
            # Add phase (simulates adding tried mutations)
            for item in self.items_small:
                bloom_filter.add(item)
            
            # Check phase (simulates checking if mutation was already tried)
            found = 0
            for item in self.items_small:
                if item in bloom_filter:
                    found += 1
            
            return found
        
        result = benchmark(mixed_operations)
        assert result == 1000 