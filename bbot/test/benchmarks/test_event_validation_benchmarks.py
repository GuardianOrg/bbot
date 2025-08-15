import pytest
import random
import string
from bbot.scanner import Scanner
from bbot.core.event.base import make_event


class TestEventValidationBenchmarks:
    def setup_method(self):
        """Setup minimal scanner configuration for benchmarking event validation"""
        # Set deterministic random seed for reproducible benchmarks
        random.seed(42)
        
        # Create a minimal scanner with no modules to isolate event validation performance
        self.scanner_config = {
            "modules": [],  # No modules to avoid overhead
            "output_modules": [],  # No output modules
            "dns": {"disable": True},  # Disable DNS to avoid network calls
            "web": {"http_timeout": 1},  # Minimal timeouts
        }
        
    def _generate_diverse_targets(self, count=1000):
        """Generate a diverse set of targets that will trigger different event type auto-detection"""
        # Use deterministic random state for reproducible target generation
        rng = random.Random(42)
        targets = []
        
        # DNS Names (various formats)
        domains = ["example.com", "test.evilcorp.com", "api.subdomain.example.org", "xn--e1afmkfd.xn--p1ai"]
        subdomains = ["www", "api", "mail", "ftp", "admin", "test", "dev", "staging", "blog"]
        tlds = ["com", "org", "net", "io", "co.uk", "de", "fr", "jp"]
        
        for _ in range(count // 10):
            # Standard domains
            targets.append(f"{rng.choice(subdomains)}.{rng.choice(['example', 'test', 'evilcorp'])}.{rng.choice(tlds)}")
            # Bare domains
            targets.append(f"{rng.choice(['example', 'test', 'company'])}.{rng.choice(tlds)}")
        
        # IP Addresses (IPv4 and IPv6)
        for _ in range(count // 15):
            # IPv4
            targets.append(f"{rng.randint(1,254)}.{rng.randint(1,254)}.{rng.randint(1,254)}.{rng.randint(1,254)}")
            # IPv6
            targets.append(f"2001:db8::{rng.randint(1,9999):x}:{rng.randint(1,9999):x}")
        
        # IP Ranges
        for _ in range(count // 20):
            targets.append(f"192.168.{rng.randint(1,254)}.0/24")
            targets.append(f"10.0.{rng.randint(1,254)}.0/24")
        
        # URLs (only supported schemes: http, https)
        url_schemes = ["http", "https"]  # Only schemes supported by BBOT auto-detection
        url_paths = ["", "/", "/admin", "/api/v1", "/login.php", "/index.html"]
        for _ in range(count // 8):
            scheme = rng.choice(url_schemes)
            domain = f"{rng.choice(subdomains)}.example.{rng.choice(tlds)}"
            path = rng.choice(url_paths)
            port = rng.choice(["", ":8080", ":443", ":80", ":8443"])
            targets.append(f"{scheme}://{domain}{port}{path}")
        
        # Open Ports
        ports = [80, 443, 22, 21, 25, 53, 110, 143, 993, 995, 8080, 8443, 3389]
        for _ in range(count // 12):
            domain = f"example.{rng.choice(tlds)}"
            port = rng.choice(ports)
            targets.append(f"{domain}:{port}")
            # IPv4 with port
            ip = f"{rng.randint(1,254)}.{rng.randint(1,254)}.{rng.randint(1,254)}.{rng.randint(1,254)}"
            targets.append(f"{ip}:{port}")
        
        # Email Addresses
        email_domains = ["example.com", "test.org", "company.net"]
        email_users = ["admin", "test", "info", "contact", "support", "sales"]
        for _ in range(count // 15):
            user = rng.choice(email_users)
            domain = rng.choice(email_domains)
            targets.append(f"{user}@{domain}")
            # Plus addressing
            targets.append(f"{user}+{rng.randint(1,999)}@{domain}")
        
        # Mixed/Edge cases that should trigger auto-detection logic
        edge_cases = [
            # Localhost variants
            "localhost", "127.0.0.1", "::1",
            # Punycode domains
            "xn--e1afmkfd.xn--p1ai", "xn--fiqs8s.xn--0zwm56d",
            # Long domains (shortened to avoid issues)
            f"very-long-subdomain-name-for-testing.test.com",
            # IP with ports
            "192.168.1.1", "10.0.0.1:80",
            # URLs with parameters
            "https://example.com/search?q=test&limit=10",
            "http://api.example.com:8080/v1/users?format=json",
            # More standard domains for better compatibility
            "api.test.com", "mail.example.org", "secure.company.net",
        ]
        targets.extend(edge_cases)
        
        # Fill remainder with random variations
        remaining = count - len(targets)
        if remaining > 0:
            for _ in range(remaining):
                choice = rng.randint(1, 4)
                if choice == 1:
                    # Random domain
                    targets.append(f"{''.join(rng.choices(string.ascii_lowercase, k=8))}.com")
                elif choice == 2:
                    # Random IP
                    targets.append(f"{rng.randint(1,254)}.{rng.randint(1,254)}.{rng.randint(1,254)}.{rng.randint(1,254)}")
                elif choice == 3:
                    # Random URL
                    targets.append(f"https://{''.join(rng.choices(string.ascii_lowercase, k=8))}.com/path")
                else:
                    # Random email
                    targets.append(f"{''.join(rng.choices(string.ascii_lowercase, k=8))}@example.com")
        
        # Ensure we have exactly the requested count by removing duplicates and filling as needed
        unique_targets = list(set(targets))
        
        # If we have too few unique targets, generate more
        while len(unique_targets) < count:
            additional_target = f"filler{len(unique_targets)}.example.com"
            if additional_target not in unique_targets:
                unique_targets.append(additional_target)
        
        # Return exactly the requested number of unique targets
        return unique_targets[:count]

    @pytest.mark.benchmark(group="event_validation_small")
    def test_event_validation_small_batch(self, benchmark):
        """Benchmark event validation with small batch (100 targets) for quick iteration"""
        targets = self._generate_diverse_targets(100)
        
        def validate_event_batch():
            scan = Scanner(*targets, config=self.scanner_config)
            # Count successful event creations and types detected
            event_counts = {}
            total_events = 0
            
            for event_seed in scan.target.seeds:
                event_type = event_seed.type
                event_counts[event_type] = event_counts.get(event_type, 0) + 1
                total_events += 1
            
            return {
                'total_events_processed': total_events,
                'unique_event_types': len(event_counts),
                'event_type_breakdown': event_counts,
                'targets_input': len(targets)
            }
        
        result = benchmark(validate_event_batch)
        assert result['total_events_processed'] == result['targets_input']  # Should process ALL targets
        assert result['unique_event_types'] >= 3  # Should detect at least DNS_NAME, IP_ADDRESS, URL

    @pytest.mark.benchmark(group="event_validation_large")
    def test_event_validation_large_batch(self, benchmark):
        """Benchmark event validation with large batch (1000 targets) for comprehensive testing"""
        targets = self._generate_diverse_targets(1000)
        
        def validate_large_batch():
            scan = Scanner(*targets, config=self.scanner_config)
            
            # Comprehensive analysis of validation pipeline performance
            validation_metrics = {
                'targets_input': len(targets),
                'events_created': 0,
                'validation_errors': 0,
                'auto_detection_success': 0,
                'type_distribution': {},
                'processing_efficiency': 0.0
            }
            
            try:
                for event_seed in scan.target.seeds:
                    validation_metrics['events_created'] += 1
                    event_type = event_seed.type
                    
                    if event_type not in validation_metrics['type_distribution']:
                        validation_metrics['type_distribution'][event_type] = 0
                    validation_metrics['type_distribution'][event_type] += 1
                    
                    # If we got a valid event type, auto-detection succeeded
                    if event_type and event_type != 'UNKNOWN':
                        validation_metrics['auto_detection_success'] += 1
                        
            except Exception as e:
                validation_metrics['validation_errors'] += 1
            
            # Calculate efficiency ratio
            if validation_metrics['targets_input'] > 0:
                validation_metrics['processing_efficiency'] = (
                    validation_metrics['events_created'] / validation_metrics['targets_input']
                )
            
            return validation_metrics
        
        result = benchmark(validate_large_batch)
        assert result['events_created'] == result['targets_input']  # Should process ALL targets successfully
        assert result['processing_efficiency'] == 1.0  # 100% success rate
        assert len(result['type_distribution']) >= 5  # Should detect multiple event types 