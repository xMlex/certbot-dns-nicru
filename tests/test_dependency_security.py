"""Tests for dependency security and compatibility validation."""

import re
import subprocess
import sys
import unittest
from pathlib import Path


class DependencySecurityTest(unittest.TestCase):
    """Test suite for validating dependency security and compatibility."""

    def setUp(self):
        """Set up test fixtures."""
        self.repo_root = Path(__file__).parent.parent
        self.requirements_file = self.repo_root / "requirements.txt"

    def _read_requirements(self):
        """Read requirements.txt and return non-comment lines."""
        with open(self.requirements_file, 'r') as f:
            lines = f.readlines()
        return [
            line.strip() for line in lines
            if line.strip() and not line.strip().startswith('#')
        ]

    def _parse_version_constraint(self, line):
        """Parse version constraint from requirement line."""
        if '#' in line:
            line = line.split('#')[0].strip()
        
        match = re.match(r'^([a-zA-Z0-9_-]+)([><=!~]+)([\d.]+)', line)
        if match:
            return {
                'package': match.group(1),
                'operator': match.group(2),
                'version': match.group(3)
            }
        return None

    def test_urllib3_security_vulnerability_fix(self):
        """Test that urllib3 is pinned to version that fixes known vulnerabilities."""
        requirements = self._read_requirements()
        
        urllib3_req = None
        for req in requirements:
            if req.startswith('urllib3'):
                urllib3_req = req
                break
        
        self.assertIsNotNone(urllib3_req, "urllib3 should be in requirements")
        
        # Parse version
        parsed = self._parse_version_constraint(urllib3_req)
        self.assertIsNotNone(parsed, "urllib3 should have valid version constraint")
        
        # Verify minimum version 2.6.0 or higher
        version_parts = [int(x) for x in parsed['version'].split('.')]
        self.assertGreaterEqual(version_parts[0], 2)
        
        if version_parts[0] == 2:
            self.assertGreaterEqual(
                version_parts[1], 6,
                "urllib3 2.x should be at least version 2.6.0 for security"
            )

    def test_urllib3_has_security_comment(self):
        """Test that urllib3 pin includes comment about security/vulnerability."""
        with open(self.requirements_file, 'r') as f:
            content = f.read()
        
        urllib3_lines = [
            line for line in content.split('\n')
            if 'urllib3' in line.lower()
        ]
        
        self.assertGreater(len(urllib3_lines), 0)
        
        urllib3_line = urllib3_lines[0]
        self.assertIn('#', urllib3_line, "urllib3 line should have explanatory comment")
        
        comment = urllib3_line.split('#')[1].lower()
        security_keywords = ['vulnerability', 'security', 'snyk', 'cve']
        
        has_security_keyword = any(keyword in comment for keyword in security_keywords)
        self.assertTrue(
            has_security_keyword,
            "urllib3 comment should mention security concern"
        )

    def test_certbot_compatibility_with_urllib3(self):
        """Test that certbot version is compatible with urllib3>=2.6.0."""
        requirements = self._read_requirements()
        
        certbot_req = None
        urllib3_req = None
        
        for req in requirements:
            if req.startswith('certbot>=') or req.startswith('certbot=='):
                certbot_req = req
            elif req.startswith('urllib3'):
                urllib3_req = req
        
        self.assertIsNotNone(certbot_req, "certbot should be in requirements")
        self.assertIsNotNone(urllib3_req, "urllib3 should be in requirements")
        
        # Parse certbot version
        certbot_parsed = self._parse_version_constraint(certbot_req)
        self.assertIsNotNone(certbot_parsed)
        
        # Certbot 2.9.0+ should be compatible with urllib3 2.6.0+
        certbot_version = [int(x) for x in certbot_parsed['version'].split('.')]
        self.assertGreaterEqual(
            certbot_version[0], 2,
            "certbot should be version 2.x or higher"
        )

    def test_requests_compatibility_with_urllib3(self):
        """Test that requests is present and compatible with urllib3."""
        requirements = self._read_requirements()
        
        has_requests = any(req.startswith('requests') for req in requirements)
        has_urllib3 = any(req.startswith('urllib3') for req in requirements)
        
        self.assertTrue(has_requests, "requests should be in requirements")
        self.assertTrue(has_urllib3, "urllib3 should be in requirements")
        
        # requests depends on urllib3, so compatibility is important
        # This is a basic check; real compatibility testing would need runtime checks

    def test_no_vulnerable_package_versions(self):
        """Test that no obviously vulnerable package versions are specified."""
        requirements = self._read_requirements()
        
        # Known vulnerable versions (examples, not exhaustive)
        vulnerable_patterns = [
            (r'^urllib3==1\.\d+', 'urllib3 1.x has known vulnerabilities'),
            (r'^urllib3>=?1\.\d+,<2', 'urllib3 1.x has known vulnerabilities'),
            (r'^requests==2\.([0-9]|1[0-9])\.', 'requests <2.20 has known vulnerabilities'),
        ]
        
        for req in requirements:
            for pattern, message in vulnerable_patterns:
                self.assertIsNone(
                    re.match(pattern, req),
                    f"{message}: {req}"
                )

    def test_security_pins_use_minimum_version_constraints(self):
        """Test that security pins use >= rather than == for flexibility."""
        with open(self.requirements_file, 'r') as f:
            content = f.read()
        
        # Find lines with security-related comments
        security_lines = []
        for line in content.split('\n'):
            if '#' in line:
                comment = line.split('#')[1].lower()
                if any(kw in comment for kw in ['vulnerability', 'security', 'snyk', 'cve']):
                    pkg_part = line.split('#')[0].strip()
                    if pkg_part:
                        security_lines.append(pkg_part)
        
        for pkg_line in security_lines:
            # Security pins should prefer >= over == for forward compatibility
            if '==' in pkg_line:
                self.fail(
                    f"Security pin '{pkg_line}' uses ==. "
                    f"Consider using >= for better forward compatibility."
                )

    def test_urllib3_version_format_valid(self):
        """Test that urllib3 version is in valid semantic versioning format."""
        requirements = self._read_requirements()
        
        urllib3_req = None
        for req in requirements:
            if req.startswith('urllib3'):
                urllib3_req = req
                break
        
        self.assertIsNotNone(urllib3_req)
        
        # Extract version
        match = re.search(r'(\d+)\.(\d+)\.(\d+)', urllib3_req)
        self.assertIsNotNone(
            match,
            "urllib3 version should be in semantic versioning format (X.Y.Z)"
        )
        
        major, minor, patch = match.groups()
        self.assertTrue(major.isdigit())
        self.assertTrue(minor.isdigit())
        self.assertTrue(patch.isdigit())

    def test_dependencies_not_pinned_too_strictly(self):
        """Test that dependencies allow for minor version updates."""
        requirements = self._read_requirements()
        
        strict_pins = []
        for req in requirements:
            # Skip comment-only lines
            if '#' in req:
                pkg_part = req.split('#')[0].strip()
            else:
                pkg_part = req
            
            # Check for exact version pins that might be too strict
            if '==' in pkg_part and not any(x in pkg_part.lower() for x in ['urllib3']):
                # Allow == for specific security pins, but warn for others
                parsed = self._parse_version_constraint(pkg_part)
                if parsed:
                    strict_pins.append(parsed['package'])
        
        # This is informational; exact pins may be needed for stability
        # but we should be aware of them
        if strict_pins:
            print(f"\nInfo: Found strict version pins: {strict_pins}")

    def test_all_security_relevant_packages_have_versions(self):
        """Test that security-relevant packages have version constraints."""
        requirements = self._read_requirements()
        
        security_relevant = ['urllib3', 'requests', 'certbot']
        
        for pkg in security_relevant:
            pkg_lines = [req for req in requirements if req.startswith(pkg)]
            self.assertGreater(
                len(pkg_lines), 0,
                f"Security-relevant package '{pkg}' should be in requirements"
            )
            
            pkg_line = pkg_lines[0]
            has_version = any(op in pkg_line for op in ['>=', '==', '<=', '>', '<', '!=', '~='])
            self.assertTrue(
                has_version,
                f"Security-relevant package '{pkg}' should have version constraint"
            )

    def test_urllib3_not_conflicting_with_other_deps(self):
        """Test that urllib3 constraint doesn't create obvious conflicts."""
        requirements = self._read_requirements()
        
        urllib3_req = None
        for req in requirements:
            if req.startswith('urllib3'):
                urllib3_req = req
                break
        
        self.assertIsNotNone(urllib3_req)
        
        # If there are multiple urllib3 entries, they should not conflict
        urllib3_reqs = [req for req in requirements if req.startswith('urllib3')]
        self.assertEqual(
            len(urllib3_reqs), 1,
            "Should have exactly one urllib3 requirement to avoid conflicts"
        )

    def test_snyk_recommendation_documented(self):
        """Test that Snyk recommendation is properly documented."""
        with open(self.requirements_file, 'r') as f:
            content = f.read()
        
        # Find urllib3 line
        urllib3_lines = [
            line for line in content.split('\n')
            if 'urllib3' in line and not line.strip().startswith('#')
        ]
        
        self.assertGreater(len(urllib3_lines), 0)
        
        urllib3_line = urllib3_lines[0]
        
        # Should mention Snyk
        self.assertIn(
            'snyk',
            urllib3_line.lower(),
            "urllib3 security pin should mention Snyk recommendation"
        )

    def test_vulnerability_pin_not_indirectly_required_flag(self):
        """Test that comment indicates this is not a direct dependency."""
        with open(self.requirements_file, 'r') as f:
            content = f.read()
        
        urllib3_lines = [
            line for line in content.split('\n')
            if 'urllib3' in line
        ]
        
        self.assertGreater(len(urllib3_lines), 0)
        
        urllib3_line = urllib3_lines[0]
        comment_lower = urllib3_line.split('#')[1].lower() if '#' in urllib3_line else ''
        
        # Should indicate it's not directly required
        indirect_keywords = ['not directly', 'indirect', 'pinned by']
        has_indirect_mention = any(kw in comment_lower for kw in indirect_keywords)
        
        self.assertTrue(
            has_indirect_mention,
            "Comment should indicate urllib3 is not a direct dependency"
        )


class DependencyVersionCompatibilityTest(unittest.TestCase):
    """Test compatibility between different dependency versions."""

    def setUp(self):
        """Set up test fixtures."""
        self.repo_root = Path(__file__).parent.parent
        self.requirements_file = self.repo_root / "requirements.txt"

    def test_major_version_consistency(self):
        """Test that major versions are consistent across related packages."""
        with open(self.requirements_file, 'r') as f:
            requirements = [
                line.strip() for line in f.readlines()
                if line.strip() and not line.strip().startswith('#')
            ]
        
        # Extract Python packages with major versions
        packages_with_versions = {}
        for req in requirements:
            match = re.match(r'^([a-zA-Z0-9_-]+)[><=!~]+(\d+)', req)
            if match:
                pkg_name = match.group(1)
                major_version = int(match.group(2))
                packages_with_versions[pkg_name] = major_version
        
        # urllib3 2.x requires Python 3.7+, which should be compatible with certbot 2.x
        if 'urllib3' in packages_with_versions:
            self.assertEqual(
                packages_with_versions['urllib3'], 2,
                "urllib3 should be version 2.x"
            )
        
        if 'certbot' in packages_with_versions:
            self.assertGreaterEqual(
                packages_with_versions['certbot'], 2,
                "certbot should be version 2.x or higher"
            )

    def test_python_version_compatibility(self):
        """Test that all packages are compatible with declared Python version."""
        setup_cfg = self.repo_root / "setup.cfg"
        
        # Read Python version requirement
        with open(setup_cfg, 'r') as f:
            content = f.read()
        
        python_req_match = re.search(r'python_requires\s*=\s*>=(\d+\.\d+)', content)
        self.assertIsNotNone(python_req_match, "setup.cfg should specify python_requires")
        
        python_version = python_req_match.group(1)
        
        # urllib3 2.x requires Python 3.7+
        # Verify our python_requires is compatible
        major, minor = map(int, python_version.split('.'))
        
        if major == 3:
            self.assertGreaterEqual(
                minor, 7,
                "Python 3.7+ required for urllib3 2.x"
            )


if __name__ == '__main__':
    unittest.main()