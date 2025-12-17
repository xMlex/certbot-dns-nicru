"""Tests for requirements.txt validation"""

import os
import re
import unittest
from pathlib import Path


class RequirementsValidationTest(unittest.TestCase):
    """Test suite for validating requirements.txt structure and content."""

    def setUp(self):
        """Set up test fixtures."""
        self.repo_root = Path(__file__).parent.parent
        self.requirements_file = self.repo_root / "requirements.txt"
        self.requirements_content = self._read_requirements()

    def _read_requirements(self):
        """Read and parse requirements.txt file."""
        with open(self.requirements_file, 'r') as f:
            lines = f.readlines()
        return [line.strip() for line in lines if line.strip()]

    def _parse_requirement(self, line):
        """Parse a requirement line into package name and version spec."""
        # Remove inline comments
        if '#' in line:
            line = line.split('#')[0].strip()
        
        # Match package name and version specification
        match = re.match(r'^([a-zA-Z0-9_-]+)([><=!~]+.*)?$', line)
        if match:
            return match.group(1), match.group(2) or ''
        return None, None

    def test_requirements_file_exists(self):
        """Test that requirements.txt file exists."""
        self.assertTrue(
            self.requirements_file.exists(),
            "requirements.txt file should exist"
        )

    def test_requirements_file_not_empty(self):
        """Test that requirements.txt is not empty."""
        self.assertGreater(
            len(self.requirements_content),
            0,
            "requirements.txt should not be empty"
        )

    def test_core_dependencies_present(self):
        """Test that all core dependencies are present."""
        required_packages = [
            'certbot',
            'setuptools',
            'requests',
            'zope.interface',
            'sh-nic-api',
        ]
        
        package_names = []
        for line in self.requirements_content:
            if line and not line.startswith('#'):
                pkg_name, _ = self._parse_requirement(line)
                if pkg_name:
                    package_names.append(pkg_name)
        
        for required_pkg in required_packages:
            self.assertIn(
                required_pkg,
                package_names,
                f"Required package '{required_pkg}' should be in requirements.txt"
            )

    def test_certbot_version_constraint(self):
        """Test that certbot has proper version constraint."""
        certbot_lines = [
            line for line in self.requirements_content
            if line.startswith('certbot') and not line.startswith('certbot_')
        ]
        
        self.assertEqual(
            len(certbot_lines),
            1,
            "Should have exactly one certbot requirement"
        )
        
        self.assertIn(
            '>=',
            certbot_lines[0],
            "certbot should have a minimum version constraint"
        )
        
        # Extract version
        match = re.search(r'>=(\d+\.\d+\.\d+)', certbot_lines[0])
        self.assertIsNotNone(match, "certbot version should be in X.Y.Z format")
        
        version_parts = match.group(1).split('.')
        major_version = int(version_parts[0])
        self.assertGreaterEqual(
            major_version,
            2,
            "certbot version should be at least 2.x"
        )

    def test_sh_nic_api_version_constraint(self):
        """Test that sh-nic-api has proper version constraint."""
        sh_nic_lines = [
            line for line in self.requirements_content
            if line.startswith('sh-nic-api')
        ]
        
        self.assertEqual(
            len(sh_nic_lines),
            1,
            "Should have exactly one sh-nic-api requirement"
        )
        
        self.assertIn(
            '>=',
            sh_nic_lines[0],
            "sh-nic-api should have a minimum version constraint"
        )

    def test_urllib3_security_pin_present(self):
        """Test that urllib3 security pin is present."""
        urllib3_lines = [
            line for line in self.requirements_content
            if 'urllib3' in line.lower()
        ]
        
        self.assertGreater(
            len(urllib3_lines),
            0,
            "urllib3 security pin should be present"
        )
        
        urllib3_line = urllib3_lines[0]
        self.assertIn(
            '>=',
            urllib3_line,
            "urllib3 should have a minimum version constraint"
        )
        
        # Verify it's pinned to address vulnerability
        self.assertIn(
            '#',
            urllib3_line,
            "urllib3 pin should have a comment explaining the security fix"
        )
        
        comment = urllib3_line.split('#')[1].lower()
        self.assertTrue(
            'vulnerability' in comment or 'snyk' in comment or 'security' in comment,
            "urllib3 comment should mention security/vulnerability"
        )

    def test_urllib3_minimum_version(self):
        """Test that urllib3 is pinned to at least 2.6.0 for security."""
        urllib3_lines = [
            line for line in self.requirements_content
            if line.startswith('urllib3')
        ]
        
        self.assertGreater(
            len(urllib3_lines),
            0,
            "urllib3 should be in requirements"
        )
        
        # Extract version
        match = re.search(r'>=(\d+\.\d+\.\d+)', urllib3_lines[0])
        self.assertIsNotNone(match, "urllib3 should have version in X.Y.Z format")
        
        version_str = match.group(1)
        version_parts = [int(x) for x in version_str.split('.')]
        
        # Check it's at least 2.6.0
        self.assertGreaterEqual(version_parts[0], 2, "urllib3 major version should be at least 2")
        if version_parts[0] == 2:
            self.assertGreaterEqual(version_parts[1], 6, "urllib3 minor version should be at least 6")

    def test_no_duplicate_packages(self):
        """Test that there are no duplicate package declarations."""
        package_names = []
        
        for line in self.requirements_content:
            if line and not line.startswith('#'):
                pkg_name, _ = self._parse_requirement(line)
                if pkg_name:
                    package_names.append(pkg_name.lower())
        
        duplicates = [
            pkg for pkg in set(package_names)
            if package_names.count(pkg) > 1
        ]
        
        self.assertEqual(
            len(duplicates),
            0,
            f"No duplicate packages should exist. Found: {duplicates}"
        )

    def test_valid_version_specifiers(self):
        """Test that all version specifiers are valid."""
        valid_operators = ['==', '>=', '<=', '>', '<', '!=', '~=']
        
        for line in self.requirements_content:
            if line and not line.startswith('#'):
                pkg_name, version_spec = self._parse_requirement(line)
                
                if version_spec:
                    # Check if it starts with a valid operator
                    has_valid_operator = any(
                        version_spec.startswith(op) for op in valid_operators
                    )
                    self.assertTrue(
                        has_valid_operator,
                        f"Package '{pkg_name}' has invalid version specifier: {version_spec}"
                    )

    def test_no_conflicting_versions(self):
        """Test that there are no obvious version conflicts."""
        # Check for packages that have both >= and <= constraints
        # This is a basic check; real conflict detection is complex
        package_constraints = {}
        
        for line in self.requirements_content:
            if line and not line.startswith('#'):
                pkg_name, version_spec = self._parse_requirement(line)
                if pkg_name and version_spec:
                    if pkg_name not in package_constraints:
                        package_constraints[pkg_name] = []
                    package_constraints[pkg_name].append(version_spec)
        
        # For now, just ensure we don't have multiple constraints on same package
        # (except in complex scenarios)
        for pkg, constraints in package_constraints.items():
            self.assertEqual(
                len(constraints),
                1,
                f"Package '{pkg}' should not have multiple version constraints"
            )

    def test_testing_dependencies_present(self):
        """Test that testing dependencies are present."""
        testing_packages = ['mock', 'requests-mock']
        
        package_names = []
        for line in self.requirements_content:
            if line and not line.startswith('#'):
                pkg_name, _ = self._parse_requirement(line)
                if pkg_name:
                    package_names.append(pkg_name)
        
        for test_pkg in testing_packages:
            self.assertIn(
                test_pkg,
                package_names,
                f"Testing package '{test_pkg}' should be in requirements.txt"
            )

    def test_build_dependency_present(self):
        """Test that build dependency is present."""
        package_names = []
        for line in self.requirements_content:
            if line and not line.startswith('#'):
                pkg_name, _ = self._parse_requirement(line)
                if pkg_name:
                    package_names.append(pkg_name)
        
        self.assertIn(
            'build',
            package_names,
            "Build package should be in requirements.txt"
        )

    def test_requirements_format_consistency(self):
        """Test that requirements follow consistent formatting."""
        for line in self.requirements_content:
            if line and not line.startswith('#'):
                # Should not have trailing whitespace (already stripped)
                pkg_name, version_spec = self._parse_requirement(line)
                
                if pkg_name:
                    # Package names should be lowercase or have hyphens
                    self.assertTrue(
                        pkg_name.replace('-', '').replace('_', '').isalnum(),
                        f"Package name '{pkg_name}' should contain only alphanumeric characters, hyphens, or underscores"
                    )

    def test_inline_comments_properly_formatted(self):
        """Test that inline comments are properly formatted with spacing."""
        for line_num, line in enumerate(self.requirements_content, 1):
            if '#' in line and not line.startswith('#'):
                # There should be a space before the # for inline comments
                parts = line.split('#')
                self.assertTrue(
                    parts[0].endswith(' '),
                    f"Line {line_num}: Inline comments should have a space before #"
                )

    def test_security_pins_documented(self):
        """Test that security-related pins have documentation."""
        security_keywords = ['vulnerability', 'security', 'cve', 'snyk']
        
        for line in self.requirements_content:
            if '#' in line and not line.startswith('#'):
                comment = line.split('#')[1].lower()
                
                # If it mentions security, ensure the package has version constraint
                if any(keyword in comment for keyword in security_keywords):
                    pkg_part = line.split('#')[0].strip()
                    self.assertRegex(
                        pkg_part,
                        r'[><=!~]',
                        f"Security-related pin should have version constraint: {line}"
                    )


class RequirementsIntegrationTest(unittest.TestCase):
    """Integration tests for requirements.txt with setup.cfg."""

    def setUp(self):
        """Set up test fixtures."""
        self.repo_root = Path(__file__).parent.parent
        self.requirements_file = self.repo_root / "requirements.txt"
        self.setup_cfg_file = self.repo_root / "setup.cfg"

    def _parse_requirement_name(self, line):
        """Extract package name from requirement line."""
        if '#' in line:
            line = line.split('#')[0].strip()
        match = re.match(r'^([a-zA-Z0-9_-]+)', line)
        return match.group(1) if match else None

    def test_setup_cfg_dependencies_in_requirements(self):
        """Test that install_requires from setup.cfg are in requirements.txt."""
        # Read setup.cfg install_requires
        with open(self.setup_cfg_file, 'r') as f:
            content = f.read()
        
        # Extract install_requires section
        match = re.search(r'install_requires\s*=\s*\n((?:\s+.+\n)*)', content)
        if not match:
            self.fail("Could not find install_requires in setup.cfg")
        
        install_requires = [
            line.strip() for line in match.group(1).strip().split('\n')
            if line.strip()
        ]
        
        # Read requirements.txt
        with open(self.requirements_file, 'r') as f:
            requirements = [
                line.strip() for line in f.readlines()
                if line.strip() and not line.strip().startswith('#')
            ]
        
        setup_packages = [self._parse_requirement_name(req) for req in install_requires]
        req_packages = [self._parse_requirement_name(req) for req in requirements]
        
        for pkg in setup_packages:
            if pkg:
                self.assertIn(
                    pkg,
                    req_packages,
                    f"Package '{pkg}' from setup.cfg should be in requirements.txt"
                )


if __name__ == '__main__':
    unittest.main()