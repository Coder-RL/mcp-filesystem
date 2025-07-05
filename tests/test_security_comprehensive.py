"""Comprehensive security tests for MCP Filesystem Server.

This module contains extensive security tests covering all major attack vectors
including path traversal, encoding bypasses, injection attacks, and DoS attempts.
"""

import os
import tempfile
import pytest
import asyncio
from pathlib import Path
from typing import List, Dict, Any
import urllib.parse

from mcp_filesystem.security import PathValidator
from mcp_filesystem.operations import FileOperations
from mcp_filesystem.grep import GrepTools


@pytest.fixture
def security_test_env():
    """Create a comprehensive test environment for security testing."""
    with tempfile.TemporaryDirectory() as temp_dir:
        base_dir = Path(temp_dir)
        
        # Create directory structure
        allowed_dir = base_dir / "allowed"
        restricted_dir = base_dir / "restricted"
        system_dir = base_dir / "system"
        
        allowed_dir.mkdir()
        restricted_dir.mkdir()
        system_dir.mkdir()
        
        # Create test files
        (allowed_dir / "safe.txt").write_text("Safe content")
        (allowed_dir / "config.json").write_text('{"key": "value"}')
        (restricted_dir / "secret.txt").write_text("SECRET_DATA")
        (system_dir / "passwd").write_text("root:x:0:0:root:/root:/bin/bash")
        
        # Create nested structure
        nested = allowed_dir / "nested" / "deep"
        nested.mkdir(parents=True)
        (nested / "file.txt").write_text("Deep file")
        
        # Create symlinks if supported
        try:
            os.symlink(str(restricted_dir / "secret.txt"), str(allowed_dir / "bad_link"))
            os.symlink(str(allowed_dir / "safe.txt"), str(allowed_dir / "good_link"))
            symlinks_supported = True
        except (OSError, AttributeError):
            symlinks_supported = False
        
        yield {
            "base_dir": base_dir,
            "allowed_dir": allowed_dir,
            "restricted_dir": restricted_dir,
            "system_dir": system_dir,
            "nested_dir": nested,
            "symlinks_supported": symlinks_supported
        }


@pytest.mark.asyncio
class TestPathTraversalSecurity:
    """Test path traversal attack prevention."""
    
    async def test_basic_path_traversal_attacks(self, security_test_env):
        """Test basic path traversal attack vectors."""
        env = security_test_env
        validator = PathValidator([str(env["allowed_dir"])])
        
        # Basic traversal patterns
        attack_vectors = [
            "../restricted/secret.txt",
            "../../restricted/secret.txt", 
            "../../../system/passwd",
            "..\\restricted\\secret.txt",
            "..\\..\\..\\system\\passwd",
            "....//....//restricted//secret.txt",
            "nested/../../../restricted/secret.txt",
            "nested/deep/../../../restricted/secret.txt",
        ]
        
        for attack in attack_vectors:
            _, allowed = await validator.validate_path(attack)
            assert not allowed, f"Path traversal should be blocked: {attack}"
    
    async def test_url_encoded_traversal_attacks(self, security_test_env):
        """Test URL-encoded path traversal attacks."""
        env = security_test_env
        validator = PathValidator([str(env["allowed_dir"])])
        
        # URL encoded traversal patterns
        encoded_attacks = [
            "%2e%2e%2frestricted%2fsecret.txt",  # ../restricted/secret.txt
            "%2e%2e%5crestricted%5csecret.txt",  # ..\restricted\secret.txt
            "%2e%2e%2f%2e%2e%2frestricted%2fsecret.txt",  # ../../restricted/secret.txt
            "%252e%252e%252frestricted%252fsecret.txt",  # Double encoded
            "..%2frestricted%2fsecret.txt",  # Mixed encoding
            "..%5crestricted%5csecret.txt",  # Mixed encoding backslash
        ]
        
        for attack in encoded_attacks:
            _, allowed = await validator.validate_path(attack)
            assert not allowed, f"URL encoded traversal should be blocked: {attack}"
    
    async def test_null_byte_injection(self, security_test_env):
        """Test null byte injection attacks."""
        env = security_test_env
        validator = PathValidator([str(env["allowed_dir"])])
        
        # Null byte injection patterns
        null_byte_attacks = [
            "../restricted/secret.txt\x00.txt",
            "safe.txt\x00../restricted/secret.txt",
            "config.json\x00\x00../restricted/secret.txt",
            "%00../restricted/secret.txt",
        ]
        
        for attack in null_byte_attacks:
            _, allowed = await validator.validate_path(attack)
            assert not allowed, f"Null byte injection should be blocked: {attack}"
    
    async def test_unicode_normalization_attacks(self, security_test_env):
        """Test Unicode normalization attacks."""
        env = security_test_env
        validator = PathValidator([str(env["allowed_dir"])])
        
        # Unicode traversal patterns
        unicode_attacks = [
            "\u002e\u002e\u002frestricted\u002fsecret.txt",  # Unicode ../
            "\uff0e\uff0e\uff0frestricted\uff0fsecret.txt",  # Fullwidth ../
            "\u002e\u002e\u005crestricted\u005csecret.txt",  # Unicode ..\
        ]
        
        for attack in unicode_attacks:
            _, allowed = await validator.validate_path(attack)
            assert not allowed, f"Unicode attack should be blocked: {attack}"
    
    async def test_long_path_attacks(self, security_test_env):
        """Test long path DoS attacks."""
        env = security_test_env
        validator = PathValidator([str(env["allowed_dir"])])
        
        # Long path attacks
        long_attacks = [
            "../" * 1000 + "restricted/secret.txt",
            "A" * 5000,
            "nested/" + "subdir/" * 500 + "file.txt",
        ]
        
        for attack in long_attacks:
            _, allowed = await validator.validate_path(attack)
            assert not allowed, f"Long path attack should be blocked: {attack}"
    
    async def test_absolute_path_escapes(self, security_test_env):
        """Test absolute path escape attempts."""
        env = security_test_env
        validator = PathValidator([str(env["allowed_dir"])])
        
        # Absolute path escapes
        absolute_attacks = [
            str(env["restricted_dir"] / "secret.txt"),
            str(env["system_dir"] / "passwd"),
            "/etc/passwd",
            "/var/log/messages",
            "C:\\Windows\\System32\\config\\SAM",
            "\\\\server\\share\\file.txt",
        ]
        
        for attack in absolute_attacks:
            _, allowed = await validator.validate_path(attack)
            assert not allowed, f"Absolute path escape should be blocked: {attack}"


@pytest.mark.asyncio 
class TestSymlinkSecurity:
    """Test symlink security."""
    
    async def test_symlink_traversal_prevention(self, security_test_env):
        """Test that symlinks pointing outside allowed dirs are blocked."""
        env = security_test_env
        if not env["symlinks_supported"]:
            pytest.skip("Symlinks not supported")
        
        validator = PathValidator([str(env["allowed_dir"])])
        
        # Test bad symlink (points outside allowed dir)
        bad_link = env["allowed_dir"] / "bad_link"
        _, allowed = await validator.validate_path(str(bad_link))
        assert not allowed, "Symlink pointing outside allowed dir should be blocked"
        
        # Test good symlink (points within allowed dir)
        good_link = env["allowed_dir"] / "good_link"
        _, allowed = await validator.validate_path(str(good_link))
        assert allowed, "Symlink pointing within allowed dir should be allowed"


@pytest.mark.asyncio
class TestInputValidationSecurity:
    """Test input validation and sanitization."""
    
    async def test_filename_character_restrictions(self, security_test_env):
        """Test filename character validation."""
        env = security_test_env
        validator = PathValidator([str(env["allowed_dir"])])
        
        # Potentially dangerous filename characters
        dangerous_chars = [
            "file<script>.txt",
            "file>output.txt", 
            "file|command.txt",
            "file&command.txt",
            "file;command.txt",
            "file`command`.txt",
            "file$(command).txt",
            "file\ncommand.txt",
            "file\rcommand.txt",
            "file\tcommand.txt",
        ]
        
        # These should be handled gracefully (not crash)
        for filename in dangerous_chars:
            try:
                _, allowed = await validator.validate_path(filename)
                # The result doesn't matter as much as not crashing
            except Exception as e:
                pytest.fail(f"Filename validation crashed on: {filename}, error: {e}")
    
    async def test_encoding_parameter_validation(self, security_test_env):
        """Test encoding parameter validation in file operations."""
        env = security_test_env
        validator = PathValidator([str(env["allowed_dir"])])
        file_ops = FileOperations(validator)
        
        # Test various encoding parameters
        test_file = env["allowed_dir"] / "test_encoding.txt"
        test_file.write_text("Test content", encoding="utf-8")
        
        # Valid encodings should work
        valid_encodings = ["utf-8", "ascii", "latin-1", "utf-16"]
        for encoding in valid_encodings:
            try:
                content = await file_ops.read_file(str(test_file), encoding=encoding)
                assert isinstance(content, str)
            except UnicodeDecodeError:
                # This is acceptable for incompatible encodings
                pass
            except Exception as e:
                pytest.fail(f"Unexpected error with encoding {encoding}: {e}")
        
        # Invalid encodings should be handled gracefully
        invalid_encodings = ["invalid-encoding", "malicious<script>", "utf-8; rm -rf /"]
        for encoding in invalid_encodings:
            try:
                await file_ops.read_file(str(test_file), encoding=encoding)
            except (LookupError, ValueError):
                # Expected for invalid encodings
                pass
            except Exception as e:
                pytest.fail(f"Unexpected error with invalid encoding {encoding}: {e}")


@pytest.mark.asyncio
class TestCommandInjectionSecurity:
    """Test command injection prevention in grep operations."""
    
    async def test_grep_pattern_injection(self, security_test_env):
        """Test grep pattern injection attacks."""
        env = security_test_env
        validator = PathValidator([str(env["allowed_dir"])])
        grep_tools = GrepTools(validator)
        
        # Create test file with content
        test_file = env["allowed_dir"] / "grep_test.txt"
        test_file.write_text("line1\ntest content\nline3\n")
        
        # Malicious grep patterns
        malicious_patterns = [
            "; rm -rf /",
            "| cat /etc/passwd",
            "&& echo 'hacked'",
            "$(whoami)",
            "`id`",
            "\n; malicious_command",
            "pattern'; DROP TABLE users; --",
        ]
        
        for pattern in malicious_patterns:
            try:
                # This should not execute any commands
                results = await grep_tools.search_in_file(
                    str(test_file), 
                    pattern,
                    context_lines=1
                )
                # The search might not find anything, but it shouldn't crash or execute commands
                assert isinstance(results, dict)
            except Exception as e:
                # Should handle malicious patterns gracefully
                assert "command" not in str(e).lower(), f"Possible command injection: {e}"


if __name__ == "__main__":
    pytest.main(["-xvs", __file__])
