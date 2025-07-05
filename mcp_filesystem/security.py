"""Security module for MCP filesystem server.

This module handles path validation, normalization, and security checks
to ensure that all file operations are restricted to allowed directories.
"""

import platform
import re
import urllib.parse
from pathlib import Path
from typing import List, Optional, Set, Tuple, Union

import anyio
from mcp.server.fastmcp.utilities.logging import get_logger

logger = get_logger(__name__)


class PathValidator:
    """Security class for validating and normalizing file paths."""

    def __init__(self, allowed_dirs: List[Union[str, Path]]):
        """Initialize with a list of allowed directories.

        Args:
            allowed_dirs: List of directories that are allowed for file operations.
                          Paths are normalized to absolute paths.
        """
        self.allowed_dirs: Set[str] = set()

        # Normalize and validate allowed directories
        for directory in allowed_dirs:
            try:
                # Convert to Path object and resolve to absolute path
                abs_path = Path(directory).expanduser().resolve()

                # Check if it's actually a directory
                if not abs_path.is_dir():
                    logger.warning(
                        f"Allowed path is not a directory: {abs_path}",
                        extra={"path": str(abs_path)},
                    )
                    continue

                # Add to allowed set in normalized form
                self.allowed_dirs.add(self._normalize_case(str(abs_path)))
                logger.debug(f"Added allowed directory: {abs_path}")

            except (PermissionError, FileNotFoundError) as e:
                logger.error(
                    f"Error accessing allowed directory {directory}: {e}",
                    extra={"error": str(e), "path": str(directory)},
                )

        if not self.allowed_dirs:
            logger.warning("No valid allowed directories provided!")

    def _normalize_case(self, path: str) -> str:
        """Normalize path case based on platform.

        On Windows, convert to lowercase for case-insensitive comparison.
        On other platforms, keep the original case.

        Args:
            path: Path to normalize

        Returns:
            Normalized path
        """
        if platform.system() == "Windows":
            return path.lower()
        return path

    def _decode_path_safely(self, requested_path: str) -> str:
        """Safely decode URL-encoded paths to prevent encoding bypass attacks.
        
        Args:
            requested_path: Raw path that may contain URL encoding
            
        Returns:
            Decoded path
        """
        try:
            # Decode URL encoding (e.g., %2e%2e%2f -> ../)
            decoded = urllib.parse.unquote(requested_path)
            
            # Additional decoding for double-encoded attempts
            if '%' in decoded:
                decoded = urllib.parse.unquote(decoded)
                
            return decoded
        except Exception:
            # If decoding fails, return original path
            return requested_path
    
    async def _validate_path_security(self, requested_path: str) -> bool:
        """Pre-validation security checks to prevent path traversal attacks.
        
        Args:
            requested_path: Raw user input path to validate
            
        Returns:
            True if path passes security checks, False otherwise
        """
        # SECURITY FIX: Decode path before validation to prevent encoding bypass
        decoded_path = self._decode_path_safely(requested_path)
        
        # Block null bytes (can bypass security checks in some filesystems)
        if '\x00' in requested_path or '\x00' in decoded_path:
            logger.warning(f"Path contains null byte: {requested_path}")
            return False
            
        # Block obvious traversal attempts before path resolution (check both original and decoded)
        if '..' in requested_path or '..' in decoded_path:
            logger.warning(f"Path traversal attempt detected: {requested_path} (decoded: {decoded_path})")
            return False
            
        # Block suspicious patterns (check both original and decoded paths)
        suspicious_patterns = [
            '/../',
            '/./',
            '\\..\\',
            '\\',
            '//',
            '\\/',
            # Additional encoded patterns
            '%2e%2e%2f',
            '%2e%2e%5c',
            '..%2f',
            '..%5c',
        ]
        
        for pattern in suspicious_patterns:
            if pattern in requested_path or pattern in decoded_path:
                logger.warning(f"Suspicious path pattern detected: {pattern} in {requested_path} (decoded: {decoded_path})")
                return False
                
        # Limit path length to prevent buffer overflow attacks (check both paths)
        if len(requested_path) > 4096 or len(decoded_path) > 4096:
            logger.warning(f"Path too long: {len(requested_path)} characters (decoded: {len(decoded_path)})")
            return False
            
        # Block absolute paths that don't start with allowed prefixes
        if Path(requested_path).is_absolute():
            allowed = False
            for allowed_dir in self.allowed_dirs:
                clean_allowed = allowed_dir.rstrip('/')
                if requested_path.startswith(clean_allowed):
                    allowed = True
                    break
            if not allowed:
                logger.warning(f"Absolute path outside allowed directories: {requested_path}")
                return False
                
        return True

    async def validate_path(
        self, requested_path: Union[str, Path]
    ) -> Tuple[Path, bool]:
        """Validate if a path is within allowed directories.

        Args:
            requested_path: Path to validate

        Returns:
            Tuple of (resolved_path, is_allowed)

        Raises:
            ValueError: If path is invalid or outside allowed directories
        """
        try:
            # SECURITY: Pre-validation before path resolution to prevent traversal attacks
            if not await self._validate_path_security(str(requested_path)):
                logger.warning(
                    f"Path validation failed security check: {requested_path}",
                    extra={"path": str(requested_path)},
                )
                return Path(requested_path), False

            # Convert to absolute path after security validation
            abs_path = Path(requested_path).expanduser().resolve()
            normalized = self._normalize_case(str(abs_path))

            # Check if path is within allowed directories
            for allowed_dir in self.allowed_dirs:
                if normalized.startswith(allowed_dir):
                    return abs_path, True

            # Handle case where path doesn't exist yet but parent directory does
            if not abs_path.exists():
                parent_path = abs_path.parent
                try:
                    parent_abs = parent_path.resolve()
                    parent_normalized = self._normalize_case(str(parent_abs))

                    for allowed_dir in self.allowed_dirs:
                        if parent_normalized.startswith(allowed_dir):
                            return abs_path, True
                except (FileNotFoundError, PermissionError):
                    pass

            logger.warning(
                f"Access denied - path outside allowed directories: {abs_path}",
                extra={"path": str(abs_path)},
            )
            return abs_path, False

        except (FileNotFoundError, PermissionError) as e:
            logger.error(
                f"Error validating path: {e}",
                extra={"error": str(e), "path": str(requested_path)},
            )
            return Path(requested_path), False

    async def resolve_symlinks(self, path: Path) -> Tuple[Path, bool]:
        """Safely resolve symlinks to ensure target is within allowed directories.

        Args:
            path: Path that might contain symlinks

        Returns:
            Tuple of (resolved_path, is_allowed)
        """
        try:
            # Try to resolve symlinks
            real_path = await anyio.to_thread.run_sync(Path.resolve, path)
            normalized = self._normalize_case(str(real_path))

            # Check if resolved path is within allowed directories
            for allowed_dir in self.allowed_dirs:
                if normalized.startswith(allowed_dir):
                    return real_path, True

            logger.warning(
                f"Access denied - symlink target outside allowed directories: {real_path}",
                extra={"path": str(real_path), "original": str(path)},
            )
            return real_path, False

        except (FileNotFoundError, PermissionError) as e:
            logger.error(
                f"Error resolving symlinks: {e}",
                extra={"error": str(e), "path": str(path)},
            )
            return path, False

    def get_allowed_dirs(self) -> List[str]:
        """Get the list of allowed directories.

        Returns:
            List of allowed directory paths
        """
        return sorted(list(self.allowed_dirs))

    def is_path_allowed(self, path: Union[str, Path]) -> bool:
        """Quick check if a path is within allowed directories.

        Args:
            path: Path to check

        Returns:
            True if path is allowed, False otherwise
        """
        try:
            abs_path = Path(path).expanduser().resolve()
            normalized = self._normalize_case(str(abs_path))

            for allowed_dir in self.allowed_dirs:
                if normalized.startswith(allowed_dir):
                    return True

            return False
        except (FileNotFoundError, PermissionError):
            return False

    async def find_matching_files(
        self,
        root_path: Union[str, Path],
        pattern: str,
        recursive: bool = True,
        exclude_patterns: Optional[List[str]] = None,
    ) -> List[Path]:
        """Find files matching a pattern within allowed directories.

        Args:
            root_path: Starting directory for search
            pattern: Glob pattern to match against filenames
            recursive: Whether to search subdirectories
            exclude_patterns: Optional patterns to exclude

        Returns:
            List of matching file paths

        Raises:
            ValueError: If root_path is outside allowed directories
        """
        abs_path, allowed = await self.validate_path(root_path)
        if not allowed:
            raise ValueError(f"Search path outside allowed directories: {root_path}")

        if not abs_path.is_dir():
            raise ValueError(f"Search path is not a directory: {abs_path}")

        results = []
        exclude_regexes = []

        # Compile exclude patterns if provided
        if exclude_patterns:
            for exclude in exclude_patterns:
                try:
                    exclude_regexes.append(re.compile(exclude))
                except re.error:
                    logger.warning(f"Invalid exclude pattern: {exclude}")

        # Use glob for pattern matching
        glob_pattern = "**/" + pattern if recursive else pattern
        for matched_path in abs_path.glob(glob_pattern):
            # Skip if matched by exclude pattern
            path_str = str(matched_path)
            excluded = False
            for exclude_re in exclude_regexes:
                if exclude_re.search(path_str):
                    excluded = True
                    break

            if not excluded:
                # Verify path is still allowed (e.g., in case of symlinks)
                if self.is_path_allowed(matched_path):
                    results.append(matched_path)

        return results
