"""Enhanced grep functionality for MCP filesystem server.

This module provides powerful grep-like searching capabilities,
with ripgrep integration when available and a Python fallback.
"""

import json
import re
import subprocess
import asyncio
import signal
from functools import partial  # Added for mypy compatibility with run_sync
from pathlib import Path
from typing import Dict, List, Optional, Union, Callable, Any

import anyio
from mcp.server.fastmcp.utilities.logging import get_logger

from .security import PathValidator

logger = get_logger(__name__)

# SECURITY: Regex execution timeout in seconds
REGEX_TIMEOUT_SECONDS = 5
# SECURITY: Maximum regex pattern length to prevent ReDoS
MAX_REGEX_LENGTH = 1000


class GrepMatch:
    """Represents a single grep match."""

    def __init__(
        self,
        file_path: str,
        line_number: int,
        line_content: str,
        match_start: int,
        match_end: int,
        context_before: Optional[List[str]] = None,
        context_after: Optional[List[str]] = None,
    ):
        """Initialize a grep match.

        Args:
            file_path: Path to the file containing the match
            line_number: Line number of the match (1-based)
            line_content: Content of the matching line
            match_start: Start index of the match within the line
            match_end: End index of the match within the line
            context_before: Lines before the match
            context_after: Lines after the match
        """
        self.file_path = file_path
        self.line_number = line_number
        self.line_content = line_content
        self.match_start = match_start
        self.match_end = match_end
        self.context_before = context_before or []
        self.context_after = context_after or []

    def to_dict(self) -> Dict:
        """Convert to dictionary representation.

        Returns:
            Dictionary with match information
        """
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "line_content": self.line_content,
            "match_start": self.match_start,
            "match_end": self.match_end,
            "context_before": self.context_before,
            "context_after": self.context_after,
        }

    def __str__(self) -> str:
        """Get string representation.

        Returns:
            Formatted string with match information
        """
        return f"{self.file_path}:{self.line_number}: {self.line_content}"


class GrepResult:
    """Result of a grep operation."""

    def __init__(self):
        """Initialize an empty grep result."""
        self.matches: List[GrepMatch] = []
        self.file_counts: Dict[str, int] = {}
        self.total_matches = 0
        self.files_searched = 0
        self.errors: Dict[str, str] = {}

    def add_match(self, match: GrepMatch) -> None:
        """Add a match to the results.

        Args:
            match: GrepMatch to add
        """
        self.matches.append(match)
        self.total_matches += 1

        # Update file counts
        if match.file_path in self.file_counts:
            self.file_counts[match.file_path] += 1
        else:
            self.file_counts[match.file_path] = 1

    def add_error(self, file_path: str, error: str) -> None:
        """Add an error for a file.

        Args:
            file_path: Path to the file with error
            error: Error message
        """
        self.errors[file_path] = error

    def to_dict(self) -> Dict:
        """Convert to dictionary representation.

        Returns:
            Dictionary with search results
        """
        return {
            "matches": [match.to_dict() for match in self.matches],
            "file_counts": self.file_counts,
            "total_matches": self.total_matches,
            "files_searched": self.files_searched,
            "errors": self.errors,
        }


class GrepTools:
    """Provides grep-like functionality for searching text in files."""

    def __init__(self, validator: PathValidator):
        """Initialize with a path validator.

        Args:
            validator: PathValidator for security checks
        """
        self.validator = validator
        self._ripgrep_available = self._check_ripgrep()

    def _check_ripgrep(self) -> bool:
        """Check if ripgrep is available on the system.

        Returns:
            True if ripgrep is available, False otherwise
        """
        try:
            subprocess.run(
                ["rg", "--version"], capture_output=True, check=True, timeout=5
            )
            return True
        except (subprocess.SubprocessError, FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _sanitize_ripgrep_pattern(self, pattern: str) -> str:
        """Sanitize pattern for safe use with ripgrep to prevent command injection.
        
        Args:
            pattern: User input pattern to sanitize
            
        Returns:
            Sanitized pattern safe for use with ripgrep
        """
        # Block dangerous characters that could be used for command injection
        dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', '\n', '\r']
        
        for char in dangerous_chars:
            if char in pattern:
                raise ValueError(f"Pattern contains dangerous character: {char}")
        
        # Limit pattern length to prevent buffer overflow
        if len(pattern) > 1000:
            raise ValueError("Pattern too long (max 1000 characters)")
            
        # Additional validation for shell metacharacters
        if any(metachar in pattern for metachar in ['&&', '||', '>>', '<<']):
            raise ValueError("Pattern contains shell metacharacters")
            
        return pattern

    async def grep_files(
        self,
        path: Union[str, Path],
        pattern: str,
        is_regex: bool = False,
        case_sensitive: bool = True,
        whole_word: bool = False,
        include_patterns: Optional[List[str]] = None,
        exclude_patterns: Optional[List[str]] = None,
        context_lines: int = 0,
        context_before: int = 0,
        context_after: int = 0,
        max_results: int = 1000,
        max_file_size_mb: float = 50.0,
        recursive: bool = True,
        max_depth: Optional[int] = None,
        count_only: bool = False,
        results_offset: int = 0,
        results_limit: Optional[int] = None,
        show_progress: bool = False,
        progress_callback: Optional[Callable[[int, int], Any]] = None,
    ) -> GrepResult:
        """Search for pattern in files, similar to grep.

        Args:
            path: Starting directory or file path
            pattern: Text or regex pattern to search for
            is_regex: Whether to treat pattern as regex
            case_sensitive: Whether search is case sensitive
            whole_word: Match whole words only
            include_patterns: Only include files matching these patterns
            exclude_patterns: Exclude files matching these patterns
            context_lines: Number of lines to show before AND after matches (like grep -C)
            context_before: Number of lines to show BEFORE matches (like grep -B)
            context_after: Number of lines to show AFTER matches (like grep -A)
            max_results: Maximum total matches to find during search
            max_file_size_mb: Skip files larger than this size
            recursive: Whether to search subdirectories
            max_depth: Maximum directory depth to recurse
            count_only: Only show match counts per file
            results_offset: Start at Nth match (0-based, for pagination)
            results_limit: Return at most this many matches (for pagination)
            show_progress: Whether to show progress
            progress_callback: Optional callback for progress updates

        Returns:
            GrepResult object with matches and statistics

        Raises:
            ValueError: If path is outside allowed directories
        """
        abs_path, allowed = await self.validator.validate_path(path)
        if not allowed:
            raise ValueError(f"Path outside allowed directories: {path}")

        if self._ripgrep_available and not count_only:
            # Use ripgrep for better performance
            try:
                return await self._grep_with_ripgrep(
                    abs_path,
                    pattern,
                    is_regex,
                    case_sensitive,
                    whole_word,
                    include_patterns,
                    exclude_patterns,
                    context_lines,
                    context_before,
                    context_after,
                    max_results,
                    recursive,
                    max_depth,
                    results_offset,
                    results_limit,
                )
            except Exception as e:
                logger.warning(f"Ripgrep failed, falling back to Python: {e}")

        # Fall back to Python implementation
        return await self._grep_with_python(
            abs_path,
            pattern,
            is_regex,
            case_sensitive,
            whole_word,
            include_patterns,
            exclude_patterns,
            context_lines,
            context_before,
            context_after,
            max_results,
            max_file_size_mb,
            recursive,
            max_depth,
            count_only,
            show_progress,
            progress_callback,
            results_offset,
            results_limit,
        )

    async def _grep_with_ripgrep(
        self,
        path: Path,
        pattern: str,
        is_regex: bool,
        case_sensitive: bool,
        whole_word: bool,
        include_patterns: Optional[List[str]],
        exclude_patterns: Optional[List[str]],
        context_lines: int,
        context_before: int,
        context_after: int,
        max_results: int,
        recursive: bool,
        max_depth: Optional[int],
        results_offset: int = 0,
        results_limit: Optional[int] = None,
    ) -> GrepResult:
        """Use ripgrep for searching.

        Args:
            See grep_files for parameter descriptions

        Returns:
            GrepResult with matches

        Raises:
            RuntimeError: If ripgrep execution fails
        """
        # Build ripgrep command
        cmd = ["rg", "--json"]

        # Case sensitivity
        if not case_sensitive:
            cmd.append("--ignore-case")

        # Regex mode
        if not is_regex:
            cmd.append("--fixed-strings")

        # Word boundary
        if whole_word:
            cmd.append("--word-regexp")

        # Context lines
        if context_lines > 0:
            cmd.extend(["--context", str(context_lines)])
        else:
            if context_before > 0:
                cmd.extend(["--before-context", str(context_before)])
            if context_after > 0:
                cmd.extend(["--after-context", str(context_after)])

        # Recursion
        if not recursive:
            cmd.append("--max-depth=1")
        elif max_depth is not None:
            cmd.extend(["--max-depth", str(max_depth)])

        # Result limits
        if max_results > 0:
            cmd.extend(["--max-count", str(max_results)])

        # Include patterns
        if include_patterns:
            for pattern_glob in include_patterns:
                cmd.extend(["--glob", pattern_glob])

        # Exclude patterns
        if exclude_patterns:
            for pattern_glob in exclude_patterns:
                cmd.extend(["--glob", f"!{pattern_glob}"])

        # Add pattern and path
        cmd.append(pattern)

        # Run ripgrep
        result = GrepResult()

        try:
            process = await anyio.run_process(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Parse JSON output
            output = process.stdout.decode("utf-8", errors="replace")
            error_output = process.stderr.decode("utf-8", errors="replace")

            if (
                process.returncode != 0 and process.returncode != 1
            ):  # 1 means no matches
                raise RuntimeError(f"Ripgrep failed: {error_output}")

            # Process each line (each is a JSON object)
            current_file = None
            current_file_path = None
            line_context: Dict[int, List[str]] = {}  # line_number -> context lines

            for line in output.splitlines():
                if not line.strip():
                    continue

                try:
                    data = json.loads(line)
                    match_type = data.get("type")

                    if match_type == "begin":
                        # New file
                        current_file = data.get("data", {}).get("path", {}).get("text")
                        if current_file:
                            # Validate the file is allowed
                            file_path = Path(current_file)
                            file_abs, file_allowed = await self.validator.validate_path(
                                file_path
                            )
                            if file_allowed:
                                current_file_path = current_file
                            else:
                                current_file_path = None

                    elif match_type == "match" and current_file_path:
                        # Match in current file
                        match_data = data.get("data", {})
                        line_number = match_data.get("line_number", 0)

                        # Extract the submatches
                        submatches = match_data.get("submatches", [])
                        if not submatches:
                            continue

                        line_content = (
                            match_data.get("lines", {}).get("text", "").rstrip("\n")
                        )

                        for submatch in submatches:
                            match_start = submatch.get("start", 0)
                            match_end = (
                                match_start
                                + submatch.get("end", 0)
                                - submatch.get("start", 0)
                            )

                            # Create a match
                            context_before_lines: List[str] = []
                            context_after_lines: List[str] = []

                            # No need to determine line context variables here as we set them directly in the loops below

                            # Get context before from line_context if available
                            before_lines = (
                                context_before if context_before > 0 else context_lines
                            )
                            for i in range(line_number - before_lines, line_number):
                                if i in line_context:
                                    # line_context[i] is a List[str], but we need to add a single string
                                    # to our own list, so we take just the first element or an empty string
                                    ctx_line = (
                                        line_context[i][0] if line_context[i] else ""
                                    )
                                    context_before_lines.append(ctx_line)

                            # We don't actually have context after in the ripgrep output format
                            # in our current implementation

                            match = GrepMatch(
                                file_path=current_file_path,
                                line_number=line_number,
                                line_content=line_content,
                                match_start=match_start,
                                match_end=match_end,
                                context_before=context_before_lines,
                                context_after=context_after_lines,
                            )

                            result.add_match(match)

                    elif match_type == "context" and current_file_path:
                        # Context line
                        context_data = data.get("data", {})
                        line_number = context_data.get("line_number", 0)
                        line_content = (
                            context_data.get("lines", {}).get("text", "").rstrip("\n")
                        )

                        # Store for potential use in match context
                        if line_number not in line_context:
                            line_context[line_number] = []
                        line_context[line_number].append(line_content)

                except json.JSONDecodeError:
                    # Skip invalid JSON lines
                    continue

            # Apply pagination if requested
            if results_offset > 0 or results_limit is not None:
                paginated_result = GrepResult()
                paginated_result.file_counts = result.file_counts
                paginated_result.total_matches = result.total_matches
                paginated_result.files_searched = result.files_searched
                paginated_result.errors = result.errors

                # Apply offset and limit
                start_idx = min(results_offset, len(result.matches))

                if results_limit is not None:
                    end_idx = min(start_idx + results_limit, len(result.matches))
                else:
                    end_idx = len(result.matches)

                # Copy only the matches in the requested range
                paginated_result.matches = result.matches[start_idx:end_idx]

                # Return the paginated result
                return paginated_result

            return result

        except (subprocess.SubprocessError, FileNotFoundError) as e:
            raise RuntimeError(f"Failed to run ripgrep: {e}")

    async def _grep_with_python(
        self,
        path: Path,
        pattern: str,
        is_regex: bool,
        case_sensitive: bool,
        whole_word: bool,
        include_patterns: Optional[List[str]],
        exclude_patterns: Optional[List[str]],
        context_lines: int,
        context_before: int,
        context_after: int,
        max_results: int,
        max_file_size_mb: float,
        recursive: bool,
        max_depth: Optional[int],
        count_only: bool,
        show_progress: bool,
        progress_callback: Optional[Callable[[int, int], Any]],
        results_offset: int = 0,
        results_limit: Optional[int] = None,
    ) -> GrepResult:
        """Use Python implementation for searching.

        Args:
            See grep_files for parameter descriptions

        Returns:
            GrepResult with matches
        """
        result = GrepResult()
        max_file_size = int(max_file_size_mb * 1024 * 1024)

        # Compile regex pattern
        if is_regex:
            # SECURITY: Validate regex pattern to prevent ReDoS attacks
            self._validate_regex_security(pattern)
            
            flags = 0 if case_sensitive else re.IGNORECASE
            try:
                if whole_word:
                    compiled_pattern = re.compile(r"\b" + pattern + r"\b", flags)
                else:
                    compiled_pattern = re.compile(pattern, flags)
            except re.error:
                raise ValueError(f"Invalid regex pattern: {pattern}")
        else:
            # For non-regex, use simple string search
            if not case_sensitive:
                pattern = pattern.lower()

            # For whole word, we'll check boundaries during search
            if whole_word:

                def is_whole_word(text: str, start: int, end: int) -> bool:
                    """Check if match is a whole word."""
                    is_start = start == 0 or not text[start - 1].isalnum()
                    is_end = end == len(text) or not text[end].isalnum()
                    return is_start and is_end
            else:

                def is_whole_word(text: str, start: int, end: int) -> bool:
                    """Always return True for non-whole word search."""
                    return True

        # Get file list
        files_to_search: List[Path] = []

        if path.is_file():
            files_to_search.append(path)
        elif recursive:
            # Get all files recursively, respecting max_depth
            async def scan_dir(dir_path: Path, current_depth: int = 0) -> None:
                if max_depth is not None and current_depth > max_depth:
                    return

                try:
                    entries = await anyio.to_thread.run_sync(list, dir_path.iterdir())

                    for entry in entries:
                        try:
                            # Check if path is allowed
                            (
                                entry_abs,
                                entry_allowed,
                            ) = await self.validator.validate_path(entry)
                            if not entry_allowed:
                                continue

                            if entry.is_file():
                                # Apply include/exclude patterns

                                # Skip if doesn't match include patterns
                                if include_patterns:
                                    included = False
                                    for pattern_glob in include_patterns:
                                        if entry.match(pattern_glob):
                                            included = True
                                            break
                                    if not included:
                                        continue

                                # Skip if matches exclude patterns
                                if exclude_patterns:
                                    excluded = False
                                    for pattern_glob in exclude_patterns:
                                        if entry.match(pattern_glob):
                                            excluded = True
                                            break
                                    if excluded:
                                        continue

                                files_to_search.append(entry)

                            elif entry.is_dir():
                                await scan_dir(entry, current_depth + 1)

                        except (PermissionError, FileNotFoundError):
                            # Skip entries we can't access
                            pass

                except (PermissionError, FileNotFoundError):
                    # Skip directories we can't access
                    pass

            await scan_dir(path)

        else:
            # Only get immediate files
            try:
                entries = await anyio.to_thread.run_sync(list, path.iterdir())

                for entry in entries:
                    try:
                        if entry.is_file():
                            # Apply include/exclude patterns
                            if include_patterns:
                                included = False
                                for pattern_glob in include_patterns:
                                    if entry.match(pattern_glob):
                                        included = True
                                        break
                                if not included:
                                    continue

                            if exclude_patterns:
                                excluded = False
                                for pattern_glob in exclude_patterns:
                                    if entry.match(pattern_glob):
                                        excluded = True
                                        break
                                if excluded:
                                    continue

                            files_to_search.append(entry)

                    except (PermissionError, FileNotFoundError):
                        # Skip entries we can't access
                        pass

            except (PermissionError, FileNotFoundError):
                # Skip directories we can't access
                pass

        # Search files
        total_files = len(files_to_search)
        processed = 0

        for file_path in files_to_search:
            if result.total_matches >= max_results:
                break

            try:
                # Check file size
                file_stat = await anyio.to_thread.run_sync(file_path.stat)
                if file_stat.st_size > max_file_size:
                    result.add_error(str(file_path), "File too large")
                    continue

                # Count this file as searched
                result.files_searched += 1

                # Read file content
                try:
                    content = await anyio.to_thread.run_sync(
                        file_path.read_text, encoding="utf-8", errors="replace"
                    )
                except UnicodeDecodeError:
                    # Skip binary files
                    result.add_error(str(file_path), "Binary file")
                    continue

                lines = content.splitlines()
                file_matches = 0

                # Search each line
                for line_num, line in enumerate(lines, 1):
                    if result.total_matches >= max_results:
                        break

                    search_line = line if case_sensitive else line.lower()

                    if is_regex:
                        # Use compiled regex with timeout protection
                        try:
                            matches = await self._safe_regex_operation(compiled_pattern.finditer, search_line)
                            for match in matches:
                                if is_whole_word(line, match.start(), match.end()):
                                    # Get context lines
                                    context_before_lines = []
                                    context_after_lines = []

                                    # Context before
                                    before_count = (
                                        context_before
                                        if context_before > 0
                                        else context_lines
                                    )
                                    for i in range(
                                        max(0, line_num - 1 - before_count),
                                        line_num - 1,
                                    ):
                                        context_before_lines.append(lines[i])

                                    # Context after
                                    after_count = (
                                        context_after if context_after > 0 else context_lines
                                    )
                                    for i in range(
                                        line_num,
                                        min(len(lines), line_num + after_count),
                                    ):
                                        context_after_lines.append(lines[i])

                                    grep_match = GrepMatch(
                                        file_path=str(file_path),
                                        line_number=line_num,
                                        line_content=line,
                                        match_start=match.start(),
                                        match_end=match.end(),
                                        context_before=context_before_lines,
                                        context_after=context_after_lines,
                                    )

                                    if not count_only:
                                        result.add_match(grep_match)
                                    file_matches += 1

                                    if result.total_matches >= max_results:
                                        break
                        except ValueError as e:
                            if "timed out" in str(e):
                                result.add_error(str(file_path), f"Regex timeout: {e}")
                                continue
                            else:
                                raise
                    else:
                        # Simple string search
                        start = 0
                        while True:
                            pos = search_line.find(pattern, start)
                            if pos == -1:
                                break

                            end_pos = pos + len(pattern)
                            if is_whole_word(line, pos, end_pos):
                                # Get context lines
                                context_before_lines = []
                                context_after_lines = []

                                # Context before
                                before_count = (
                                    context_before
                                    if context_before > 0
                                    else context_lines
                                )
                                for i in range(
                                    max(0, line_num - 1 - before_count),
                                    line_num - 1,
                                ):
                                    context_before_lines.append(lines[i])

                                # Context after
                                after_count = (
                                    context_after if context_after > 0 else context_lines
                                )
                                for i in range(
                                    line_num,
                                    min(len(lines), line_num + after_count),
                                ):
                                    context_after_lines.append(lines[i])

                                grep_match = GrepMatch(
                                    file_path=str(file_path),
                                    line_number=line_num,
                                    line_content=line,
                                    match_start=pos,
                                    match_end=end_pos,
                                    context_before=context_before_lines,
                                    context_after=context_after_lines,
                                )

                                if not count_only:
                                    result.add_match(grep_match)
                                file_matches += 1

                                if result.total_matches >= max_results:
                                    break

                            start = pos + 1

                            if result.total_matches >= max_results:
                                break

                # Update file count if we had matches
                if file_matches > 0:
                    result.file_counts[str(file_path)] = file_matches

            except (PermissionError, FileNotFoundError) as e:
                result.add_error(str(file_path), str(e))

            # Update progress
            processed += 1
            if show_progress and progress_callback:
                progress_callback(processed, total_files)

        # Apply pagination if requested
        if results_offset > 0 or results_limit is not None:
            paginated_result = GrepResult()
            paginated_result.file_counts = result.file_counts
            paginated_result.total_matches = result.total_matches
            paginated_result.files_searched = result.files_searched
            paginated_result.errors = result.errors

            # Apply offset and limit
            start_idx = min(results_offset, len(result.matches))

            if results_limit is not None:
                end_idx = min(start_idx + results_limit, len(result.matches))
            else:
                end_idx = len(result.matches)

            # Copy only the matches in the requested range
            paginated_result.matches = result.matches[start_idx:end_idx]

            # Return the paginated result
            return paginated_result

        return result

    def _validate_regex_security(self, pattern: str) -> None:
        """Validate regex patterns to prevent ReDoS attacks.
        
        Args:
            pattern: Regex pattern to validate
            
        Raises:
            ValueError: If pattern is potentially dangerous
        """
        # Check pattern length
        if len(pattern) > MAX_REGEX_LENGTH:
            raise ValueError(f"Regex pattern too long (max {MAX_REGEX_LENGTH} characters)")
        
        # Block dangerous patterns that can cause exponential backtracking
        dangerous_patterns = [
            r'(.*)*',      # Nested quantifiers
            r'(.+)+',      # Nested quantifiers  
            r'(a+)+',      # Nested quantifiers
            r'(a*)*',      # Nested quantifiers
            r'(a+)*',      # Nested quantifiers
            r'(a|a)*',     # Alternation with overlap
            r'([a-z]+)+',  # Character class with nested quantifiers
            r'(\w+)+',     # Word boundary with nested quantifiers
        ]
        
        for dangerous in dangerous_patterns:
            if dangerous in pattern:
                raise ValueError(f"Potentially dangerous regex pattern detected: {dangerous}")
        
        # Count nested quantifiers and alternations
        quantifier_count = pattern.count('+') + pattern.count('*') + pattern.count('?')
        if quantifier_count > 10:
            raise ValueError("Too many quantifiers in regex pattern (max 10)")
            
        alternation_count = pattern.count('|')
        if alternation_count > 20:
            raise ValueError("Too many alternations in regex pattern (max 20)")
    
    async def _safe_regex_operation(self, operation, *args, **kwargs):
        """Execute regex operation with timeout protection.
        
        Args:
            operation: Function to execute
            *args: Arguments for the operation
            **kwargs: Keyword arguments for the operation
            
        Returns:
            Result of the operation
            
        Raises:
            asyncio.TimeoutError: If operation times out
        """
        try:
            return await asyncio.wait_for(
                anyio.to_thread.run_sync(operation, *args, **kwargs),
                timeout=REGEX_TIMEOUT_SECONDS
            )
        except asyncio.TimeoutError:
            raise ValueError(f"Regex operation timed out after {REGEX_TIMEOUT_SECONDS} seconds - possible ReDoS attack")