"""
Wordlist management utilities for NTREE
Handles SecLists wordlist searching and retrieval
"""

import os
from pathlib import Path
from typing import List, Dict, Optional
import fnmatch

from .logger import get_logger

logger = get_logger(__name__)


class WordlistManager:
    """Manage and search wordlists from SecLists."""

    def __init__(self, seclists_path: Optional[str] = None):
        """
        Initialize wordlist manager.

        Args:
            seclists_path: Path to SecLists directory (defaults to ~/wordlists/SecLists)
        """
        if seclists_path:
            self.seclists_path = Path(seclists_path)
        else:
            # Try standard locations
            home = Path.home()
            possible_paths = [
                home / "wordlists" / "SecLists",
                Path("/usr/share/seclists"),
                Path("/opt/SecLists"),
            ]

            self.seclists_path = None
            for path in possible_paths:
                if path.exists():
                    self.seclists_path = path
                    break

        if self.seclists_path and self.seclists_path.exists():
            logger.info(f"SecLists found at: {self.seclists_path}")
        else:
            logger.warning("SecLists not found. Please install from: https://github.com/danielmiessler/SecLists.git")

    def is_available(self) -> bool:
        """Check if SecLists is available."""
        return self.seclists_path is not None and self.seclists_path.exists()

    def search_wordlists(
        self,
        keyword: str,
        category: Optional[str] = None,
        max_results: int = 50
    ) -> List[Dict[str, str]]:
        """
        Search for wordlists by keyword.

        Args:
            keyword: Search keyword (e.g., 'password', 'username', 'subdomain')
            category: Optional category filter (e.g., 'Passwords', 'Discovery', 'Fuzzing')
            max_results: Maximum number of results to return

        Returns:
            List of wordlist metadata dictionaries
        """
        if not self.is_available():
            return []

        results = []
        keyword_lower = keyword.lower()

        # Search through SecLists directory
        try:
            search_path = self.seclists_path
            if category:
                category_path = self.seclists_path / category
                if category_path.exists():
                    search_path = category_path

            for root, dirs, files in os.walk(search_path):
                # Skip hidden directories
                dirs[:] = [d for d in dirs if not d.startswith('.')]

                for file in files:
                    if file.endswith(('.txt', '.lst', '.list')):
                        file_path = Path(root) / file
                        file_lower = file.lower()

                        # Check if keyword matches filename or path
                        if keyword_lower in file_lower or keyword_lower in str(file_path).lower():
                            rel_path = file_path.relative_to(self.seclists_path)
                            file_size = file_path.stat().st_size

                            results.append({
                                "name": file,
                                "path": str(file_path),
                                "relative_path": str(rel_path),
                                "category": str(rel_path.parts[0]) if len(rel_path.parts) > 1 else "root",
                                "size_bytes": file_size,
                                "size_human": self._format_size(file_size),
                            })

                            if len(results) >= max_results:
                                return results

        except Exception as e:
            logger.error(f"Error searching wordlists: {e}", exc_info=True)

        return results

    def get_wordlist_path(self, relative_path: str) -> Optional[str]:
        """
        Get full path to a wordlist by relative path.

        Args:
            relative_path: Relative path within SecLists (e.g., 'Passwords/Common-Credentials/10-million-password-list-top-100.txt')

        Returns:
            Full path to wordlist or None if not found
        """
        if not self.is_available():
            return None

        full_path = self.seclists_path / relative_path
        if full_path.exists() and full_path.is_file():
            return str(full_path)

        return None

    def list_categories(self) -> List[str]:
        """
        List available wordlist categories.

        Returns:
            List of category names
        """
        if not self.is_available():
            return []

        categories = []
        try:
            for item in self.seclists_path.iterdir():
                if item.is_dir() and not item.name.startswith('.'):
                    categories.append(item.name)
        except Exception as e:
            logger.error(f"Error listing categories: {e}", exc_info=True)

        return sorted(categories)

    def get_category_info(self, category: str) -> Dict:
        """
        Get information about a specific category.

        Args:
            category: Category name

        Returns:
            Dictionary with category information
        """
        if not self.is_available():
            return {"status": "error", "error": "SecLists not available"}

        category_path = self.seclists_path / category
        if not category_path.exists():
            return {"status": "error", "error": f"Category '{category}' not found"}

        # Count wordlists in category
        wordlist_count = 0
        total_size = 0

        try:
            for root, dirs, files in os.walk(category_path):
                dirs[:] = [d for d in dirs if not d.startswith('.')]
                for file in files:
                    if file.endswith(('.txt', '.lst', '.list')):
                        wordlist_count += 1
                        file_path = Path(root) / file
                        total_size += file_path.stat().st_size

            # List subdirectories
            subdirs = [d.name for d in category_path.iterdir() if d.is_dir() and not d.name.startswith('.')]

            return {
                "status": "success",
                "category": category,
                "path": str(category_path),
                "wordlist_count": wordlist_count,
                "total_size": self._format_size(total_size),
                "subdirectories": subdirs,
            }

        except Exception as e:
            logger.error(f"Error getting category info: {e}", exc_info=True)
            return {"status": "error", "error": str(e)}

    def get_common_wordlists(self) -> Dict[str, List[Dict]]:
        """
        Get commonly used wordlists organized by type.

        Returns:
            Dictionary of common wordlists by category
        """
        if not self.is_available():
            return {}

        common = {
            "passwords": [],
            "usernames": [],
            "subdomains": [],
            "directories": [],
            "files": [],
            "fuzzing": [],
        }

        # Define common wordlist patterns
        patterns = {
            "passwords": [
                "Passwords/Common-Credentials/*",
                "Passwords/Default-Credentials/*",
                "Passwords/*top*.txt",
                "Passwords/*common*.txt",
            ],
            "usernames": [
                "Usernames/*",
                "Discovery/DNS/*usernames*.txt",
            ],
            "subdomains": [
                "Discovery/DNS/*subdomain*.txt",
                "Discovery/DNS/*dns*.txt",
            ],
            "directories": [
                "Discovery/Web-Content/*directories*.txt",
                "Discovery/Web-Content/raft-*-directories*.txt",
            ],
            "files": [
                "Discovery/Web-Content/*files*.txt",
                "Discovery/Web-Content/raft-*-files*.txt",
            ],
            "fuzzing": [
                "Fuzzing/*",
                "Discovery/Web-Content/burp-parameter-names.txt",
            ],
        }

        try:
            for category, pattern_list in patterns.items():
                for pattern in pattern_list:
                    search_pattern = str(self.seclists_path / pattern)
                    for file_path in Path(self.seclists_path).glob(pattern):
                        if file_path.is_file() and file_path.suffix in ['.txt', '.lst', '.list']:
                            rel_path = file_path.relative_to(self.seclists_path)
                            common[category].append({
                                "name": file_path.name,
                                "path": str(file_path),
                                "relative_path": str(rel_path),
                                "size": self._format_size(file_path.stat().st_size),
                            })

                # Limit to most relevant
                common[category] = common[category][:10]

        except Exception as e:
            logger.error(f"Error getting common wordlists: {e}", exc_info=True)

        return common

    def read_wordlist(
        self,
        path: str,
        max_lines: Optional[int] = None,
        skip_comments: bool = True
    ) -> List[str]:
        """
        Read wordlist from file.

        Args:
            path: Path to wordlist file
            max_lines: Maximum number of lines to read (None for all)
            skip_comments: Skip lines starting with # or //

        Returns:
            List of wordlist entries
        """
        entries = []

        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for i, line in enumerate(f):
                    if max_lines and i >= max_lines:
                        break

                    line = line.strip()

                    # Skip empty lines
                    if not line:
                        continue

                    # Skip comments if requested
                    if skip_comments and (line.startswith('#') or line.startswith('//')):
                        continue

                    entries.append(line)

        except Exception as e:
            logger.error(f"Error reading wordlist {path}: {e}", exc_info=True)

        return entries

    def _format_size(self, size_bytes: int) -> str:
        """Format file size in human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"


# Global wordlist manager instance
_wordlist_manager = None


def get_wordlist_manager() -> WordlistManager:
    """Get global WordlistManager instance."""
    global _wordlist_manager
    if _wordlist_manager is None:
        _wordlist_manager = WordlistManager()
    return _wordlist_manager


def search_wordlists(keyword: str, category: Optional[str] = None, max_results: int = 50) -> List[Dict[str, str]]:
    """Convenience function to search wordlists."""
    manager = get_wordlist_manager()
    return manager.search_wordlists(keyword, category, max_results)


def get_wordlist_path(relative_path: str) -> Optional[str]:
    """Convenience function to get wordlist path."""
    manager = get_wordlist_manager()
    return manager.get_wordlist_path(relative_path)


def list_categories() -> List[str]:
    """Convenience function to list categories."""
    manager = get_wordlist_manager()
    return manager.list_categories()
