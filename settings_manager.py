"""
Settings Manager module for loading, updating, and saving user configuration.
"""

import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional

BASE_DIR = Path(sys.executable).parent if getattr(sys, 'frozen', False) else Path(__file__).resolve().parent
DEFAULT_SETTINGS_PATH = str(BASE_DIR / "config" / "settings.json")

DEFAULT_SETTINGS: Dict[str, Any] = {
    "max_workers": 8,
    "check_timeout": 3.0,
    "default_protocol": "TCP",
}


class SettingsManager:
    """Manages application configuration with default fallback support."""

    def __init__(
        self,
        filepath: Optional[str] = None,
        defaults: Optional[Dict[str, Any]] = None,
        autosave: bool = True
    ):
        """Initializes settings and loads configuration from disk."""
        self.filepath = Path(filepath or DEFAULT_SETTINGS_PATH)
        self.defaults = dict(defaults if defaults is not None else DEFAULT_SETTINGS)
        self.autosave = autosave
        self.data: Dict[str, Any] = {}
        self.load()

    def load(self) -> Dict[str, Any]:
        """Loads settings from disk, applying defaults for missing keys."""
        self.filepath.parent.mkdir(parents=True, exist_ok=True)

        if not self.filepath.exists():
            self.data = dict(self.defaults)
            self.save()
            return self.data

        try:
            with open(self.filepath, "r", encoding="utf-8") as f:
                saved_data = json.load(f)

            merged = dict(self.defaults)
            if isinstance(saved_data, dict):
                merged.update(saved_data)

            self.data = merged
            return self.data

        except (json.JSONDecodeError, OSError) as error:
            print(f"[SettingsManager Warning] Failed to read {self.filepath}: {error}. Using defaults.")
            self.data = dict(self.defaults)
            return self.data

    def get(self, key: str, fallback: Any = None) -> Any:
        """Retrieves a configuration value by key."""
        return self.data.get(key, fallback)

    def set(self, key: str, value: Any, autosave: Optional[bool] = None) -> None:
        """Sets a configuration value and optionally persists it."""
        self.data[key] = value
        should_save = self.autosave if autosave is None else autosave
        if should_save:
            self.save()

    def save(self) -> bool:
        """Persists current settings to disk."""
        try:
            self.filepath.parent.mkdir(parents=True, exist_ok=True)
            with open(self.filepath, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=2)
            return True
        except OSError as error:
            print(f"[SettingsManager Error] Failed to write settings to {self.filepath}: {error}")
            return False


if __name__ == "__main__":
    test_manager = SettingsManager("config/test_settings.json")
    test_manager.set("max_workers", 16)
    if test_manager.filepath.exists():
        test_manager.filepath.unlink()
