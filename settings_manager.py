"""
=============================================================================
SETTINGS MANAGER MODULE (settings_manager.py)
=============================================================================
A clean, modular, and reusable configuration management engine.

WHY THIS MODULE EXISTS:
-----------------------
Every serious desktop or command-line application needs a way to remember user
preferences between sessions (for example: window sizes, theme choices, worker
thread limits, network timeouts).

Without a settings manager, users are forced to reconfigure the application
every single time they open it.

HOW THE "DEFAULT FALLBACK" PATTERN WORKS:
-----------------------------------------
A common bug in software development happens when you release "Version 2" with
a new setting (e.g. 'enable_dark_mode'). If an existing user has an old settings
file from "Version 1", their file won't have that new setting. If your code tries
to read it directly with config['enable_dark_mode'], Python will crash with a
KeyError!

This module solves that completely through the Default-Merge pattern:
1. We define a dictionary of DEFAULT_SETTINGS in code.
2. When loading from disk, we read the user's saved JSON file.
3. We merge the user's saved values ON TOP of the defaults.
   - Any setting the user customized is preserved.
   - Any new setting added in future updates is automatically filled with its default.
   - The file is never broken, and the app never crashes!

REUSABILITY IN FUTURE PROJECTS:
-------------------------------
This file has ZERO dependencies on PySide6, Qt, or any graphical frameworks.
It only uses Python's standard library ('json' and 'pathlib'). You can copy and
paste this single file into ANY future Python project (CLI tool, Flask/FastAPI
backend, PyGame project, or desktop app) and it will work out of the box.
=============================================================================
"""

import json
from pathlib import Path
from typing import Any, Dict, Optional


# =============================================================================
# MASTER DEFAULT CONFIGURATION
# =============================================================================
# When creating a new setting in the future, simply add it to this dictionary!
# For example, to add an auto-refresh timer in the future, you would just add:
#   "auto_refresh_seconds": 60,
#
# That single line is all it takes for the entire application to know about it.
DEFAULT_SETTINGS: Dict[str, Any] = {
    # Number of parallel worker threads used for batch verification
    "max_workers": 8,

    # Socket connection and ICMP ping timeout threshold (in seconds)
    "check_timeout": 3.0,

    # Verification protocol selected by default ('TCP' or 'PING')
    "default_protocol": "TCP",
}


class SettingsManager:
    """
    Manages loading, modifying, and auto-saving user configuration data.
    
    Attributes:
        filepath (Path): The filesystem location of the JSON settings file.
        defaults (dict): The baseline fallback dictionary.
        data (dict): The current in-memory key-value settings.
    """

    def __init__(
        self,
        filepath: str = "config/settings.json",
        defaults: Optional[Dict[str, Any]] = None,
        autosave: bool = True
    ):
        """
        Initializes the settings engine and immediately loads saved preferences.

        Parameters:
            filepath  - Path to the JSON configuration file (e.g. 'config/settings.json').
                        Parent folders will be created automatically if they do not exist.
            defaults  - Optional custom dictionary of default values. If omitted,
                        uses the DEFAULT_SETTINGS constant defined above.
            autosave  - If True, calling set() will immediately write changes to disk.
                        If False, you must call save() manually.
        """
        # Convert string path to a modern Path object for cross-platform safety
        self.filepath = Path(filepath)

        # Use provided defaults or fallback to the module-level constant
        self.defaults = dict(defaults if defaults is not None else DEFAULT_SETTINGS)

        # Flag determining whether set() writes to disk immediately
        self.autosave = autosave

        # In-memory dictionary holding the active configuration
        self.data: Dict[str, Any] = {}

        # Load existing settings from disk, or initialize with defaults
        self.load()

    def load(self) -> Dict[str, Any]:
        """
        Loads settings from disk and merges them with default values.

        How it works:
        1. If the file does not exist, it creates the folder and file populated
           with DEFAULT_SETTINGS.
        2. If the file does exist, it reads the JSON content.
        3. It performs a "merge" so any missing keys in the file are populated
           from defaults, ensuring a 100% complete configuration dictionary.

        Returns:
            The loaded and merged dictionary of settings.
        """
        # Ensure the destination folder exists (e.g. creates 'config/' if missing)
        self.filepath.parent.mkdir(parents=True, exist_ok=True)

        # Case 1: Settings file does not exist yet (first-time launch)
        if not self.filepath.exists():
            # Start fresh with a copy of all default values
            self.data = dict(self.defaults)
            # Write initial file to disk so user can inspect or edit it
            self.save()
            return self.data

        # Case 2: File exists -- read and merge
        try:
            with open(self.filepath, "r", encoding="utf-8") as f:
                saved_data = json.load(f)

            # Start with a full set of default values
            merged = dict(self.defaults)

            # Overlay saved user values on top of defaults
            if isinstance(saved_data, dict):
                merged.update(saved_data)

            self.data = merged
            return self.data

        except (json.JSONDecodeError, OSError) as error:
            # If the user accidentally corrupted the JSON file (e.g. syntax error),
            # safely fall back to defaults rather than crashing the application.
            print(f"[SettingsManager Warning] Failed to read {self.filepath}: {error}. Using defaults.")
            self.data = dict(self.defaults)
            return self.data

    def get(self, key: str, fallback: Any = None) -> Any:
        """Retrieves the value for a given setting key."""
        return self.data.get(key, fallback)

    def set(self, key: str, value: Any, autosave: Optional[bool] = None) -> None:
        """
        Updates a setting value in memory and optionally auto-saves to disk.

        Parameters:
            key      - The setting name string (e.g. 'max_workers').
            value    - The new value to store (integer, string, boolean, float, list, etc.).
            autosave - Optional override for the auto-save behavior. If None, uses
                       the default self.autosave setting configured at initialization.

        Example:
            # Updates in memory AND writes to config/settings.json immediately
            settings.set("max_workers", 12)
        """
        self.data[key] = value

        # Check if we should persist immediately to disk
        should_save = self.autosave if autosave is None else autosave
        if should_save:
            self.save()

    def save(self) -> bool:
        """
        Serializes current in-memory settings to the JSON file on disk.

        Uses indentation (indent=2) so the file remains easily readable and
        editable in standard text editors like Notepad or VS Code.

        Returns:
            True if write succeeded, False if an operating system error occurred.
        """
        try:
            # Ensure folder exists prior to writing
            self.filepath.parent.mkdir(parents=True, exist_ok=True)

            with open(self.filepath, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=2)
            return True

        except OSError as error:
            print(f"[SettingsManager Error] Failed to write settings to {self.filepath}: {error}")
            return False


# =============================================================================
# SELF-TESTING / DEMONSTRATION CODE
# =============================================================================
# This block runs only when executing `python settings_manager.py` directly.
# It serves as a quick built-in test and interactive tutorial for beginners.
if __name__ == "__main__":
    print("--- Running SettingsManager Demonstration ---")
    
    # 1. Initialize manager with a temporary test file
    test_manager = SettingsManager("config/test_settings.json")
    print("Initial loaded data:", test_manager.data)

    # 2. Read a value
    print("Worker count:", test_manager.get("max_workers"))

    # 3. Update a value (with auto-save)
    test_manager.set("max_workers", 16)
    print("Updated worker count:", test_manager.get("max_workers"))

    # 4. Clean up test file
    if test_manager.filepath.exists():
        test_manager.filepath.unlink()
        print("Cleaned up test file successfully.")
        
    print("--- All demonstrations passed! ---")

