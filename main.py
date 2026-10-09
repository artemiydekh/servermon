import os
import sys
from pathlib import Path
from PySide6.QtWidgets import QApplication
from gui import NetworkMonitorUI

def get_resource_path(relative_name: str) -> str:
    """Resolves application resource path for both development and bundled builds."""
    if hasattr(sys, '_MEIPASS'):
        bundle_path = Path(sys._MEIPASS) / relative_name
        if bundle_path.exists():
            return str(bundle_path)
    base_dir = Path(sys.executable).parent if getattr(sys, 'frozen', False) else Path(__file__).resolve().parent
    direct_path = base_dir / relative_name
    if direct_path.exists():
        return str(direct_path)
    return str(Path(__file__).resolve().parent / relative_name)

def main():
    """Initializes the Qt application and displays the main window."""
    base_dir = Path(sys.executable).parent if getattr(sys, 'frozen', False) else Path(__file__).resolve().parent
    os.chdir(base_dir)
    app = QApplication(sys.argv)
    window = NetworkMonitorUI(get_resource_path("gui.ui"))
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()  