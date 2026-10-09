import os
import sys
from pathlib import Path
from PySide6.QtWidgets import QApplication
from gui import NetworkMonitorUI

def main():
    base_dir = Path(sys.executable).parent if getattr(sys, 'frozen', False) else Path(__file__).resolve().parent
    os.chdir(base_dir)
    app = QApplication(sys.argv)
    window = NetworkMonitorUI("gui.ui")
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()  