import sys
from PySide6.QtWidgets import QApplication
from gui import NetworkMonitorUI

def main():
    app = QApplication(sys.argv)
    window = NetworkMonitorUI("gui.ui")
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()  