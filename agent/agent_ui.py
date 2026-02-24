import sys
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QPushButton,
    QLineEdit, QTextEdit
)
from PySide6.QtCore import Qt, QThread, Signal
import subprocess
import os

class AgentThread(QThread):
    log = Signal(str)

    def __init__(self, token):
        super().__init__()
        self.token = token
        self.process = None

    def run(self):
        try:
            cmd = [
                os.path.abspath("./venv/Scripts/python.exe"),
                os.path.abspath("./agent/agent.py"),
                "--agent-token", self.token
            ]
            self.process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )
            for line in self.process.stdout:
                self.log.emit(line)
        except Exception as e:
            self.log.emit(f"ERROR: {e}")

    def stop(self):
        if self.process:
            self.process.kill()

class AgentUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("KeepConnected Agent UI")
        layout = QVBoxLayout()

        self.label = QLabel("Agent Token:")
        self.input = QLineEdit()
        self.start_btn = QPushButton("Iniciar Agente")
        self.stop_btn = QPushButton("Detener Agente")
        self.log = QTextEdit()
        self.log.setReadOnly(True)

        layout.addWidget(self.label)
        layout.addWidget(self.input)
        layout.addWidget(self.start_btn)
        layout.addWidget(self.stop_btn)
        layout.addWidget(self.log)

        self.setLayout(layout)

        self.thread = None

        self.start_btn.clicked.connect(self.start_agent)
        self.stop_btn.clicked.connect(self.stop_agent)

    def start_agent(self):
        token = self.input.text().strip()
        if not token:
            self.log.append("Debes ingresar un agent_token.")
            return
        self.thread = AgentThread(token)
        self.thread.log.connect(self.log.append)
        self.thread.start()
        self.log.append("Agente iniciadoâ€¦")

    def stop_agent(self):
        if self.thread:
            self.thread.stop()
            self.thread = None
            self.log.append("Agente detenido.")

def main():
    app = QApplication(sys.argv)
    ui = AgentUI()
    ui.show()
    sys.exit(app.exec())
    
if __name__ == "__main__":
    main()
