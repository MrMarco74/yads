import sys
import os
import tkinter as tk
from tkinter import ttk

# Add path to the installer source
sys.path.insert(0, os.path.abspath('release_assets/yads_installer'))

from gui import YADSInstallerGUI, STYLE_HEADER, STYLE_ACTION_BTN

class VerifiedGUI(YADSInstallerGUI):
    def __init__(self, root):
        self.root = root
        self.colors = {
            'bg': '#1e1e2e',
            'bg_alt': '#313244',
            'fg': '#cdd6f4',
            'fg_sub': '#a6adc8',
            'accent': '#89b4fa'
        }
        self.data = {
            'yads_host': 'localhost',
            'api_port': '8000',
            'use_ssl': False,
            'host': 'localhost',
            'remote_workers': []
        }
        self.current_step = 4
        self.steps = [None]*10
        self.secrets = {}
        
        self.content_frame = ttk.Frame(self.root)
        self.content_frame.pack(fill="both", expand=True, padx=40, pady=20)
        
        # Style mock
        self.card_style = "Card.TFrame"
        
        # Data mock
        self.data['remote_workers'].append({
            "host": "192.168.1.50",
            "user": "root",
            "method": "ssh",
            "status": "new"
        })
        self.data['remote_workers'].append({
            "host": "192.168.1.60",
            "user": "admin",
            "method": "manual",
            "status": "new"
        })
        
        self.step_remote_workers()

root = tk.Tk()
root.title("YADS Remote Worker Verification")
root.geometry("800x600")
root.configure(bg='#1e1e2e')

style = ttk.Style()
style.configure(STYLE_HEADER, font=("Helvetica", 16, "bold"), foreground='#cdd6f4', background='#1e1e2e')
style.configure("TFrame", background='#1e1e2e')
style.configure("Card.TFrame", background='#313244')

gui = VerifiedGUI(root)

def capture():
    os.system('gnome-screenshot -f /home/mrmarco/Documents/gitlab/yads/remote_worker_verified.png')
    root.destroy()

root.after(2000, capture)
root.mainloop()
