from tkinter import *
from tkinter.ttk import Notebook

from gui.generate_keys import GenerateKeysFrame
from gui.receive_message import ReceiveFrame
from gui.select_user import SelectUserFrame
from gui.send_message import SendFrame
from gui.browse_keys import BrowseKeysFrame

from backend.ring import Keyring, keyrings
from backend.config import Cfg

keyrings[Cfg.USERNAME] = Keyring()

root = Tk()
root.title(f"ZP Projekat 2022/2023 [{Cfg.USERNAME}]")

Grid.rowconfigure(root, 0, weight=1)
Grid.columnconfigure(root, 0, weight=1)

notebook = Notebook(root)
notebook.pack(expand=True, fill="both")

SelectUserFrame(notebook)
GenerateKeysFrame(notebook)
BrowseKeysFrame(notebook)
SendFrame(notebook)
ReceiveFrame(notebook)

def on_tab_change(event):
	event.widget.winfo_children()[event.widget.index("current")].refresh()
	
notebook.bind("<<NotebookTabChanged>>", on_tab_change)

root.mainloop()
