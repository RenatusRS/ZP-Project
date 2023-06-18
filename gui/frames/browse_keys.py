from gui.components.CTabbedView import CTabbedView
from gui.frames.private_keys import PrivateKeysTab
from gui.frames.public_keys import PublicKeysTab
from gui.frames.tab import Tab
from tkinter import BOTH, BOTTOM, E
from tkinter.ttk import Button

from gui.utils import import_key

class BrowseKeysTab(Tab):
	def __init__(self, parent, *args, **kwargs):
		super().__init__(parent, (0, 0, 0, 0), *args, **kwargs)

	def fill(self):
		self.tabbed = CTabbedView(self)
		
		self.tabbed.add_tab(PrivateKeysTab, '🔒 Private Keys')
		self.tabbed.add_tab(PublicKeysTab, '🔓 Public Keys')
		
		button_import = Button(self, text='➕ Import Keys', command=import_key)
		
		# Pack
		self.tabbed.pack(expand=True, fill=BOTH)
		button_import.pack(side=BOTTOM, anchor=E, padx=10, pady=10)
		
	def refresh(self):
		self.tabbed.refresh()
