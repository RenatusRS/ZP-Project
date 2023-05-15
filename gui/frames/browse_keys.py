from gui.components.CTabbedView import CTabbedView
from gui.frames.private_keys import PrivateKeysTab
from gui.frames.public_keys import PublicKeysTab
from gui.frames.tab import Tab
from tkinter import *


class BrowseKeysTab(Tab):

	def fill(self):
		tabbed_view = CTabbedView(self)
		tabbed_view.pack(expand=True, fill=BOTH)
		
		tabbed_view.add_tab(PrivateKeysTab, 'Private Keys')
		tabbed_view.add_tab(PublicKeysTab, 'Public Keys')
