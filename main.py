from backend.store import Store
from gui.frames.browse_keys import BrowseKeysTab
from gui.frames.generate_keys import GenerateKeysTab
from gui.frames.receive_message import ReceiveMessageTab
from gui.frames.select_user import SelectUserTab
from gui.frames.send_message import SendMessageTab
from gui.window import TabbedWindow


if __name__ == '__main__':
	Store.ROOT = root = TabbedWindow()
	root.title(f'ZP Projekat 2022/2023 [{Store.USERNAME}]')
	root.iconbitmap('zp.ico')
	root.minsize(600, 450)
	root.maxsize(800, 600)
	
	root.add_tab(SelectUserTab, 'Select User')
	root.add_tab(GenerateKeysTab, 'Generate Keys')
	root.add_tab(BrowseKeysTab, 'Browse Keys')
	root.add_tab(SendMessageTab, 'Send Message')
	root.add_tab(ReceiveMessageTab, 'Receive Message')
	
	root.mainloop()
	