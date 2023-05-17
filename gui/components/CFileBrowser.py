from tkinter.filedialog import askopenfilename
from tkinter.ttk import Frame, Button, Entry
from tkinter import StringVar, LEFT, BOTH, RIGHT, Y

class CFileBrowser(Frame):
	def __init__(self, parent, button_text = "...", file_type = (None, None), *args, **kwargs):
		super().__init__(parent, *args, **kwargs)
		
		self.file_type = file_type
		
		self.path = StringVar()
		
		entry_path = Entry(self, textvariable=self.path)
		
		button_browse = Button(self, text=button_text, command=self.browse)
		
		entry_path.pack(side=LEFT, fill=BOTH, expand=True)
		button_browse.pack(side=RIGHT, fill=Y)
		
		
	def browse(self):
		file = askopenfilename(defaultextension=self.file_type[0], filetypes=[(self.file_type[1], f'*.{self.file_type[0]}')])
		self.path.set(file)
		
		
	def get_path(self):
		return self.path.get()
	
	
	def get_data(self, mode = 'r'):
		path = self.get_path()
		
		if path == '':
			return None
		
		with open(path, mode) as file:
			data = file.read()
		
		return data