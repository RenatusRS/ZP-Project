from tkinter import Text

class CText(Text):
	def __init__(self, parent, read_only = False, *args, **kwargs):
		super().__init__(parent, *args, **kwargs)
		
		self.read_only = read_only
		
		if self.read_only:
			self.config(state='disabled')
		
	def clear(self):
		self.set('')
		
	def set(self, text: str):
		self.config(state='normal')
		
		self.delete('1.0', 'end')
		self.insert('1.0', text)
		
		if self.read_only:
			self.config(state='disabled')
		
	def data(self) -> str:
		return self.get('1.0', 'end-1c')
	