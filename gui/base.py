from tkinter import *


class BaseFrame(Frame):
	def __init__(self, parent):
		super().__init__(parent)

		self.refresh()

		self.pack(fill="both", expand=True)
		parent.add(self, text=self.title, padding=(5, 5, 5, 5))
		
	def refresh(self):
		for child in self.winfo_children():
			child.destroy()
		
		self.fill()
