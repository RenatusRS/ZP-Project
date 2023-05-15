from tkinter import *
from gui.components.CFrame import CFrame

class Table(Frame):
	def __init__(self, parent, columns):
		super().__init__(parent)
		
		fr = CFrame(self)
		self.table = fr.content

		for ind, column in enumerate(columns):
			Grid.columnconfigure(self.table, ind, weight=1)
			Label(self.table, text=column).grid(row=0, column=ind, sticky=W)
			
		fr.pack(side=TOP, anchor=W, expand=True, fill=BOTH)
