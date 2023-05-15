from abc import ABCMeta, abstractmethod
from tkinter import *


class Tab(Frame, metaclass=ABCMeta):
	def __init__(self, parent):
		super().__init__(parent)

		self.fill()
		
	def refresh(self):
		for child in self.winfo_children():
			child.destroy()
		
		self.fill()
		
	@abstractmethod
	def fill(self):
		pass
