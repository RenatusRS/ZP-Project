from abc import ABCMeta, abstractmethod
from tkinter.ttk import Frame


class Tab(Frame, metaclass=ABCMeta):
	def __init__(self, parent, padding, *args, **kwargs):
		super().__init__(parent, padding = padding, *args, **kwargs)

		self.fill()
		
	def refresh(self):
		for child in self.winfo_children():
			child.destroy()
		
		self.fill()
		
	@abstractmethod
	def fill(self):
		pass
