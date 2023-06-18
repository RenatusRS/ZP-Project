from tkinter.ttk import Frame, Scrollbar
from tkinter import Canvas, NW, RIGHT, BOTH, VERTICAL, Y, Event

class CFrame(Frame):
	def __init__(self, parent, *args, **kwargs):
		super().__init__(parent, *args, **kwargs)
		
		self.canvas = Canvas(self)
		self.canvas.config(highlightthickness=0)
		self.canvas.pack(side=RIGHT, fill=BOTH, expand=True)
		
		self.content = Frame(self.canvas)
		
		self.canvas_frame = self.canvas.create_window((0, 0), window=self.content, anchor=NW)
		
		scrollbar = Scrollbar(self.canvas, orient=VERTICAL, command=self.canvas.yview)
		scrollbar.pack(side=RIGHT, fill=Y)
		
		self.canvas.config(yscrollcommand=scrollbar.set)
		
		self.content.bind('<Configure>', self.ScrollSize)
		self.canvas.bind('<Configure>', self.FrameWidth)
		
		self.bind('<Enter>', lambda event: self.canvas.bind_all('<MouseWheel>', lambda event: self.canvas.yview_scroll(int(-1 * (event.delta / 120)), 'units')))
		self.bind('<Leave>', lambda event: self.canvas.unbind_all('<MouseWheel>'))
		

	def FrameWidth(self, event: Event):
		self.canvas.itemconfig(self.canvas_frame, width = event.width)
		
	def ScrollSize(self, event: Event):
		self.canvas.configure(scrollregion=self.canvas.bbox('all'))
		