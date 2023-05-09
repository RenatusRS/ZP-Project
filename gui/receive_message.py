from tkinter import simpledialog
from tkinter.filedialog import askopenfile, asksaveasfile
from gui.base import BaseFrame
from tkinter import *
from backend.config import Cfg

from backend.messages import read_message


class ReceiveFrame(BaseFrame):
	title = "Receive Message"
	decrypted_data = None

	def fill(self):
		self.receive_message_frame()
		
		button_save_message = Button(self, text="Save Message", command=lambda: self.save_message("message", self.decrypted_data))
		
		button_save_message.pack(side="bottom")
		
	def receive_message_frame(self):
		global path
		path = StringVar(value="/")
		
		frame = Frame(self)
		
		button_recieve_message = Button(frame, text="Receive Message", command=self.process_message)
		
		Label(frame, textvariable=path).pack(side="left")
		button_recieve_message.pack(side="right")

		frame.pack(side="top", fill="both")
		
	def process_message(self):
		data = self.receive_message()
		
		if data is None:
			return
		
		password = simpledialog.askstring("Password", "Enter password", show="*")
		
		if password is None:
			return
		
		data = read_message(Cfg.USERNAME, data, password)
		
		self.decrypted_data = data
		    
	def receive_message(self):
		file = askopenfile(mode="rb", defaultextension=".xtx", filetypes=[("Encrypted text file", "*.xtx")])
		
		if file is None:
			return None
		
		path.set(file.name)
		
		data = file.read()
		file.close()
		
		return data
	
	def save_message(self, name, data):
		if data is None:
			return
		
		file = asksaveasfile(mode="w", defaultextension=".txt", filetypes=[("Text file", "*.txt")], initialfile=f"{name}.txt")
		
		if file is None:
			return
		
		file.write(data)
		file.close()
