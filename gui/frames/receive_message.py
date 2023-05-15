from tkinter.filedialog import askopenfile, asksaveasfile
from backend.store import Store
from gui.frames.tab import Tab
from tkinter import *

from backend.messages import read_message


class ReceiveMessageTab(Tab):
	decrypted_data = None

	def fill(self):
		self.receive_message_frame()
		
		button_save_message = Button(self, text='Save Message', command=lambda: self.save_message('message', self.decrypted_data))
		
		button_save_message.pack(side=BOTTOM, fill=X)
		
	def receive_message_frame(self):
		global path
		path = StringVar(value='/')
		
		frame = Frame(self)
		
		button_recieve_message = Button(frame, text='Receive Message', command=self.process_message)
		
		Label(frame, textvariable=path).pack(side=LEFT)
		button_recieve_message.pack(side=RIGHT)

		frame.pack(side=TOP, fill=BOTH)
		
	def process_message(self):
		data = self.receive_message()
		
		if data is None:
			return
		
		data = read_message(Store.USERNAME, data)
		
		self.decrypted_data = data
		    
	def receive_message(self):
		file = askopenfile(mode='rb', defaultextension='.xtx', filetypes=[('Encrypted text file', '*.xtx')])
		
		if file is None:
			return None
		
		path.set(file.name)
		
		data = file.read()
		file.close()
		
		return data
	
	def save_message(self, name, data):
		if data is None:
			return
		
		file = asksaveasfile(mode=W, defaultextension='.txt', filetypes=[('Text file', '*.txt')], initialfile=f'{name}.txt')
		
		if file is None:
			return
		
		file.write(data)
		file.close()