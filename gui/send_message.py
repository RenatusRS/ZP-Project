from tkinter.ttk import Separator, Checkbutton as ttkCheckbutton
from gui.base import BaseFrame
from tkinter import *
from tkinter.filedialog import asksaveasfile
from backend.config import Cfg

from backend.messages import create_message
from backend.ring import Keyring, keyrings

from backend.utils import SymEnc


class SendFrame(BaseFrame):
	title = "Send Message"

	def fill(self):
		checkbox_encrypt = ttkCheckbutton(self, text="Encrypt")
		checkbox_encrypt.state(['!alternate'])

		global radio_group_encrypt
		radio_group_encrypt = StringVar(value=SymEnc.DES3)

		radio_encrypt_triple_des = Radiobutton(
			self, text="Triple DES", value="triple_des", variable=radio_group_encrypt)
		radio_encrypt_aes = Radiobutton(
			self, text="AES128", value="aes", variable=radio_group_encrypt)

		self.public_keys = Keyring.public
		options_public_keys = [key.user_id for key in self.public_keys]
		var_public_key = StringVar()
		
		option_public_keys = OptionMenu(self, var_public_key, "", *options_public_keys)

		checkbox_authenticate = ttkCheckbutton(self, text="Authenticate")
		checkbox_authenticate.state(['!alternate'])
		
		self.private_keys = keyrings[Cfg.USERNAME].private if Cfg.USERNAME in keyrings else []
		options_private_keys = [key.user_id for key in self.private_keys]
		var_private_key = StringVar()

		option_private_keys = OptionMenu(self, var_private_key, "", *options_private_keys)

		checkbox_compress = ttkCheckbutton(self, text="Compress")
		checkbox_compress.state(['!alternate'])

		checkbox_convert = ttkCheckbutton(self, text="Convert")
		checkbox_convert.state(['!alternate'])

		text_message = Text(self, height=10, width=50)

		button_send_message = Button(self,
									 text="Send Message",
									 command=lambda: self.send_message(
										 text_message.get("1.0", "end-1c"),
										 (keyrings[Cfg.USERNAME].get_public_ring_by_user_id(var_public_key.get()), SymEnc.AES if radio_group_encrypt.get() == "aes" else SymEnc.DES3) if 'selected' in checkbox_encrypt.state() else None,
										 keyrings[Cfg.USERNAME].get_private_ring_by_user_id(var_private_key.get()) if 'selected' in checkbox_authenticate.state() else None,
										 'selected' in checkbox_compress.state(),
										 'selected' in checkbox_convert.state()
									 	)
									 )

		checkbox_encrypt.pack(side="top", anchor="w")
		
		Label(self, text="Algorithm").pack(side="top", anchor="w")
		radio_encrypt_triple_des.pack(side="top", anchor="w")
		radio_encrypt_aes.pack(side="top", anchor="w")
		
		Label(self, text="Public Key").pack(side="top", anchor="w")
		option_public_keys.pack(side="top", anchor="w")

		Separator(self, orient="horizontal").pack(
			side="top", fill="x", pady=10)

		checkbox_authenticate.pack(side="top", anchor="w")
		
		Label(self, text="Private Key").pack(side="top", anchor="w")
		option_private_keys.pack(side="top", anchor="w")

		Separator(self, orient="horizontal").pack(
			side="top", fill="x", pady=10)

		checkbox_compress.pack(side="top", anchor="w")

		Separator(self, orient="horizontal").pack(
			side="top", fill="x", pady=10)

		checkbox_convert.pack(side="top", anchor="w")

		Label(self, text="Message").pack(side="top", anchor="w")
		text_message.pack(side="top", anchor="w", fill="both")
		button_send_message.pack(side="bottom", fill="x")

	def send_message(self, message, encr, auth, compr, radix64):
		print(compr, radix64)
		
		data = create_message(message, encr, auth, compr, radix64)

		file = asksaveasfile(mode="wb", defaultextension=".xtx", filetypes=[
			("Encrypted text file", "*.xtx")], initialfile=f"message.xtx")

		if file is None:
			return

		file.write(data)
		file.close()
