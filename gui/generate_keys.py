from gui.base import BaseFrame
from tkinter import *
from backend.config import Cfg

from backend.ring import Keyring, keyrings, PrivateKeyRowRSA, PrivateKeyRowElGamal


class GenerateKeysFrame(BaseFrame):
	title = "Generate Keys"

	def fill(self):
		self.generate_keys_frame()

	def generate_keys_frame(self):
		frame = Frame(self)

		# Name
		frame_name = Frame(frame)

		entry_name = Entry(frame_name)

		Label(frame_name, text="Name").pack(side=LEFT)
		entry_name.pack(side=RIGHT)

		# Email
		frame_email = Frame(frame)

		entry_email = Entry(frame_email)

		Label(frame_email, text="Email").pack(side=LEFT)
		entry_email.pack(side=RIGHT)

		# Algorithm
		frame_algorithm = Frame(frame)

		global radio_group_algorithm
		radio_group_algorithm = StringVar(value="rsa")

		radio_algorithm_rsa = Radiobutton(
			frame_algorithm,
			text="RSA",
			value="rsa",
			variable=radio_group_algorithm,
		)

		radio_algorithm_dsa_elgamal = Radiobutton(
			frame_algorithm,
			text="DSA + El Gamal",
			value="dsa_elgamal",
			variable=radio_group_algorithm,
		)

		Label(frame_algorithm, text="Algorithm").pack(side=LEFT)
		radio_algorithm_dsa_elgamal.pack(side=RIGHT)
		radio_algorithm_rsa.pack(side=RIGHT)

		# Size
		frame_size = Frame(frame)

		global radio_group_size
		radio_group_size = IntVar(value=1024)

		radio_size_1024 = Radiobutton(
			frame_size, text="1024", value=1024, variable=radio_group_size)
		radio_size_2048 = Radiobutton(
			frame_size, text="2048", value=2048, variable=radio_group_size)

		Label(frame_size, text="Size").pack(side=LEFT)
		radio_size_2048.pack(side=RIGHT)
		radio_size_1024.pack(side=RIGHT)

		# Password
		frame_password = Frame(frame)

		entry_password = Entry(frame_password, show="*")

		Label(frame_password, text="Password").pack(side=LEFT)
		entry_password.pack(side=RIGHT)

		# Generate
		button_generate = Button(frame, text="Generate", command=lambda: self.generate_keys(entry_name.get(
		), entry_email.get(), radio_group_algorithm.get(), radio_group_size.get(), entry_password.get()))

		# Pack
		frame_name.pack(side=TOP, expand=True, fill="both")
		frame_email.pack(side=TOP, expand=True, fill="both")
		frame_algorithm.pack(side=TOP, expand=True, fill="both")
		frame_size.pack(side=TOP, expand=True, fill="both")
		frame_password.pack(side=TOP, expand=True, fill="both")
		button_generate.pack(side=BOTTOM, fill="both")

		frame.pack(fill="both", expand=True)

	def generate_keys(self, name, email, algorithm, size, password):
		Method = None

		if algorithm == "rsa":
			Method = PrivateKeyRowRSA
		elif algorithm == "dsa_elgamal":
			Method = PrivateKeyRowElGamal
			
		if Cfg.USERNAME not in keyrings:
			keyrings[Cfg.USERNAME] = Keyring()

		keyrings[Cfg.USERNAME].add_private_ring(Method(email, size, password), name)
