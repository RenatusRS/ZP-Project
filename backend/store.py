class Store:
	ROOT = None
	
	def __init__(self):
		self._USERNAME = "default"

	@property
	def USERNAME(self):
		return self._USERNAME
	
	@USERNAME.setter
	def USERNAME(self, value):
		if value == "":
			value = "default"
		
		self._USERNAME = value
	
		
Store = Store()
