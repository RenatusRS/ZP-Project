class InputException(Exception):
    pass


class WrongPasswordException(Exception):
    pass


class BadPasswordFormat(Exception):
    pass


class BadPEMFormat(Exception):
    pass


class KeyAlreadyExists(Exception):
    pass


class VerificationFailed(Exception):
	pass
