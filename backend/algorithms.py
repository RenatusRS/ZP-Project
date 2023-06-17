from enum import Enum

'''
Enum za simetrične alogritme šifrovanja
'''
class SymEnc(Enum):
    DES3  = 1
    AES   = 2
    CAST5 = 3
    IDEA  = 4


'''
Enum za asimetrične algoritme šifrovanja
'''
class AsymEnc(Enum):
    RSA     = 1
    ELGAMAL = 2