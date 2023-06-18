from typing import Tuple
from backend.messages.radix import isBase64, message_to_radix64, radix64_to_message
from backend.messages.compression import compress, decompress
from backend.utils import SymEnc, gen_timestamp
from backend.config import Cfg
from backend.keys.keyring import keyrings
from backend.keys.private_key_row import PrivateKeyRow
from backend.keys.public_key_row import PublicKeyRow

import sys


def create_message(message: str, encr: Tuple[PublicKeyRow, SymEnc] = None, auth: PrivateKeyRow = None, compr: bool = False, radix64: bool = False, contaminate: bool = False) -> bytes:
    '''
    Kreiranje poruke koja treba da se sačuva negde na disku.
    
    Parametri:
    message     -- poruka
    encr        -- opcioni argument. Predstavlja torku identifikatora asimetričnog algoritma i javnog ključa primaoca.
    auth        -- opcioni argument. Predstavlja torku identifikatora asimetričnog algoritma i privatnog ključa pošiljaoca.
    compression -- opcioni argument. Predstavlja izbor da li se poruka kompresuje ili ne.
    radix64     -- opcioni argument. Predstavlja izbor da li se poruka konvertuje u radix64 pre slanja ili ne.
    '''
    
    encoded: bytes = message.encode('utf8')
    encoded = gen_timestamp() + encoded
    
    if auth: # dodajemo zaglavlje ispred poruke (ukupno 42B + veličina ključa u bajtovima)
        encoded = auth.sign(encoded, contaminate) + encoded
        
    if compr: # kompresujemo poruku
        encoded = compress(encoded)
        
    if encr: # šifrujemo poruku i ispred nje dodajemo zaglavlje sa sesijskim ključem
        encoded = encr[0].encrypt(encoded, encr[1])

    header = b''
    header += auth.algo.value.to_bytes(1, sys.byteorder) if auth else b'\x00'
    header += encr[0].algo.value.to_bytes(1, sys.byteorder) if encr else b'\x00'
    header += encr[1].value.to_bytes(1, sys.byteorder) if encr else b'\x00'
    header += compr.to_bytes(1, sys.byteorder)
    
    encoded = header + encoded

    if radix64: # sve konvertujemo u radix64
        encoded = message_to_radix64(encoded)
        
    return encoded


def read_message(user: str, message: bytes) -> str:
    '''
    Čitanje poruke u obliku bytearray

    message -- poruka
    decr    -- opciona torka algoritma za dešifrovanje. Sadrži identifikator algoritma
    za dešifrovanje i privatni ključ primaoca
    auth    -- opciona torka za autentikaciju pošiljaoca. Sadrži identifikator algoritma
    za autentikaciju i javni ključ pošiljaoca
    compr   -- opcioni bool koji određuje da li se poruka kompresuje ili ne
    radix64 -- opcioni bool koji određuje da li se poruka konvertuje iz radix64 ili ne
    '''
    f_radix = isBase64(message)

    if f_radix: # konvertujemo nazad iz radix64
        message = radix64_to_message(message)

    header = message[:Cfg.MESSAGE_METADATA]
    message = message[Cfg.MESSAGE_METADATA:]

    f_auth = int.from_bytes(header[0:1], sys.byteorder)
    f_asym = int.from_bytes(header[1:2], sys.byteorder)
    f_sym  = int.from_bytes(header[2:3], sys.byteorder)
    f_comp = int.from_bytes(header[3:4], sys.byteorder)
    valid = True

    assert((f_asym and f_sym) or (not f_asym and not f_sym))

    if f_sym and f_asym:
        # sklanjamo zaglavlje
        key_id  = message[:Cfg.KEY_ID_SIZE]
        message = message[Cfg.KEY_ID_SIZE:]

        private_key_ring = keyrings[user].get_private_ring(key_id)

        assert(private_key_ring is not None)

        # dešifrujemo poruku i sklanjamo zaglavlje ispred nje
        message = private_key_ring.decrypt(message, SymEnc(f_sym))
        
    if f_comp: # dekompresujemo poruku
        message = decompress(message)
        
    if f_auth: # sklanjamo zaglavlje za autentikaciju i proveravamo ispravnost potpisa
        header = message

        timestamp = header[:Cfg.TIMESTAMP_BYTE_SIZE]
        header = header[Cfg.TIMESTAMP_BYTE_SIZE:]
        public_key_id = header[:Cfg.KEY_ID_SIZE]
        header = header[Cfg.KEY_ID_SIZE:]
        octets = header[:2]
        header = header[2:]

        keyrow = keyrings[user].get_public_ring(public_key_id)

        assert(keyrow is not None)

        message, valid = keyrow.verify(message, header)

    timestamp = message[0:Cfg.TIMESTAMP_BYTE_SIZE] # sklanjamo timestamp
    
    return message[Cfg.TIMESTAMP_BYTE_SIZE:].decode('utf8'), (f_auth, valid), (f_asym, f_sym), f_comp, f_radix

