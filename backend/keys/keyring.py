import pickle
import base64
import re

from typing import List, Dict

from backend.exceptions import *
from backend.utils import *


class Keyring:
    public = []


    def __init__(self):
        self.private = []


    def get_private_ring(self, key_id: bytes):
        for row in self.private:
            if row.key_id == key_id:
                return row
            
        return None


    def get_public_ring(self, key_id: bytes):
        for row in Keyring.public:
            if row.key_id == key_id:
                return row
            
        return None


    @staticmethod
    def read_key(file, algo, is_private):
        
        re_emptyline = b'^\s*$'
        re_end = b'^-----END (RSA|ELGAMAL) (PRIVATE|PUBLIC) KEY-----$'
        key = None
        line = file.readline()
        
        while line != b'':
            match_empty = re.search(re_emptyline, line)
            match_end = re.search(re_end, line)
            
            if not match_empty and not match_end:
                if key:
                    raise BadPEMFormat('Bad PEM format') # ako se pojavljuje "dva" ključa (u dva različita reda)
                
                key = line

            if match_end:
                algo2 = match_end.group(1)
                is_private2 = match_end.group(2)
                
                if algo2 != algo or is_private != is_private2 or not key: # ako se ne poklaplaju BEGIN i END ili ako ključ ne postoji
                    raise BadPEMFormat('BEGIN and END do not match or key does not exist')
                
                return base64.b64decode(key)

            line = file.readline()
            
        raise BadPEMFormat('Bad PEM format')


    def import_key(self, filename: str) -> None:
        with open(filename, 'rb') as f:

            re_emptyline = b'^\s*$'
            re_title = b'^-----BEGIN (RSA|ELGAMAL) (PRIVATE|PUBLIC) KEY-----$'
            line = f.readline()
            
            while line != b'':
                match_empty = re.search(re_emptyline, line)
                match_title = re.search(re_title, line)
                
                if not match_title and not match_empty:
                    raise BadPEMFormat('Bad PEM format')
                
                if match_title:
                    algo = match_title.group(1)
                    private = match_title.group(2)
                    
                    assert(algo == b'RSA' or algo == b'ELGAMAL')
                    assert(private == b'PRIVATE' or private == b'PUBLIC')

                    try:
                        key = pickle.loads(self.read_key(f, algo, private))
                        
                    except pickle.UnpicklingError:
                        raise BadPEMFormat('Bad PEM format')
                    
                    is_private = (private == b'PRIVATE')
                    exists = [x for x in (self.private if is_private else self.public) if x.key_id == key.key_id]
                    
                    if exists:
                        raise KeyAlreadyExists('Key already exists')
                    
                    if is_private:
                        self.add_private_ring(key, key.user_id)
                    else:
                        self.public.append(key)
                        

                line = f.readline()


    def add_private_ring(self, key_row, name: str):
        '''
        Dodaje privatni ključ u tabelu korisnika, a njegov javni
        parnjak dodaje u globalnu tabelu javnih ključeva
        '''
        
        # TODO postoji problem kod import key u slučaju da se uvozi privatni
        # ključ ako je njegov javni parnjak već uvezen (dupliraće se)

        self.private.append(key_row)
        key_row.add_public_key(name)


    def __repr__(self):
        rpr = "=================== PRIVATE ====================\n"
        
        for row in self.private:
            rpr += str(row)
            
        return rpr


    @staticmethod
    def all_public_keys():
        rpr = "\n============== PUBLIC (GLOBAL) =================\n"
        
        for row in Keyring.public:
            rpr += str(row)
            
        return rpr


keyrings: Dict[str, Keyring] = { }
