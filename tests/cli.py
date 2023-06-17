
from backend.keys.private_key_row import PrivateKeyRow, PrivateKeyRowRSA
from backend.keys.keyring import Keyring, keyrings

from backend.messages.messages import create_message, read_message, send_message, receive_message
from backend.utils import AsymEnc, SymEnc

from tkinter import Tk

def populate():
    key_size = 1024

    p = PrivateKeyRowRSA("fedja@fedja", key_size, "fedja")
    keyrings["fedja"].add_private_ring(p, "urosh1")
    p = PrivateKeyRowRSA("djafe@djafe", key_size, "fedja")
    keyrings["fedja"].add_private_ring(p, "urosh2")
    p = PrivateKeyRow("lonchar@lonchar", key_size, "lonchar")
    keyrings["lonchar"].add_private_ring(p, "fedja1")


if __name__ == '__main__':
    root = Tk()

    keyrings["fedja"] = Keyring()
    keyrings["lonchar"] = Keyring()
    populate()
    # keyrings["fedja"].import_key("f1.pem")
    # keyrings["fedja"].import_key("f2.pem")
    # keyrings["lonchar"].import_key("u1.pem")

    print(str(keyrings["fedja"]))
    print('////////////////////////////////////////////////////////////\n')
    print(str(keyrings["lonchar"]))
    print('////////////////////////////////////////////////////////////\n')
    print(Keyring.all_public_keys())

    # keyrings["fedja"].private[0].export_key("f1")
    # keyrings["fedja"].private[1].export_key("f2")
    # keyrings["lonchar"].private[0].export_key("u1")

    msg = create_message("zdravo fedja", auth=keyrings["fedja"].private[0], encr=(Keyring.public[2], SymEnc.DES3), compr=True, radix64=True)

    send_message(msg, 'pls2')
    print(receive_message('pls2', "lonchar"))

