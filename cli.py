
from backend.ring import populate, keyrings, Keyring

from backend.messages import create_message, read_message, send_message, receive_message
from backend.utils import AsymEnc, SymEnc

from tkinter import Tk

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

