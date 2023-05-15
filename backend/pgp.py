
from backend.ring import populate, keyrings, Keyring

from backend.messages import create_message, read_message, send_message, receive_message
from backend.utils import AsymEnc, SymEnc

if __name__ == '__main__':
    populate()
    print(str(keyrings["fedja"]))
    print('////////////////////////////////////////////////////////////\n')
    print(str(keyrings["lonchar"]))
    print('////////////////////////////////////////////////////////////\n')
    print(Keyring.all_public_keys())


    msg = create_message("zdravo fedja", auth=keyrings["fedja"].private[0], encr=(Keyring.public[2], SymEnc.DES3), compr=True, radix64=True)

    send_message(msg, 'pls2')
    print(receive_message('pls2', "lonchar"))
