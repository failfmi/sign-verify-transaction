from pycoin.ecdsa import generator_secp256k1, sign, verify
import hashlib, json


def ripemd160(msg: str) -> str:
    hash_bytes = hashlib.new('ripemd160', msg.encode("utf8")).digest()
    return hash_bytes.hex()


def sha256(msg: str) -> int:
    hash_bytes = hashlib.sha256(msg.encode("utf8")).digest()
    return int.from_bytes(hash_bytes, byteorder="big")


# def random_private_key_to_address():
#     se = random.getrandbits(256)
#     key = Key(secret_exponent=se)
#     print(key)
#     print(key.sec_as_hex())
#     print(key.public_pair())
#     private_key = (key.sec_as_hex(), 16)
#     print(private_key)
#     # print((generator_secp256k1 * ll).pair())
#     print("Address:", key.address())
#     print("----------------")
#
#     return key.sec_as_hex()


def private_key_hex_to_int(private_key_hex: str):
    return int(private_key_hex, 16)


def private_key_to_public_key(private_key):
    return (generator_secp256k1 * private_key).pair()


def get_pub_key_compressed(pub_key):
    return hex(pub_key[0])[2:] + str(pub_key[1] % 2)


def public_key_compressed_to_address(public_key_compressed):
    return ripemd160(public_key_compressed)


def extract_public_key_and_address(private_key):
    pub_key = private_key_to_public_key(private_key)
    pub_key_compressed = get_pub_key_compressed(pub_key)
    print("public key compressed:", pub_key_compressed)
    sender_address = public_key_compressed_to_address(pub_key_compressed)
    print("address:", sender_address)

    return pub_key_compressed, sender_address


def sign_and_verify_transaction(recipient_address: str,
                                value: int,
                                fee: int,
                                date_created: str,
                                sender_priv_key_hex: str):
    print("sender private key hex:", sender_priv_key_hex)
    sender_priv_key = private_key_hex_to_int(sender_priv_key_hex)

    print("sender private key:", sender_priv_key)
    pub_key_compressed, sender_address = extract_public_key_and_address(sender_priv_key)

    transaction = {
        'from': sender_address,
        'to': recipient_address,
        'senderPubKey': pub_key_compressed,
        'value': value,
        'fee': fee,
        'dateCreated': date_created,
    }
    json_encoder = json.JSONEncoder(separators=(',', ':'))
    tran_json = json_encoder.encode(transaction)
    print("transaction (json):", tran_json)

    tran_hash = sha256(tran_json)
    print("transaction hash (sha256):", hex(tran_hash)[2:])
    tran_signature = sign(generator_secp256k1, sender_priv_key, tran_hash)
    print("transaction signature:", tran_signature)

    transaction['senderSignature'] = [hex(tran_signature[0])[2:], hex(tran_signature[1])[2:]]
    print("signed transaction:")
    print(json.JSONEncoder(indent=2).encode(transaction))

    pub_key = private_key_to_public_key(sender_priv_key)
    valid = verify(generator_secp256k1, pub_key, tran_hash, tran_signature)
    print("Is signature valid? " + str(valid))
    return valid


sign_and_verify_transaction(
    recipient_address="f51362b7351ef62253a227a77751ad9b2302f911",
    value=25000,
    fee=10,
    date_created='2018-02-10T17:53:48.972Z',
    sender_priv_key_hex="7e4670ae70c98d24f3662c172dc510a085578b9ccc717e6c2f4e547edd960a34")
