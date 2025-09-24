# pip install umbral
from umbral import SecretKey, Signer, encrypt, generate_kfrags, reencrypt, decrypt_reencrypted

class Sender:
    def __init__(self, name):
        self.name = name
        self.key_store = {}
        self.transforms_store = {}

    def key_gen(self, secret_name):
        sk = SecretKey.random()
        pk = sk.public_key()
        singe_sk = SecretKey.random()
        singer = Signer(singe_sk)
        self.key_store[secret_name] = {"sk": sk, "pk": pk, "singe_sk": singe_sk, "singer": singer}

    def encrypt_secret(self, secret_name, secret_value):
        self.key_gen(secret_name)
        return encrypt(self.key_store[secret_name]["pk"], secret_value)

    def grant_access(self, receiver, secret_name, receiver_public_key):
        kfrags = generate_kfrags(
            delegating_sk = self.key_store[secret_name]["sk"],
            receiving_pk = receiver_public_key,
            signer = self.key_store[secret_name]["singer"],
            threshold = 1,
            shares = 1,
        )
        if receiver not in self.transforms_store:
            self.transforms_store[receiver] = {}
        self.transforms_store[receiver][secret_name] = kfrags

    def get_pk(self, secret_name):
        return self.key_store[secret_name]["pk"]

class Proxy:
    def __init__(self, name):
        self.name = name
        self.store = {}
        self.permission_store = {}

    def register_secret(self, sender, secret_name, payload):
        capsule, cipher = payload
        if sender not in self.store:
            self.store[sender] = {}
        self.store[sender][secret_name] = {"capsule": capsule, "cipher": cipher}

    def register_new_grant(self, sender, receiver, secret_name, kfrags):
        if sender not in self.permission_store:
            self.permission_store[sender] = {}
        if receiver not in self.permission_store[sender]:
            self.permission_store[sender][receiver] = {}
        self.permission_store[sender][receiver][secret_name] = kfrags

    def request_capsule(self, sender, receiver, secret_name):
        capsule = self.store[sender][secret_name]["capsule"]
        kfrags = self.permission_store[sender][receiver][secret_name]
        return [reencrypt(capsule, k) for k in kfrags[:]], capsule

    def request_cipher(self, sender, secret_name):
        cipher = self.store[sender][secret_name]["cipher"]
        return cipher

class Receiver:
    def __init__(self, name):
        self.name = name
        self.key_store = {}

    def key_gen(self, sender, secret_name):
        sk = SecretKey.random()
        pk = sk.public_key()
        if sender not in self.key_store:
            self.key_store[sender] = {}
        self.key_store[sender][secret_name] = sk
        return pk

    def decrypt(self, sender, secret_name, sender_pk, capsule, verified_cfrags, cipher):
        return decrypt_reencrypted(
            self.key_store[sender][secret_name],
            sender_pk,
            capsule,
            verified_cfrags,
            cipher,
        )

alice = Sender("alice")
david = Sender("david")
bob = Receiver("bob")
charlie = Receiver("charlie")
ursula = Proxy("ursula")

street = "main_residence_street_name"
number = "main_residence_street_number"
#zip = "main_residence_zip_code"
#town = "main_residence_town"

ursula.register_secret(alice.name, street, alice.encrypt_secret(street, "Dunkingstreet".encode("utf-8")))
ursula.register_secret(alice.name, number, alice.encrypt_secret(number, "55".encode("utf-8")))
ursula.register_secret(david.name, street, david.encrypt_secret(street, "Mainstreet".encode("utf-8")))

alice.grant_access(bob.name, street, bob.key_gen(alice.name, street))
alice.grant_access(bob.name, number, bob.key_gen(alice.name, number))
alice.grant_access(charlie.name, street, charlie.key_gen(alice.name, street))

david.grant_access(bob.name, street, bob.key_gen(david.name, street))

ursula.register_new_grant(alice.name, bob.name, street, alice.transforms_store[bob.name][street])
ursula.register_new_grant(alice.name, bob.name, number, alice.transforms_store[bob.name][number])
ursula.register_new_grant(alice.name, charlie.name, street, alice.transforms_store[charlie.name][street])
ursula.register_new_grant(david.name, bob.name, street, david.transforms_store[bob.name][street])

cfrags_bob_alice_street, capsule = ursula.request_capsule(alice.name, bob.name, street)
recovered_bob = bob.decrypt(alice.name, street, alice.get_pk(street), capsule, cfrags_bob_alice_street, ursula.request_cipher(alice.name, street))
print(bob.name + " recovered: " + alice.name + " " + street + " = " + recovered_bob.decode("utf-8"))

cfrags_bob_alice_number, capsule = ursula.request_capsule(alice.name, bob.name, number)
recovered_bob = bob.decrypt(alice.name, number, alice.get_pk(number), capsule, cfrags_bob_alice_number, ursula.request_cipher(alice.name, number))
print(bob.name + " recovered: " + alice.name + " " + number + " = " + recovered_bob.decode("utf-8"))

cfrags_bob_david_street, capsule = ursula.request_capsule(david.name, bob.name, street)
recovered_bob = bob.decrypt(david.name, street, david.get_pk(street), capsule, cfrags_bob_david_street, ursula.request_cipher(david.name, street))
print(bob.name + " recovered: " + david.name + " " + street + " = " + recovered_bob.decode("utf-8"))

cfrags_charlie_alice_street, capsule = ursula.request_capsule(alice.name, charlie.name, street)
recovered_charlie = charlie.decrypt(alice.name, street, alice.get_pk(street), capsule, cfrags_charlie_alice_street, ursula.request_cipher(alice.name, street))
print(charlie.name + " recovered: " + alice.name + " " + street + " = " + recovered_charlie.decode("utf-8"))
