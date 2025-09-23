# pip install umbral
from umbral import SecretKey, Signer, encrypt, generate_kfrags, reencrypt, decrypt_reencrypted

class Sender:
    def __init__(self, name):
        self.name = name
        self.key_store = {}
        self.transforms_store = {}

    # checked
    def key_gen(self, secret_name):
        sk = SecretKey.random()
        pk = sk.public_key()
        singe_sk = SecretKey.random()
        singer = Signer(singe_sk)
        self.key_store[secret_name] = {"sk": sk, "pk": pk, "singe_sk": singe_sk, "singer": singer}

    # checked
    def encrypt_secret(self, secret_name, secret_value):
        self.key_gen(secret_name)
        return encrypt(self.key_store[secret_name]["pk"], secret_value)

    # checked
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
    
    # checked
    def get_pk(self, secret_name):
        return self.key_store[secret_name]["pk"]

class Proxy:
    def __init__(self, name):
        self.name = name
        self.store = {}
        self.permission_store = {}

    # checked
    def register_secret(self, sender, secret_name, payload):
        capsule, cipher = payload
        if sender not in self.store:
            self.store[sender] = {}
        self.store[sender][secret_name] = {"capsule": capsule, "cipher": cipher}

    # checked
    def register_new_grant(self, sender, receiver, secret_name, kfrags):
        if sender not in self.permission_store:
            self.permission_store[sender] = {}
        if receiver not in self.permission_store[sender]:
            self.permission_store[sender][receiver] = {}
        self.permission_store[sender][receiver][secret_name] = kfrags

    # checked
    def request_capsule(self, sender, receiver, secret_name):
        capsule = self.store[sender][secret_name]["capsule"]
        kfrags = self.permission_store[sender][receiver][secret_name]
        return [reencrypt(capsule, k) for k in kfrags[:]], capsule
    
    # checked
    def request_cipher(self, sender, secret_name):
        cipher = self.store[sender][secret_name]["cipher"]
        return cipher

class Receiver:
    def __init__(self, name):
        self.name = name
        self.key_store = {}

    # checked
    def key_gen(self, sender, secret_name):
        sk = SecretKey.random()
        pk = sk.public_key()
        if sender not in self.key_store:
            self.key_store[sender] = {}
        self.key_store[sender][secret_name] = sk
        return pk

    # checked
    def decrypt(self, sender, secret_name, sender_pk, capsule, verified_cfrags, cipher):
        return decrypt_reencrypted(
            self.key_store[sender][secret_name],
            sender_pk,
            capsule,
            verified_cfrags,
            cipher,
        )

alice = Sender("alice")
bob = Receiver("bob")
#charlie = Receiver("charlie")
ursula = Proxy("ursula")

# Alice
street = "main_residence_street_name"
#number = "main_residence_street_number"
#zip = "main_residence_zip_code"
#town = "main_residence_town"

ursula.register_secret(alice.name, street, alice.encrypt_secret(street, "Dunkingstreet".encode("utf-8")))
#ursula.register_secret(alice.name, number, alice.encrypt_secret(number, "55".encode("utf-8")))
#ursula.register_secret(alice.name, zip, alice.encrypt_secret(zip, "12345".encode("utf-8")))
#ursula.register_secret(alice.name, town, alice.encrypt_secret(town, "Ney York".encode("utf-8")))

alice.grant_access(bob.name, street, bob.key_gen(alice.name, street))
ursula.register_new_grant(alice.name, bob.name, street, alice.transforms_store[bob.name][street])

#alice.grant_access(charlie.name, street, charlie.pk)
#ursula.register_new_grant(alice.name, charlie.name, alice.transforms[charlie.name][street])
#alice.grant_access(charlie.name, zip, charlie.pk)
#ursula.register_new_grant(alice.name, charlie.name, alice.transforms[charlie.name][zip])
#alice.grant_access(charlie.name, town, charlie.pk)
#ursula.register_new_grant(alice.name, charlie.name, alice.transforms[charlie.name][town])

# ursula

# bob
cfrags_bob, capsule = ursula.request_capsule(alice.name, bob.name, street)
recovered_bob = bob.decrypt(alice.name, street, alice.get_pk(street), capsule, cfrags_bob, ursula.request_cipher(alice.name, street))
print(recovered_bob.decode("utf-8"))

# charlie
# cfrags_charlie, capsule = ursula.request_cipher(alice.name, charlie.name)
# recovered_charlie = charlie.decrypt(alice.pk, capsule, cfrags_charlie, ct)
# assert recovered_charlie == secret
# print(recovered_charlie.decode("utf-8"))


