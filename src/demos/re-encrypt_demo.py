# pip install umbral
from umbral import SecretKey, Signer, encrypt, generate_kfrags, reencrypt, decrypt_reencrypted

class Sender:
    def __init__(self, name):
        self.name = name
        self.sk = SecretKey.random()
        self.pk = self.sk.public_key()
        self.sing_sk = SecretKey.random()
        self.signer = Signer(self.sing_sk)
    
    def encrypt_to_self(self, secret):
        return encrypt(self.pk, secret)

    def calc_transform_key(self, receiver_public_key):
        kfrags = generate_kfrags(
            delegating_sk=self.sk,
            receiving_pk=receiver_public_key,
            signer=self.signer,
            threshold=1,
            shares=1,
        )
        return kfrags

class Receiver:
    def __init__(self, name):
        self.name = name
        self.sk = SecretKey.random()
        self.pk = self.sk.public_key()
    
    def decrypt(self, sender_pk, capsule, verified_cfrags, ct):
        return decrypt_reencrypted(
            self.sk,
            sender_pk,
            capsule,
            verified_cfrags,
            ct,
        )

class Proxy:
    def __init__(self, name):
        self.name = name
        self.store = {}

    def register_new_connection(self, sender, receiver, capsule, kfrags):
        connection_id = sender+"<->"+receiver
        if connection_id not in self.store:
            self.store[connection_id] = [capsule, kfrags]

    def request_cipher(self, sender, receiver):
        capsule, kfrags = self.store[sender+"<->"+receiver]
        return [reencrypt(capsule, k) for k in kfrags[:]], capsule

class CipherStore:
    def __init__(self):
        pass

alice = Sender("alice")
bob = Receiver("bob")
charlie = Receiver("charlie")
ursula = Proxy("ursula")

# Alice
secret = "symmetric-key-to-big-data".encode("utf-8")
capsule, ct = alice.encrypt_to_self(secret)
kfrags_bob = alice.calc_transform_key(bob.pk)
kfrags_charlie = alice.calc_transform_key(charlie.pk)
ursula.register_new_connection(alice.name, bob.name, capsule, kfrags_bob)
ursula.register_new_connection(alice.name, charlie.name, capsule, kfrags_charlie)
capsule = 0

# ursula

# bob
cfrags_bob, capsule = ursula.request_cipher(alice.name, bob.name)
recovered_bob = bob.decrypt(alice.pk, capsule, cfrags_bob, ct)
assert recovered_bob == secret
print(recovered_bob.decode("utf-8"))
capsule = 0

# charlie
cfrags_charlie, capsule = ursula.request_cipher(alice.name, charlie.name)
recovered_charlie = charlie.decrypt(alice.pk, capsule, cfrags_charlie, ct)
assert recovered_charlie == secret
print(recovered_charlie.decode("utf-8"))


