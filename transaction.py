## Blockchain CW2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding

class Transaction:
    
    def __init__(self, sender_hash, recipient_hash, sender_public_key, amount, fee, nonce, signature, txid):
        self.sender_hash = sender_hash # The public key hash of the user sending the funds
        self.recipient_hash = recipient_hash # The public key hash of the user receiving the funds
        self.sender_public_key = sender_public_key # A byte array representing the public key of the user sending the funds
        self.amount = amount # The amount of funds being sent from the sender's address
        self.fee = fee # The amount of funds paid as a mining fee in this transaction
        self.nonce = nonce # A 64 bit number, this should increase by 1 for each transfer made by the sender
        self.signature = signature # A signature, created by the sender, confirming that they consent to this transaction
        self.txid = txid # The transaction id, this is a hash of the other fields of the transaction

    def verify(self, sender_balance, sender_previous_nonce):
        '''
        
        '''
        self.sender_balance = sender_balance
        self.sender_previous_nonce = sender_previous_nonce

        if len(self.recipient_hash) != 20 and len(self.sender_hash) != 20:
            #### Note: may need to add in checking it's 20 bytes, not just 20
            raise ValueError('Length of recipient_hash and/or sender_hash is not 20')
        else:    
            print('len good')
        
        # check sender_hash should is SHA-1 hash of sender_public_key
        sender_public_key_hash_check = hashes.Hash(hashes.SHA1())
        sender_public_key_hash_check.update(self.sender_public_key)#.to_bytes(8, byteorder = 'little', signed = False))
        sender_public_key_hash_check = sender_public_key_hash_check.finalize()

        if self.sender_hash != sender_public_key_hash_check:
            raise ValueError('SHA1 hash of sender_public_key does not match sender_hash')

        # check if amount is between 1 and sander_balance inclusive and is a whole number
        if not (1 <= self.amount <= self.sender_balance) and not (isinstance(self.amount, int)):
            raise ValueError('Amount failed test of being below balance or being whole number')

        # check if fee is between 1 and amount inclusive and is a whole number
        if not (1 <= self.fee <= self.amount) and not (isinstance(self.fee, int)):
            raise ValueError('Fee failed test of being below amount or being whole number')

        # check if nonce == sender_previous_nonce+1
        if self.nonce != self.sender_previous_nonce+1:
            raise ValueError('Invalid nonce')

        # get hash of other fields to check txid
        txid_check = hashes.Hash(hashes.SHA256())
        txid_check.update(self.sender_hash)
        txid_check.update(self.recipient_hash)
        txid_check.update(self.sender_public_key)
        txid_check.update(self.amount.to_bytes(8, byteorder = 'little', signed = False))
        txid_check.update(self.fee.to_bytes(8, byteorder = 'little', signed = False))
        txid_check.update(self.nonce.to_bytes(8, byteorder = 'little', signed = False))
        txid_check.update(self.signature)
        txid_check = txid_check.finalize()

        if self.txid != txid_check:
            raise ValueError('txid is not a match')


        # verification of signature
        sign_check = hashes.Hash(hashes.SHA256())
        sign_check.update(self.recipient_hash)
        sign_check.update((self.amount).to_bytes(8, byteorder = 'little', signed = False))
        sign_check.update((self.fee).to_bytes(8, byteorder = 'little', signed = False))
        sign_check.update((self.nonce).to_bytes(8, byteorder = 'little', signed = False))
        sign_check = sign_check.finalize()

        # private and public key
        private_key = ec.generate_private_key(ec.SECP256K1)
        public_key = private_key.public_key()
        # sign
        signature_hash = private_key.sign(sign_check, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        # verify
        public_key.verify(signature_hash, sign_check, ec.ECDSA(utils.Prehashed(hashes.SHA256())))







def create_signed_transaction(sender_private_key, recipient_hash, amount, fee, nonce):

        '''
        
        '''
        
        sender_public_key = create_public_key(sender_private_key)
        sender_hash = create_sender_hash(sender_public_key)
        signature = bytes.fromhex("ca388e0890b71bd1775460d478f26af3776c9b4f6c2b936e1e788c5c87657bc3")

        txid = create_txid(sender_hash, recipient_hash, sender_public_key, amount, fee, nonce, signature)

        return Transaction(sender_hash, recipient_hash, sender_public_key, amount, fee, nonce, signature, txid)



def create_txid(sender_hash, recipient_hash, sender_public_key, amount, fee, nonce, signature):
        '''
        
        '''
        # get hash of other fields to check txid
        txid_builder = hashes.Hash(hashes.SHA256())
        txid_builder.update(sender_hash)
        txid_builder.update(recipient_hash)
        txid_builder.update(sender_public_key.public_bytes(encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo))
        txid_builder.update(amount.to_bytes(8, byteorder = 'little', signed = False))
        txid_builder.update(fee.to_bytes(8, byteorder = 'little', signed = False))
        txid_builder.update(nonce.to_bytes(8, byteorder = 'little', signed = False))
        txid_builder.update(signature)
        txid_builder = txid_builder.finalize()

        return txid_builder


def create_private_key():
    '''
    Generates and returns a private key

    input : None
    output : ec.SECP256K1 private key
    '''

    return ec.generate_private_key(ec.SECP256K1)

def create_public_key(private_key):
    '''
    Generates and returns a public key based on private key
    input : private key
    output : public key
    '''
    public_key = private_key.public_key()
    return public_key

def create_sender_hash(sender_public_key):
    '''
    Generates sender hash
    '''
    # check sender_hash should is SHA-1 hash of sender_public_key
    sender_public_key_hash = hashes.Hash(hashes.SHA1())
    sender_public_key_hash.update(sender_public_key.public_bytes(encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo))
    #sender_public_key_hash = sender_public_key_hash.finalize()
    return sender_public_key_hash.finalize()

    # # sign
    # signature_hash = private_key.sign(sign_check, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    # # verify
    # public_key.verify(signature_hash, sign_check, ec.ECDSA(utils.Prehashed(hashes.SHA256())))

# tester = Transaction(
# bytes.fromhex("3df8f04b3c159fdc6631c4b8b0874940344d173d"),
# bytes.fromhex("5c1499a0484ace2f731b0afb83241e15f0e168ca"),
# bytes.fromhex("3056301006072a8648ce3d020106052b8104000a03420004886ed03cb7ffd4cbd95579ea2e202f1db29afc3bf5d7c2c34a34701bbb0685a7b535f1e631373afe8d1c860a9ac47d8e2659b74d437435b05f2c55bf3f033ac1"), 
# 10,
# 2,
# 5, 
# bytes.fromhex("3046022100f9c076a72a2341a1b8cb68520713e12f173378cf78cf79c7978a2337fbad141d022100ec27704d4d604f839f99e62c02e65bf60cc93ae1735c1ccf29fd31bd3c5a40ed"),
# bytes.fromhex("ca388e0890b71bd1775460d478f26af3776c9b4f6c2b936e1e788c5c87657bc3")
# )
        

# private_key = create_private_key()
# x = create_signed_transaction(private_key, bytes.fromhex("5c1499a0484ace2f731b0afb83241e15f0e168ca"), 10, 2, 5)
