# import necessary libraries
#from typing import Dict, List
from time import time
import math
from transaction import Transaction

from cryptography.hazmat.primitives import hashes


#### Helper code ####

## Note - creates node on merkle tree
def calculation_of_block_id_of_miner(previous, miner, transactions, timestamp, difficulty, nonce):
    """
    Check and verify block id of the miner
    input: previous, miner, transactions, timestamp, difficulty, nonce
    output: hashed block id
    """
    hash_id = hashes.Hash(hashes.SHA256())  
    # compile all relevant information for hashing
    hash_id.update(b''.join([previous, 
                            miner, 
                            # Concatenate all txids of transactions
                            b''.join([v.txid for v in transactions]), 
                            # 8 byte encode timestamp
                            timestamp.to_bytes(8, byteorder='little', signed = False), 
                            # 16 byte encode difficulty 
                            difficulty.to_bytes(16, byteorder='little', signed = False),
                            # 8 byte encode nonce
                            nonce.to_bytes(8, byteorder='little', signed = False)])) 
    new_block_id = hash_id.finalize()
    
    return new_block_id
####  ####

def get_target(difficulty):
    """
    Returns target based on difficulty
    input : difficulty
    output : target
    """
    return 2**256 // difficulty

####  ####

####  End of helper code #### 



# Creation of UserState class
class UserState:
    # initiate UserState class
    def __init__(self, balance, nonce):
        self.balance = balance
        self.nonce = nonce


# Creation of Block class
class Block:
    # initiate Block class
    def __init__(self, previous, height, miner, transactions, timestamp, difficulty, block_id="", nonce=""):
        self.previous = previous
        self.height = height
        self.miner = miner
        self.transactions = transactions
        self.timestamp = timestamp
        self.difficulty = difficulty
        self.block_id = block_id
        self.nonce = nonce

        
    # function to verify and make changes    
    def verify_and_get_changes(self, difficulty, previous_user_states):   
        """
        Function to verify and make changes to user state
        input : difficulty, previous_user_states
        output : dictionary with states in chain
        """  
        # Verify difficulty matches one provided as argument
        if difficulty != self.difficulty:
            raise Exception("Difficulties do not match")
        
        # Check block id is correct
        block_id = calculation_of_block_id_of_miner(self.previous, self.miner, self.transactions, 
                                                    self.timestamp, self.difficulty, self.nonce)                                        
        if  block_id != self.block_id:
            raise Exception("Block id is incorrect")
        
        # Check list of transactions has max length of 25
        if len(self.transactions) > 25:
            raise Exception("Amount of transactions exceeds limit")
         
        # Check miner field is 20 bytes
        if len(self.miner) != 20:
            raise Exception("Miner field if not 20 bytes")
         
        #  Check block_id is small enough to match block difficulty
        target = get_target(difficulty)
        block_id_int = int(block_id.hex(), 16)
        if block_id_int > target:
            raise Exception("Invalid proof of work")
             
        # create states from imput previous_user_states
        all_states_in_block = previous_user_states
        
        # iterate through the transaction list to process trancations
        for transaction in self.transactions:
            
            # verify the transaction through Transaction.verify() method
            transaction.verify(all_states_in_block[transaction.sender_hash].balance,
                              all_states_in_block[transaction.sender_hash].nonce)
            
            # add recipient_hash to state dictionary
            if transaction.recipient_hash not in all_states_in_block.keys():
                all_states_in_block[transaction.recipient_hash] = UserState(0,-1)
            else:
                all_states_in_block[transaction.recipient_hash].balance += transaction.amount - transaction.fee
            
            # add sender_hash to state dictionary
            if transaction.sender_hash not in all_states_in_block.keys():
                all_states_in_block[transaction.sender_hash].nonce += 1
                all_states_in_block[transaction.sender_hash].balance += transaction.amount
            else:
                all_states_in_block[transaction.sender_hash] = UserState(0,-1)
        
            # add miner to state dictionary
            if self.miner not in all_states_in_block.keys():
                all_states_in_block[self.miner].balance += transaction.fee
            else:
                all_states_in_block[self.miner] = UserState(0,-1)
        
        # grant reward
        if self.miner not in all_states_in_block.keys():
            all_states_in_block[self.miner] = UserState(10000,-1)
        else:
            all_states_in_block[self.miner].balance += 10000
        
        return all_states_in_block
        

# function for mining block
def mine_block(previous, height, miner, transactions, timestamp, difficulty):
    '''
    Function to mine a block.

    input: previous, height, miner, transactions, timestamp, difficulty
    output: block object of Block class
    '''

    # Initialize block 
    base_block = Block(previous, height, miner, transactions,timestamp, difficulty)
    
    # set initial nonce at zero 
    nonce = 0
    
    # create hash digest for block id
    digest = hashes.Hash(hashes.SHA256())
    digest.update(b''.join([previous, 
                            miner, 
                            b''.join([transaction.txid for transaction in transactions]), 
                            timestamp.to_bytes(8, byteorder='little'), 
                            difficulty.to_bytes(16, byteorder='little')]))
    
    
    ## loop through  iterations increasing nonce by 1 to find correct nonce where block id is <= target
    target = get_target(difficulty)
    while True:
        nonce += 1
        #nonce_bytes = int(nonce).to_bytes(8, byteorder = 'little', signed = False)
        full_hash = digest.copy()
        full_hash.update(nonce.to_bytes(8, byteorder = 'little', signed = False))
        block_id = full_hash.finalize() #block_id, SHA-256 hash 
        block_id_int = int(block_id.hex(), 16)
        # break loop when a block id is found <= the target
        if block_id_int <= target:
            print(block_id.hex(),nonce)
            break
            
    # return complete block including block_id and nonce
    return Block(previous, height, miner, transactions,timestamp, difficulty, block_id, nonce)