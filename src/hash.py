import hashlib

# double sha256
def hash(message):
    '''two rounds of sha256'''
    return hashlib.sha256(message).digest()


# double sha256
def hash256(message):
    '''two rounds of sha256'''
    return hashlib.sha256(hashlib.sha256(message).digest()).digest()

