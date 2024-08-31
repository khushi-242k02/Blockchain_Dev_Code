from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

def generate_keys():
    # generating public and private key

    private = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public = private.public_key()   #in-built functions
    return private,public

def sign(message,private):
    # signing my message with my private key
    message = bytes(str(message),'utf-8') #converting message to bytes
    signature = private.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verification(message,sig,public):
    message = bytes(str(message), 'utf-8')  # converting message to bytes
    try:
        public.verify(
            sig,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    except:
        print("Error executing public key")
        return False


if __name__=='__main__':
    pr,pu=generate_keys()
    print(pr)
    print(pu)

    message="I have sent 5 eth to A"
    sig = sign(message,pr)
    print(sig)

    correct = verification(message,sig,pu)
    if correct:
        print("Successful")
    else:
        print("Failed")


