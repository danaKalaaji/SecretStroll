"""
Skeleton credential module for implementing PS credentials

The goal of this skeleton is to help you implementing PS credentials. Following
this API is not mandatory and you can change it as you see fit. This skeleton
only provides major functionality that you will need.

You will likely have to define more functions and/or classes. In particular, to
maintain clean code, we recommend to use classes for things that you want to
send between parties. You can then use `jsonpickle` serialization to convert
these classes to byte arrays (as expected by the other classes) and back again.

We also avoided the use of classes in this template so that the code more closely
resembles the original scheme definition. However, you are free to restructure
the functions provided to resemble a more object-oriented interface.
"""

from typing import Any, List, Tuple, Dict

from serialization import jsonpickle

from petrelic.multiplicative.pairing import G1, G2, GT, G1Element, G2Element, GTElement
from petrelic.bn import Bn

import hashlib


# Type hint aliases
# Feel free to change them as you see fit.
# Maybe at the end, you will not need aliases at all!
Attribute = str
ProofKnowledge = Tuple[int, int, int]
SecretKey = Tuple[int, G1Element, List[int], List[Attribute]]
PublicKey = Tuple[G1Element, List[G1Element], G2Element, G2Element, List[G2Element], List[Attribute]]
Signature = Tuple[G1Element, G1Element]
AttributeMap = Dict[Attribute, bytes]
IssueRequest = Tuple[G1Element, ProofKnowledge]
BlindSignature = Tuple[Signature, AttributeMap]
AnonymousCredential = Tuple[Signature, List[bytes]]
DisclosureProof = Tuple[Signature, List[Attribute], List[bytes], ProofKnowledge]



######################
## HELPER FUNCTIONS ##
######################


def to_int(
    byte: bytes
    ) -> int:

    """Converts a byte into an int

    Args:
        byte: byte to be converted

    Returns:
        resulting int
    """

    return int.from_bytes(byte, "big") & (2**64-1) # TODO check this 64b limit of petrlic


def proof_of_knowledge1(                
    g: G1Element,
    p: Bn,
    Ys: List[G1Element],
    C: G1Element,
    t: G1Element,
    attributes: List[Attribute],
    user_attributes_values: AttributeMap
    ) -> ProofKnowledge:

    """Creates the proof of knowledge used in the issuance protocol

    Args:
        g: generator of the group G1
        p: order of the group G1
        Ys: 2nd element of the public key
        C: commitment
        t: secret
        attributes: list of attributes
        user_attributes_values: map of the attributes

    Returns:
        Non interactive proof that C has been computed correctly
    """

    user_attributes = [att for att in attributes if att in user_attributes_values.keys()]

    r_t = p.random()
    r_as = [p.random() for _ in range(len(user_attributes_values))]

    R = (g**r_t) * G1.prod([Ys[attributes.index(att)]**r_as[user_attributes.index(att)] 
        for att in user_attributes])

    to_hash = jsonpickle.encode((g, Ys, C, R))
    c = to_int(hashlib.sha256(to_hash.encode()).digest())      #not random hash

    s_t = (r_t - c * t) % p
    s_as = [(r_as[user_attributes.index(att)] - c * to_int(user_attributes_values[att])) % p
        for att in user_attributes] 

    Yrs = [Ys[attributes.index(att)]**r_as[user_attributes.index(att)]
        for att in user_attributes]

    Ycs = [Ys[attributes.index(att)]**(c*to_int(user_attributes_values[att]))
        for att in user_attributes]

    return c, s_t, s_as


def verify_proof_of_knowledge1(                      
    g: G1Element,
    Ys: List[G1Element],
    user_attributes: List[Attribute],
    attributes: List[Attribute],
    C: G1Element,
    c: int,
    s_t: int,
    s_as: int
    ) -> bool:

    """Verifies the proof of knowledge used in the issuance protocol

    Args:
        g: generator of the group G1
        Ys: 2nd element of the public key
        user_attributes: list of user's attributes
        attributes: list of attributes
        C: commit
        c: challenge
        s_t: value computed in the proof based on secret t
        s_as: value computed in the proof based on the attributes values


    Returns:
        True if the verification was a success
    """

    R_ = (C**c) * (g**s_t) * G1.prod([Ys[attributes.index(att)]**s_as[user_attributes.index(att)]
        for att in user_attributes])

    to_hash = jsonpickle.encode((g, Ys, C, R_))
    c_ = to_int(hashlib.sha256(to_hash.encode()).digest())     #not random hash

    if c != c_:
        print("Zero-proof verification 1 failed")
        return False
    else:
        return True

def proof_of_knowledge2(
    o_: Signature,
    g_: G2Element,
    p: Bn,
    Ys_: List[G2Element],
    C: GTElement,
    t: int,
    attributes: List[Attribute],
    attributes_values: List[bytes],
    hidden_attributes: List[Attribute],
    message: bytes
    ) -> ProofKnowledge:

    """Creates the proof of knowledge used in the showing protocol

    Args:
        o_: signature
        g_: generator of the group G2
        p: order of the group G2
        Ys_: 5th element of the public key 
        C: commitment
        t: secret
        attributes: list of attributes
        attributes_values: map of the attributes
        hidden_attributes: list of attributes hidden to the verifier
        message: message to include in the hash

    Returns:
        Non interactive proof that o_ is a valid signature
    """

    r_t = p.random()
    r_as = [p.random() for _ in range(len(hidden_attributes))]

    R = ((o_[0].pair(g_))**r_t) * GT.prod([ (o_[0].pair(Ys_[attributes.index(att)]))**r_as[hidden_attributes.index(att)] 
    for att in hidden_attributes])

    to_hash = jsonpickle.encode((g_, Ys_, C, R, message))
    c = to_int(hashlib.sha256(to_hash.encode()).digest())      #not random hash

    s_t = (r_t - c * t) % p
    s_as = [(r_as[hidden_attributes.index(att)] - c * to_int(attributes_values[attributes.index(att)])) % p
        for att in hidden_attributes]

    return c, s_t, s_as


def verify_proof_of_knowledge2(
    o_: Signature,
    g_: G2Element,
    Ys_: List[G2Element],
    attributes: List[Attribute],
    hidden_attributes: List[Attribute],
    C: GTElement,
    c: int,
    s_t: int,
    s_as: int,
    message: bytes
    ) -> bool:

    """Verifies the proof of knowledge used in the showing protocol

    Args:
        o_: signature
        g_: generator of the group G2
        Ys_: 5th element of the public key 
        attributes: list of attributes
        hidden_attributes: list of attributes hidden to the verifier
        C: commitment
        c: challenge
        s_t: value computed in the proof based on secret t
        s_as: value computed in the proof based on the attributes values
        message: message to include in the hash

    Returns:
        True if o_ is a valid signature
    """

    R_ = (C**c) * ((o_[0].pair(g_))**s_t) * GT.prod([ (o_[0].pair(Ys_[attributes.index(att)]))**s_as[hidden_attributes.index(att)] 
        for att in hidden_attributes])

    to_hash = jsonpickle.encode((g_, Ys_, C, R_, message))
    c_ = to_int(hashlib.sha256(to_hash.encode()).digest())      #not random hash

    if c != c_:
        print("Zero-proof verification 2 failed")
        return False
    else:
        return True



######################
## SIGNATURE SCHEME ##
######################


def generate_key(
        attributes: List[Attribute]
    ) -> Tuple[SecretKey, PublicKey]:
    """ Generate signer key pair """

    """
        Assuming that the attributes does not contain duplicates
    """

    p = G1.order()
    L = len(attributes)

    x = p.random()

    ys = [p.random() for _ in range(L)]

    g  = G1.generator()
    g_ = G2.generator()

    X  = g**x
    X_ = g_**x

    Ys = [g**y  for y in ys]
    Ys_= [g_**y for y in ys]

    pk = (g, Ys, g_, X_, Ys_, attributes) #added attributes to pk and sk
    sk = (x, X, ys, attributes)

    return (sk, pk)


def sign(
        sk: SecretKey,
        msgs: List[bytes]
    ) -> Signature:
    """ Sign the vector of messages `msgs` """
    h = G1.generator()
    x = sk[0]
    ys = sk[2]

    sum_ym = sum([y * to_int(msg) for (y, msg) in zip(ys, msgs)])

    return (h, h**(x + sum_ym))



def verify(
        pk: PublicKey,
        signature: Signature,
        msgs: List[bytes]
    ) -> bool:
    """ Verify the signature on a vector of messages """
    if signature[0].is_neutral_element():
        print("Signature verification failed: h is the neutral element")
        return false

    X_  = pk[3]
    Ys_ = pk[4]

    X_Ys_ = X_ * G2.prod([Y_**to_int(msg) for (Y_, msg) in zip(Ys_, msgs)])

    return signature[0].pair(X_Ys_) == signature[1].pair(pk[2])


#################################
## ATTRIBUTE-BASED CREDENTIALS ##
#################################

## ISSUANCE PROTOCOL ##

def create_issue_request(
        pk: PublicKey,
        user_attributes: AttributeMap
    ) -> Tuple[IssueRequest, int]:
    """ Create an issuance request

    This corresponds to the "user commitment" step in the issuance protocol.

    *Warning:* You may need to pass state to the `obtain_credential` function.
 
    Assuming that we trust the user in user_attributes, we consider the list of
    keys to be the actual list of user defined attributes
    """

    p = G1.order()
    t = p.random()
    g = pk[0]
    Ys = pk[1]
    attributes = pk[5]

    #Ys and user_attributes might not be the same length 
    C = (g**t) * G1.prod([Ys[attributes.index(att)]**to_int(user_attributes[att])
        for att in user_attributes.keys()])

    pi = proof_of_knowledge1(g, p, Ys, C, t, attributes, user_attributes)

    return (C, pi), t



def sign_issue_request(
        sk: SecretKey,
        pk: PublicKey,
        request: IssueRequest,
        issuer_attributes: AttributeMap
    ) -> BlindSignature:

    """ Create a signature corresponding to the user's request
    This corresponds to the "Issuer signing" step in the issuance protocol.
    """
    p = G1.order()
    u = p.random()
    X = sk[1]
    g = pk[0]
    Ys = pk[1]
    attributes = pk[5]

    C, pi = request
    c, s_t, s_as = pi

    user_attributes = [att for att in attributes if att not in issuer_attributes.keys()]

    if verify_proof_of_knowledge1(g, Ys, user_attributes, attributes, C, c, s_t, s_as):
        #Ys and user_attributes might not be the same length 
        XCYs = X * C * G1.prod([Ys[attributes.index(att)]**to_int(issuer_attributes[att])
            for att in issuer_attributes.keys()])

        o_ = (g**u, XCYs**u) #G1Element

        return (o_, issuer_attributes) 
    else:
        return None



def obtain_credential(
        pk: PublicKey,
        response: BlindSignature,
        user_attributes: AttributeMap,
        t: int
    ) -> AnonymousCredential:

    """ Derive a credential from the issuer's response
    This corresponds to the "Unblinding signature" step.
    """

    attributes = pk[5]
    o_, issuer_attributes = response

    o = (o_[0], o_[1]/(o_[0]**t)) #G1Element

    attributes_values = [user_attributes[att] if att in user_attributes else issuer_attributes[att] \
        for att in attributes]

    if verify(pk, o, attributes_values):
        credential = (o, attributes_values)
        return credential
    else:
        return None



## SHOWING PROTOCOL ##

def create_disclosure_proof(
        pk: PublicKey,
        credential: AnonymousCredential,
        hidden_attributes: List[Attribute],
        message: bytes
    ) -> DisclosureProof:
    """ Create a disclosure proof """

    p = G1.order()
    r = p.random()
    t = p.random()
    g_ = pk[2]
    X_ = pk[3]
    Ys_ = pk[4]
    attributes = pk[5]

    o, attributes_values = credential

    disclosed_attributes = [att for att in attributes if att not in hidden_attributes]

    o_ = ( o[0]**r, (o[1] * (o[0]**t))** r ) #G1Element

    C = ((o_[1].pair(g_))/(o_[0].pair(X_))) * GT.prod([ (o_[0].pair(Ys_[attributes.index(att)]))**(-to_int(attributes_values[attributes.index(att)]))
        for att in disclosed_attributes])

    pi = proof_of_knowledge2(o_, g_, p, Ys_, C, t, attributes, attributes_values, hidden_attributes, message)

    disclosed_attributes_values = [attributes_values[attributes.index(att)] for att in disclosed_attributes]

    return (o_, disclosed_attributes, disclosed_attributes_values, pi)



def verify_disclosure_proof(
        pk: PublicKey,
        disclosure_proof: DisclosureProof,
        message: bytes
    ) -> bool:
    """ Verify the disclosure proof

    Hint: The verifier may also want to retrieve the disclosed attributes
    """
    
    g_ = pk[2]
    X_ = pk[3]
    Ys_ = pk[4]
    attributes = pk[5]

    o_, disclosed_attributes, disclosed_attributes_values, pi = disclosure_proof
    c, s_t, s_as = pi

    hidden_attributes = [att for att in attributes if att not in disclosed_attributes]

    C = ((o_[1].pair(g_))/(o_[0].pair(X_))) * GT.prod([ (o_[0].pair(Ys_[attributes.index(att)]))**(-to_int(disclosed_attributes_values[disclosed_attributes.index(att)])) 
        for att in disclosed_attributes])

    if o_[0].is_neutral_element():
        print("Disclosure Proof verification failed: o_[0] is the neutral element")
        return false

    return verify_proof_of_knowledge2(o_, g_, Ys_, attributes, hidden_attributes, C, c, s_t, s_as, message)
