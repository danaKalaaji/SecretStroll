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

from typing import Any, List, Tuple

from serialization import jsonpickle

from petrelic.multiplicative.pairing import G1, G2, GT


# Type hint aliases
# Feel free to change them as you see fit.
# Maybe at the end, you will not need aliases at all!
SecretKey = Any
PublicKey = Any
Signature = Any
Attribute = String
AttributeMap = Any
IssueRequest = Any
BlindSignature = Any
AnonymousCredential = Any
DisclosureProof = Any



######################
## HELPER FUNCTIONS ##
######################


def to_int(byte):
    return int.from_bytes(byte, "big")


######################
## SIGNATURE SCHEME ##
######################


def generate_key(
        attributes: List[Attribute]
    ) -> Tuple[SecretKey, PublicKey]:
    """ Generate signer key pair """
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

    return (pk, sk)


def sign(
        sk: SecretKey,
        msgs: List[bytes]
    ) -> Signature:
    """ Sign the vector of messages `msgs` """
    h = G1.generator()
    x = sk[0]

    sum_ym = sum([y * to_int(msg) for (y, msg) in zip(ys, msgs)])

    return (h, h**(x + sum_ym))



def verify(
        pk: PublicKey,
        signature: Signature,
        msgs: List[bytes]
    ) -> bool:
    """ Verify the signature on a vector of messages """
    if signature[0].is_neutral_element()
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
    ) -> IssueRequest:
    """ Create an issuance request

    This corresponds to the "user commitment" step in the issuance protocol.

    *Warning:* You may need to pass state to the `obtain_credential` function.
    """
    raise NotImplementedError()


def sign_issue_request(
        sk: SecretKey,
        pk: PublicKey,
        request: IssueRequest,
        issuer_attributes: AttributeMap
    ) -> BlindSignature:
    """ Create a signature corresponding to the user's request

    This corresponds to the "Issuer signing" step in the issuance protocol.
    """
    raise NotImplementedError()


def obtain_credential(
        pk: PublicKey,
        response: BlindSignature
    ) -> AnonymousCredential:
    """ Derive a credential from the issuer's response

    This corresponds to the "Unblinding signature" step.
    """
    raise NotImplementedError()


## SHOWING PROTOCOL ##

def create_disclosure_proof(
        pk: PublicKey,
        credential: AnonymousCredential,
        hidden_attributes: List[Attribute],
        message: bytes
    ) -> DisclosureProof:
    """ Create a disclosure proof """
    raise NotImplementedError()


def verify_disclosure_proof(
        pk: PublicKey,
        disclosure_proof: DisclosureProof,
        message: bytes
    ) -> bool:
    """ Verify the disclosure proof

    Hint: The verifier may also want to retrieve the disclosed attributes
    """
    raise NotImplementedError()
