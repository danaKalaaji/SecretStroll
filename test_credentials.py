from credential import *

####################
### generate_key ###
####################

def test_generate_key():
   
   attributes = ["D","a","n","a"]

   sk, pk = generate_key(attributes)

   g, Ys, g_, X_, Ys_, attributes1 = pk
   x, X, ys, attributes2 = sk


   assert attributes1 == attributes2
   assert attributes1 == attributes
   assert len(ys) == len(attributes)
   assert X == g ** x 
   assert X_ == g_ ** x 
   assert Ys == [g**y  for y in ys]
   assert Ys_== [g_**y for y in ys]


############
### sign ###
############

def test_sign():

   attributes = ["how","why","what","?"]
   msgs = [b"hello", b"nice", b"to", b"meet"]
   sk, _ = generate_key(attributes)
   x = sk[0]
   ys = sk[2]

   h, val = sign(sk, msgs)

   sum_ym = sum([y * to_int(msg) for (y, msg) in zip(ys, msgs)])

   assert val == h**(x + sum_ym)


#######################
### sign and verify ###
#######################

def test_sign_verify_success():

   attributes = ["why", "so", "serious", "huh", "?", "??"]
   msgs = [b"I", b"am", b"finishing", b"this", b"super", b"late"]
   sk, pk = generate_key(attributes)

   signature = sign(sk, msgs)

   assert verify(pk, signature, msgs)


def test_sign_verify_fail1():

   attributes = ["why", "so", "serious", "huh", "?", "??"]
   msgs = [b"I", b"am", b"finishing", b"this", b"super", b"late"]
   sk, pk = generate_key(attributes)

   signature = sign(sk, msgs)

   fake_msgs = [b"It", b"is", b"3", b"pm", b"right", b"now"]

   assert not verify(pk, signature, fake_msgs)


def test_sign_verify_fail2():

   attributes = ["why", "so", "serious", "huh", "?", "??"]
   msgs = [b"I", b"am", b"finishing", b"this", b"super", b"late"]
   sk, pk = generate_key(attributes)
   g, Ys, g_, X_, Ys_, attributes1 = pk
   signature = sign(sk, msgs)
   p = G1.order()
   L = len(attributes)

   fake_ys = [p.random() for _ in range(L)]
   fake_Ys_ = [g_**y for y in fake_ys]
   fake_pk = g, Ys, g_, X_, fake_Ys_, attributes1

   assert not verify(fake_pk, signature, msgs)


def test_sign_verify_fail3():

   attributes = ["why", "so", "serious", "huh", "?", "??"]
   msgs = [b"I", b"am", b"finishing", b"this", b"super", b"late"]
   sk, pk = generate_key(attributes)

   signature = sign(sk, msgs)
   h, val = signature

   fake_h = h**2
   fake_signature = (fake_h, val)

   assert not verify(pk, fake_signature, msgs)

###################################################
### create_issue_request and sign_issue_request ###
###################################################

def test_create_sign_issue_request_success():

   attributes = ["why", "so", "serious", "huh", "?", "??"]
   msgs = [b"I", b"am", b"finishing", b"this", b"super", b"late"]
   sk, pk = generate_key(attributes)

   user_attributes = {att: att[::-1].encode() for att in attributes[:3]}
   issuer_attributes = {att: att[::-1].encode() for att in attributes[3:]}

   # User side
   request, _ = create_issue_request(pk, user_attributes)

   # Issuer side
   response = sign_issue_request(sk, pk, request, issuer_attributes)

   assert response is not None


def test_create_sign_issue_request_fail1():

   attributes = ["why", "so", "serious", "huh", "?", "??"]
   msgs = [b"I", b"am", b"finishing", b"this", b"super", b"late"]
   sk, pk = generate_key(attributes)
   x, X, ys, attributes1 = sk
   p = G1.order()
   L = len(attributes)

   user_attributes = {att: att[::-1].encode() for att in attributes[:3]}
   issuer_attributes = {att: att[::-1].encode() for att in attributes[3:]}

   # User side
   request, _ = create_issue_request(pk, user_attributes)

   fake_sk, fake_pk = generate_key(attributes)

   # Issuer side
   response = sign_issue_request(fake_sk, fake_pk, request, issuer_attributes)

   assert response is None


def test_create_sign_issue_request_fail2():

   attributes = ["why", "so", "serious", "huh", "?", "??"]
   msgs = [b"I", b"am", b"finishing", b"this", b"super", b"late"]
   sk, pk = generate_key(attributes)
   p = G1.order()
   L = len(attributes)

   user_attributes = {att: att[::-1].encode() for att in attributes[:3]}
   issuer_attributes = {att: att[::-1].encode() for att in attributes[3:]}

   # User side
   request, _ = create_issue_request(pk, user_attributes)
   C, pi = request

   fake_C = C**2
   fake_request = fake_C, pi

   # Issuer side
   response = sign_issue_request(sk, pk, fake_request, issuer_attributes)

   assert response is None


#########################
### obtain_credential ###
#########################

def test_obtain_credential():

   attributes = ["why", "so", "serious", "huh", "?", "??"]
   msgs = [b"I", b"am", b"finishing", b"this", b"super", b"late"]
   sk, pk = generate_key(attributes)

   user_attributes = {att: att[::-1].encode() for att in attributes[:3]}
   issuer_attributes = {att: att[::-1].encode() for att in attributes[3:]}

   request, t = create_issue_request(pk, user_attributes)
   response = sign_issue_request(sk, pk, request, issuer_attributes)

   credential = obtain_credential(pk, response, user_attributes, t)

   assert credential is not None


def test_obtain_credential_fail1():

   attributes = ["why", "so", "serious", "huh", "?", "??"]
   msgs = [b"I", b"am", b"finishing", b"this", b"super", b"late"]
   sk, pk = generate_key(attributes)

   user_attributes = {att: att[::-1].encode() for att in attributes[:3]}
   issuer_attributes = {att: att[::-1].encode() for att in attributes[3:]}

   request, t = create_issue_request(pk, user_attributes)
   response = sign_issue_request(sk, pk, request, issuer_attributes)

   _, fake_pk = generate_key(attributes)

   credential = obtain_credential(fake_pk, response, user_attributes, t)

   assert credential is None


def test_obtain_credential_fail2():

   attributes = ["why", "so", "serious", "huh", "?", "??"]
   msgs = [b"I", b"am", b"finishing", b"this", b"super", b"late"]
   sk, pk = generate_key(attributes)

   user_attributes = {att: att[::-1].encode() for att in attributes[:3]}
   issuer_attributes = {att: att[::-1].encode() for att in attributes[3:]}

   request, t = create_issue_request(pk, user_attributes)
   response = sign_issue_request(sk, pk, request, issuer_attributes)

   fake_user_attributes = {att: att.encode() for att in attributes[:3]}

   credential = obtain_credential(pk, response, fake_user_attributes, t)

   assert credential is None


def test_obtain_credential_fail3():

   attributes = ["why", "so", "serious", "huh", "?", "??"]
   msgs = [b"I", b"am", b"finishing", b"this", b"super", b"late"]
   sk, pk = generate_key(attributes)
   p = G1.order()

   user_attributes = {att: att[::-1].encode() for att in attributes[:3]}
   issuer_attributes = {att: att[::-1].encode() for att in attributes[3:]}

   request, t = create_issue_request(pk, user_attributes)
   response = sign_issue_request(sk, pk, request, issuer_attributes)

   fake_t = p.random()

   credential = obtain_credential(pk, response, user_attributes, fake_t)

   assert credential is None


def test_obtain_credential_fail4():

   attributes = ["why", "so", "serious", "huh", "?", "??"]
   msgs = [b"I", b"am", b"finishing", b"this", b"super", b"late"]
   sk, pk = generate_key(attributes)
   p = G1.order()

   user_attributes = {att: att[::-1].encode() for att in attributes[:3]}
   issuer_attributes = {att: att[::-1].encode() for att in attributes[3:]}

   request, t = create_issue_request(pk, user_attributes)
   response = sign_issue_request(sk, pk, request, issuer_attributes)
   o_, issuer_attributes = response

   fake_issuer_attributes = {att: att[1::].encode() for att in attributes[3:]}
   fake_response = (o_, fake_issuer_attributes)

   credential = obtain_credential(pk, fake_response, user_attributes, t)

   assert credential is None


###########################################################
### create_disclosure_proof and verify_disclosure_proof ###
###########################################################

def test_create_verify_disclosure_proof():
   attributes = ["why", "so", "serious", "huh", "?", "??"]
   msgs = [b"I", b"am", b"finishing", b"this", b"super", b"late"]
   sk, pk = generate_key(attributes)

   user_attributes = {att: att[::-1].encode() for att in attributes[:3]}
   issuer_attributes = {att: att[::-1].encode() for att in attributes[3:]}

   hidden_attributes = attributes[2:5]
   message = b"We will we will rock you"

   request, t = create_issue_request(pk, user_attributes)
   response = sign_issue_request(sk, pk, request, issuer_attributes)

   credential = obtain_credential(pk, response, user_attributes, t)

   disclosure_proof = create_disclosure_proof(pk, credential, hidden_attributes, message)

   assert verify_disclosure_proof(pk, disclosure_proof, message)


def test_create_verify_disclosure_proof_fail1():
   attributes = ["why", "so", "serious", "huh", "?", "??"]
   msgs = [b"I", b"am", b"finishing", b"this", b"super", b"late"]
   sk, pk = generate_key(attributes)

   user_attributes = {att: att[::-1].encode() for att in attributes[:3]}
   issuer_attributes = {att: att[::-1].encode() for att in attributes[3:]}

   hidden_attributes = attributes[2:5]
   message = b"We will we will rock you"

   request, t = create_issue_request(pk, user_attributes)
   response = sign_issue_request(sk, pk, request, issuer_attributes)

   credential = obtain_credential(pk, response, user_attributes, t)

   disclosure_proof = create_disclosure_proof(pk, credential, hidden_attributes, message)

   _, fake_pk = generate_key(attributes)   

   assert not verify_disclosure_proof(fake_pk, disclosure_proof, message)


def test_create_verify_disclosure_proof_fail2():
   attributes = ["why", "so", "serious", "huh", "?", "??"]
   msgs = [b"I", b"am", b"finishing", b"this", b"super", b"late"]
   sk, pk = generate_key(attributes)

   user_attributes = {att: att[::-1].encode() for att in attributes[:3]}
   issuer_attributes = {att: att[::-1].encode() for att in attributes[3:]}

   hidden_attributes = attributes[2:5]
   message = b"We will we will rock you"

   request, t = create_issue_request(pk, user_attributes)
   response = sign_issue_request(sk, pk, request, issuer_attributes)

   credential = obtain_credential(pk, response, user_attributes, t)

   disclosure_proof = create_disclosure_proof(pk, credential, hidden_attributes, message)

   fake_message = b"Dont...stop...me nowww"  

   assert not verify_disclosure_proof(pk, disclosure_proof, fake_message)


def test_create_verify_disclosure_proof_fail3():
   attributes = ["why", "so", "serious", "huh", "?", "??"]
   msgs = [b"I", b"am", b"finishing", b"this", b"super", b"late"]
   sk, pk = generate_key(attributes)

   user_attributes = {att: att[::-1].encode() for att in attributes[:3]}
   issuer_attributes = {att: att[::-1].encode() for att in attributes[3:]}

   hidden_attributes = attributes[2:5]
   message = b"We will we will rock you"

   request, t = create_issue_request(pk, user_attributes)
   response = sign_issue_request(sk, pk, request, issuer_attributes)

   credential = obtain_credential(pk, response, user_attributes, t)

   disclosure_proof = create_disclosure_proof(pk, credential, hidden_attributes, message)
   o_, disclosed_attributes, disclosed_attributes_values, pi = disclosure_proof

   fake_o_ = (o_[0]**2, o_[1])
   fake_disclosure_proof = (fake_o_, disclosed_attributes, disclosed_attributes_values, pi) 

   assert not verify_disclosure_proof(pk, fake_disclosure_proof, message)
