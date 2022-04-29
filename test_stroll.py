from stroll import * 
import pytest

def test_stroll_success():

	subscriptions = ["bar", "cafe", "gym", "museum"]
	user_subscriptions = subscriptions[0:2]
	subscriptions.append("username")

	username = "My_username"

	sk_enc, pk_enc = Server.generate_ca(subscriptions)

	server = Server()
	client = Client()

	issuance_request, state = client.prepare_registration(pk_enc, username, user_subscriptions)

	response = server.process_registration(sk_enc, pk_enc, issuance_request, username, user_subscriptions)

	credentials = client.process_registration_response(pk_enc, response, state)

	disclosure_proof = client.sign_request(pk_enc, credentials, b"message", ["bar", "cafe"])

	verification = server.check_request_signature(pk_enc, b"message", ["bar", "cafe"], disclosure_proof)

	assert verification


def test_stroll_subset_of_subscription_success():
#verifies that we can create a showing proof on multiple attributes but request POI on a subset of them

	subscriptions = ["bar", "cafe", "gym", "museum"]
	user_subscriptions = subscriptions[0:2]
	subscriptions.append("username")

	username = "My_username"

	sk_enc, pk_enc = Server.generate_ca(subscriptions)

	server = Server()
	client = Client()

	issuance_request, state = client.prepare_registration(pk_enc, username, user_subscriptions)

	response = server.process_registration(sk_enc, pk_enc, issuance_request, username, user_subscriptions)

	credentials = client.process_registration_response(pk_enc, response, state)

	disclosure_proof = client.sign_request(pk_enc, credentials, b"message", ["bar", "cafe"])

	verification = server.check_request_signature(pk_enc, b"message", ["bar"], disclosure_proof)

	assert verification


def test_stroll_fail1():
#Verifying showing protocol with an altered message fails

	subscriptions = ["bar", "cafe", "gym", "museum"]
	user_subscriptions = subscriptions[0:2]
	subscriptions.append("username")

	username = "My_username"

	sk_enc, pk_enc = Server.generate_ca(subscriptions)

	server = Server()
	client = Client()

	issuance_request, state = client.prepare_registration(pk_enc, username, user_subscriptions)

	response = server.process_registration(sk_enc, pk_enc, issuance_request, username, user_subscriptions)

	credentials = client.process_registration_response(pk_enc, response, state)

	disclosure_proof = client.sign_request(pk_enc, credentials, b"message", ["bar", "cafe"])

	verification = server.check_request_signature(pk_enc, b"fake message", ["bar", "cafe"], disclosure_proof)

	assert not verification


def test_stroll_fail2():
#Requesting POI for valid attribute but not subscribed to fails

	subscriptions = ["bar", "cafe", "gym", "museum"]
	user_subscriptions = subscriptions[0:2]
	subscriptions.append("username")

	username = "My_username"

	sk_enc, pk_enc = Server.generate_ca(subscriptions)

	server = Server()
	client = Client()

	issuance_request, state = client.prepare_registration(pk_enc, username, user_subscriptions)

	response = server.process_registration(sk_enc, pk_enc, issuance_request, username, user_subscriptions)

	credentials = client.process_registration_response(pk_enc, response, state)

	disclosure_proof = client.sign_request(pk_enc, credentials, b"message", ["bar", "cafe", "gym"])

	verification = server.check_request_signature(pk_enc, b"message", ["bar", "cafe", "gym"], disclosure_proof)

	assert not verification


def test_stroll_fail3():
#Making a showing proof with altered keys fails

	subscriptions = ["bar", "cafe", "gym", "museum"]
	user_subscriptions = subscriptions[0:2]
	subscriptions.append("username")

	username = "My_username"

	sk_enc, pk_enc = Server.generate_ca(subscriptions)

	_, pk_enc_fake = Server.generate_ca(subscriptions)

	server = Server()
	client = Client()

	issuance_request, state = client.prepare_registration(pk_enc, username, user_subscriptions)

	response = server.process_registration(sk_enc, pk_enc, issuance_request, username, user_subscriptions)

	credentials = client.process_registration_response(pk_enc, response, state)

	disclosure_proof = client.sign_request(pk_enc_fake, credentials, b"message", ["bar", "cafe"])

	verification = server.check_request_signature(pk_enc_fake, b"message", ["bar", "cafe"], disclosure_proof)

	assert not verification


def test_stroll_fail4():
#Registering without username as attribute fails
	with pytest.raises(Exception):
		subscriptions = ["bar", "cafe", "gym", "museum"]
		user_subscriptions = subscriptions[0:2]

		username = "My_username"

		sk_enc, pk_enc = Server.generate_ca(subscriptions)

		server = Server()
		client = Client()

		issuance_request, state = client.prepare_registration(pk_enc, username, user_subscriptions)

		response = server.process_registration(sk_enc, pk_enc, issuance_request, username, user_subscriptions)


def test_stroll_fail5():
#Registring with an invalid attribute fails
	with pytest.raises(Exception):
		subscriptions = ["bar", "cafe", "gym", "museum"]
		user_subscriptions = subscriptions[0:2] + ["restaurant"]
		subscriptions.append("username")

		username = "My_username"

		sk_enc, pk_enc = Server.generate_ca(subscriptions)

		server = Server()
		client = Client()

		issuance_request, state = client.prepare_registration(pk_enc, username, user_subscriptions)


def test_stroll_fail6():
#Processing registration with an invalid attribute fails
	with pytest.raises(Exception):
		subscriptions = ["bar", "cafe", "gym", "museum"]
		user_subscriptions = subscriptions[0:2]
		subscriptions.append("username")

		username = "My_username"

		sk_enc, pk_enc = Server.generate_ca(subscriptions)

		server = Server()
		client = Client()

		issuance_request, state = client.prepare_registration(pk_enc, username, user_subscriptions)

		response = server.process_registration(sk_enc, pk_enc, issuance_request, username, user_subscriptions+["restaurant"])


def test_stroll_fail7():
#Verifying registration with an invalid attribute fails
	with pytest.raises(Exception):
		subscriptions = ["bar", "cafe", "gym", "museum"]
		user_subscriptions = subscriptions[0:2]
		subscriptions.append("username")

		username = "My_username"

		sk_enc, pk_enc = Server.generate_ca(subscriptions)

		server = Server()
		client = Client()

		issuance_request, state = client.prepare_registration(pk_enc, username, user_subscriptions)

		response = server.process_registration(sk_enc, pk_enc, issuance_request, username, user_subscriptions+["restaurant"])


def test_stroll_fail8():
#Getting credentials with altered state fails
	with pytest.raises(Exception):
		subscriptions = ["bar", "cafe", "gym", "museum"]
		user_subscriptions = subscriptions[0:2]
		subscriptions.append("username")

		username = "My_username"

		sk_enc, pk_enc = Server.generate_ca(subscriptions)

		server = Server()
		client = Client()

		issuance_request, state = client.prepare_registration(pk_enc, username, user_subscriptions)

		response = server.process_registration(sk_enc, pk_enc, issuance_request, username, user_subscriptions)

		credentials = client.process_registration_response(pk_enc, response, state*2)


def test_stroll_fail9():
#Creating disclosure proof with invalid argument fails
	with pytest.raises(Exception):
		subscriptions = ["bar", "cafe", "gym", "museum"]
		user_subscriptions = subscriptions[0:2]
		subscriptions.append("username")

		username = "My_username"

		sk_enc, pk_enc = Server.generate_ca(subscriptions)

		server = Server()
		client = Client()

		issuance_request, state = client.prepare_registration(pk_enc, username, user_subscriptions)

		response = server.process_registration(sk_enc, pk_enc, issuance_request, username, user_subscriptions)

		credentials = client.process_registration_response(pk_enc, response, state*2)

		disclosure_proof = client.sign_request(pk_enc, credentials, b"message", user_subscriptions+["restaurant"])


def test_stroll_fail10():
#Verifying disclosure proof with invalid argument fails
	with pytest.raises(Exception):
		subscriptions = ["bar", "cafe", "gym", "museum"]
		user_subscriptions = subscriptions[0:2]
		subscriptions.append("username")

		username = "My_username"

		sk_enc, pk_enc = Server.generate_ca(subscriptions)

		server = Server()
		client = Client()

		issuance_request, state = client.prepare_registration(pk_enc, username, user_subscriptions)

		response = server.process_registration(sk_enc, pk_enc, issuance_request, username, user_subscriptions)

		credentials = client.process_registration_response(pk_enc, response, state*2)

		disclosure_proof = client.sign_request(pk_enc, credentials, b"message", user_subscriptions)
	
		verification = server.check_request_signature(pk_enc, b"message", user_subscriptions+["restaurant"], disclosure_proof)
