from credential import *
import numpy as np
import time

def eval_key_gen(iterations, attributes):
	times = []

	for _ in range(iterations):
		start = time.time_ns()

		sk, pk = generate_key(attributes)
		
		end = time.time_ns()
		times.append((end-start)/10**6)

	mean = np.mean(times)
	std_error = np.std(times, ddof=1)/np.sqrt(len(times))
	print(f"Key gen   takes an average of {mean:6.3f}ms with standard error of mean {std_error:6.3f}ms")


def eval_issuance(iterations, sk, pk, user_attributes, issuer_attributes):
	times = []

	for _ in range(iterations):
		start = time.time_ns()
		
		request, t = create_issue_request(pk, user_attributes)
		response = sign_issue_request(sk, pk, request, issuer_attributes)
		credential = obtain_credential(pk, response, user_attributes, t)

		end = time.time_ns()
		times.append((end-start)/10**6)

	mean = np.mean(times)
	std_error = np.std(times, ddof=1)/np.sqrt(len(times))
	print(f"Issuance  takes an average of {mean:6.3f}ms with standard error of mean {std_error:6.3f}ms")


def eval_showing(iterations, pk, credential, hidden_attributes, message):
	times = []

	for _ in range(iterations):
		start = time.time_ns()
		
		disclosure_proof = create_disclosure_proof(pk, credential, hidden_attributes, message)

		end = time.time_ns()
		times.append((end-start)/10**6)

	mean = np.mean(times)
	std_error = np.std(times, ddof=1)/np.sqrt(len(times))
	print(f"Showing   takes an average of {mean:6.3f}ms with standard error of mean {std_error:6.3f}ms")


def eval_verifying(iterations, pk, disclosure_proof, message):
	times = []

	for _ in range(iterations):
		start = time.time_ns()

		success = verify_disclosure_proof(pk, disclosure_proof, message)

		end = time.time_ns()
		times.append((end-start)/10**6)

	mean = np.mean(times)
	std_error = np.std(times, ddof=1)/np.sqrt(len(times))
	print(f"Verifying takes an average of {mean:6.3f}ms with standard error of mean {std_error:6.3f}ms")


def main():
	iterations = 50

	attributes = ["why", "so", "serious", "huh", "?", "??"]
	msgs = [b"I", b"am", b"finishing", b"this", b"super", b"late"]

	eval_key_gen(iterations, attributes)

	sk, pk = generate_key(attributes)

	user_attributes = {att: att[::-1].encode() for att in attributes[:3]}
	issuer_attributes = {att: att[::-1].encode() for att in attributes[3:]}

	eval_issuance(iterations, sk, pk, user_attributes, issuer_attributes)

	request, t = create_issue_request(pk, user_attributes)
	response = sign_issue_request(sk, pk, request, issuer_attributes)
	credential = obtain_credential(pk, response, user_attributes, t)
	
	message = b"We will we will rock you"
	hidden_attributes = attributes[2:5]

	eval_showing(iterations, pk, credential, hidden_attributes, message)
	
	disclosure_proof = create_disclosure_proof(pk, credential, hidden_attributes, message)

	eval_verifying(iterations, pk, disclosure_proof, message)

	success = verify_disclosure_proof(pk, disclosure_proof, message)


if __name__ == '__main__':
	main()