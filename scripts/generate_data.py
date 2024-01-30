import json
import sys
from typing import List
from secrets import randbelow

from starkware.crypto.signature.signature import private_key_to_ec_point_on_stark_curve, ECSignature, sign
from starkware.crypto.signature.math_utils import ECPoint, ec_mult, ec_add
from starkware.cairo.common.hash_chain import compute_hash_chain
# from starkware.cairo.common.poseidon_hash import poseidon_hash

### CONSTANTS
EC_GEN = (
    0x1EF15C18599971B7BECED415A40F0C7DEACFD9B0D1819E03D723D8BC943CFCA,
    0x5668060AA49730B7BE4801DF46EC62DE53ECD11ABE43A32873000C36E8DC1F,
)
ALPHA = 1
BETA = 3141592653589793238462643383279502884197169399375105820974944592307816406665
FIELD_PRIME = 3618502788666131213697322783095070105623107215331596699973092056135872020481
EC_ORDER = 3618502788666131213697322783095070105526743751716087489154079457884512865583

### MAIN FUNCTION
def main():
    num_voters = 2 ** int(sys.argv[1])
    out_file = "artifacts/" + str(sys.argv[2])
    tallier_sec_key = randbelow(EC_ORDER)
    tallier_pub_key = private_key_to_ec_point_on_stark_curve(tallier_sec_key)
    hiding_value = randbelow(EC_ORDER)

    pub_keys = []
    ciphers = []
    ballot_proofs = []
    signatures = []

    for _ in range(num_voters):
        priv_key = randbelow(EC_ORDER)
        pub_key = private_key_to_ec_point_on_stark_curve(priv_key)
        pub_keys.append(pub_key)

        # all voters vote 1 in example
        seed = randbelow(EC_ORDER)
        vote = True
        cipher = elgamal_enc(seed,vote,tallier_pub_key)
        ciphers.append(cipher)

        # produce the NIZK proof of ballot correctness
        (cipher0, cipher1, c_0, c_1, v_0, v_1) = prove_ballot(seed,tallier_pub_key,cipher,vote)
        ballot_proofs.append({
            'cipher0': cipher0,
            'cipher1': cipher1,
            'c_0': c_0,
            'c_1': c_1,
            'v_0': v_0,
            'v_1': v_1,
        })

        # sign the ballot ciphertext and NIZK proof
        signature = sign_ballot(cipher,cipher0,cipher1,c_0,c_1,v_0,v_1,priv_key)
        signatures.append(signature)
        
    # Write the data to a JSON file.
    input_data = {
        'tal_pub_key': tallier_pub_key,
        'hiding_value': hiding_value,
        'pk_list': pub_keys,
        'cipher_list': ciphers,
        'proof_list': ballot_proofs,
        'signature_list': signatures
    }
    
    with open(out_file, 'w') as f:
        json.dump(input_data, f, indent=4)
        f.write('\n')

### HELPER FUNCTIONS
# Encrypts a vote (0 or 1) into an ElGamal ciphertext of two ec points.
def elgamal_enc(seed:int, vote:bool, public_key:ECPoint) -> (ECPoint,ECPoint):
    c1 = ec_mult(seed, EC_GEN, ALPHA, FIELD_PRIME) # c1 = seed*EC_GEN

    if not vote:
        c2 = ec_mult(seed, public_key, ALPHA, FIELD_PRIME) # c2 = seed*K
    else:
        c2 = ec_mult(seed+1, public_key, ALPHA, FIELD_PRIME) # c2 = (seed+1)*K

    return (c1,c2)

# Signs a ballot and a NIZK proof with a voter secret key
def sign_ballot(
        ballot: (ECPoint,ECPoint), cipher0: (ECPoint,ECPoint), 
        cipher1: (ECPoint,ECPoint), c_0, c_1, v_0, v_1, voter_key
        ) -> ECSignature:
    to_hash = [
            16,
            ballot[0][0],ballot[0][1], # alpha
            ballot[1][0],ballot[1][1], # beta
            cipher0[0][0],cipher0[0][1], # a_0
            cipher0[1][0],cipher0[1][1], # b_0
            cipher1[0][0],cipher1[0][1], # a_1
            cipher1[1][0],cipher1[1][1], # b_1
            c_0, c_1, v_0, v_1
    ]
    message = compute_hash_chain(to_hash) 
    signature = sign(message,voter_key,None)
    return signature

# Given encryption nonce and ciphertext produces a NIZK proof that the ciphertext hides a 0 or 1
def prove_ballot(
        nonce: int, tal_pub_key:ECPoint, ballot: (ECPoint,ECPoint), vote: bool
    ) -> ((ECPoint,ECPoint),(ECPoint,ECPoint),int,int,int,int):
    # Randomly select integers u_0, u_1
    u_0 = randbelow(EC_ORDER)
    u_1 = randbelow(EC_ORDER)

    if not vote: # ballot hides vote 0
        # Randomly select integer c_1
        c_1 = randbelow(EC_ORDER)

        # Compute (a_0, b_0) and (a_1, b_1)
        cipher0 = (
            ec_mult(u_0,EC_GEN,ALPHA,FIELD_PRIME), # a_0 = u_0 * G
            ec_mult(u_0,tal_pub_key,ALPHA,FIELD_PRIME), # b_0 = u_0 * K
        )
        a1_term = (u_1-c_1) % EC_ORDER
        cipher1 = (
            ec_mult(u_1,EC_GEN,ALPHA,FIELD_PRIME), # a_1 = u_1 * G
            ec_mult(a1_term,tal_pub_key,ALPHA,FIELD_PRIME), # b_1 = (u_1-c_1) * K
        ) 

    else: # ballot hides vote 1
        # Randomly select integer c_0
        c_0 = randbelow(EC_ORDER)

        # Compute (a_0, b_0) and (a_1, b_1)
        b0_term = (u_0+c_0) % EC_ORDER
        cipher0 = (
            ec_mult(u_0,EC_GEN,ALPHA,FIELD_PRIME), # a_0 = u_0 * G
            ec_mult(b0_term,tal_pub_key,ALPHA,FIELD_PRIME), # b_0 = (u_0+c_0) * K
        )
        cipher1 = (
            ec_mult(u_1,EC_GEN,ALPHA,FIELD_PRIME), # a_1 = u_1 * G
            ec_mult(u_1,tal_pub_key,ALPHA,FIELD_PRIME), # b_1 = u_1 * K
        )
    
    # Compute challenge value c
    to_hash = [
        14,
        tal_pub_key[0],tal_pub_key[1], # K
        ballot[0][0],ballot[0][1], # alpha
        ballot[1][0],ballot[1][1], # beta
        cipher0[0][0],cipher0[0][1], # a_0
        cipher0[1][0],cipher0[1][1], # b_0
        cipher1[0][0],cipher1[0][1], # a_1
        cipher1[1][0],cipher1[1][1] # b_1
    ]
    c = compute_hash_chain(to_hash)

    if not vote:
        c_0 = (c - c_1) % EC_ORDER # c_0 = c - c_1
    else:
        c_1 = (c - c_0) % EC_ORDER # c_1 = c - c_0     

    # Compute the final values
    v_0 = (u_0 - (c_0 * nonce)) % EC_ORDER # v_0 = u_0 - c_0 * xi
    v_1 = (u_1 - (c_1 * nonce)) % EC_ORDER # v_1= u_1 - c_1 * xi

    # # Check that the equations hold
    assert c == ((c_0 + c_1) % EC_ORDER)

    assert cipher0[0] == ec_add(
        ec_mult(v_0,EC_GEN,ALPHA,FIELD_PRIME),
        ec_mult(c_0,ballot[0],ALPHA,FIELD_PRIME),
        FIELD_PRIME) # a_0 = v_0 * G + c_0 * alpha

    assert cipher0[1] == ec_add(
        ec_mult(v_0,tal_pub_key,ALPHA,FIELD_PRIME),
        ec_mult(c_0,ballot[1],ALPHA,FIELD_PRIME),
        FIELD_PRIME) # b_0 = v_0 * K + c_0 * beta

    assert cipher1[0] == ec_add(
        ec_mult(v_1,EC_GEN,ALPHA,FIELD_PRIME),
        ec_mult(c_1,ballot[0],ALPHA,FIELD_PRIME),
        FIELD_PRIME) # a_1 = v_1 * G + c_1 * alpha
    
    first_term = (v_1 - c_1) % EC_ORDER
    assert cipher1[1] == ec_add(
        ec_mult(first_term,tal_pub_key,ALPHA,FIELD_PRIME),
        ec_mult(c_1,ballot[1],ALPHA,FIELD_PRIME),
        FIELD_PRIME) # b_1 = (v_1-c_1) * K + c_1 * beta

    return (cipher0, cipher1, c_0, c_1, v_0, v_1)

### Run the main function:
if __name__ == "__main__":
    main()