%builtins output pedersen ec_op

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.bool import TRUE
from starkware.cairo.common.ec import ec_add
from starkware.cairo.common.ec_point import EcPoint
from starkware.cairo.common.cairo_builtins import HashBuiltin, EcOpBuiltin
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.hash_chain import hash_chain
from starkware.cairo.common.serialize import serialize_word
from starkware.cairo.common.signature import check_ecdsa_signature

from src.el_gamal import EGCipher, convert
from src.ballot_proofs import BallotProof, check_proof

func main{output_ptr: felt*, pedersen_ptr: HashBuiltin*, ec_op_ptr: EcOpBuiltin*}() {
    alloc_locals;

    // allocate input arrays and values
    let (pk_list, cipher_list, proof_list, signature_list, tal_pub_key_ref, n_ciphers, hiding_value) = get_inputs();

    // dereference the tal_pub_key
    local tal_pub_key: EcPoint = EcPoint(x=tal_pub_key_ref.x,y=tal_pub_key_ref.y);

    // assert predicates for each tuple of public keys, ciphers, and ballot proofs
    check_predicates{hash_ptr=pedersen_ptr}(
        pk_list, cipher_list, proof_list, signature_list, tal_pub_key, n_ciphers
    );
    // drop pairs that fail checks?

    // generate & output head for public keys
    let (head) = hash2{hash_ptr=pedersen_ptr}(0,'head of keys');
    serialize_word(head);
    // form key list structure from leaves for hash_chain
    let (local data_ptr) = alloc();
    assert [data_ptr] = n_ciphers+1;
    form_key_leaves{hash_ptr=pedersen_ptr}(
        data_ptr=data_ptr+1, pk_list=pk_list, n_keys=n_ciphers,head=head
    );
    // construct hash chain and output root
    let (root) = hash_chain{hash_ptr=pedersen_ptr}(data_ptr=data_ptr);
    serialize_word(root);

    // generate & output head' for ciphertexts
    let (head) = hash2{hash_ptr=pedersen_ptr}(0,'ciphertext head');
    serialize_word(head);
    // form ciphertext list structure from leaves for hash_chain
    let (local data_ptr) = alloc();
    assert [data_ptr] = n_ciphers+1;
    form_cipher_leaves{hash_ptr=pedersen_ptr}(
        data_ptr=data_ptr+1, cipher_list=cipher_list, n_ciphers=n_ciphers,head=head
    );
    // construct hash chain and output root
    let (root) = hash_chain{hash_ptr=pedersen_ptr}(data_ptr=data_ptr);
    // compose the committed root value with the secret hiding value
    let output = root * hiding_value;
    serialize_word(output);

    // find & output product ciphertext
    let (prod_c1,prod_c2) = find_product(
        cipher_list=cipher_list, n_ciphers=n_ciphers
    );
    serialize_word(prod_c1.x);
    serialize_word(prod_c1.y);
    serialize_word(prod_c2.x);
    serialize_word(prod_c2.y);
    
    return ();
}

// Asserts the predicates for each tuple of public keys, ciphertexts, and ballot proofs.
//
// Arguments:
//   pk_list - a pointer to a field element list
//   cipher_list - a pointer to a ciphertext list
//   proof_list - a pointer to a ballot proof list
//   tal_pub_key - the tallier public key curve point.
//   n_ciphers - the number of ciphertexts
func check_predicates{ec_op_ptr: EcOpBuiltin*, hash_ptr: HashBuiltin*}(
    pk_list: EcPoint*, 
    cipher_list: EGCipher*, 
    proof_list: BallotProof*,
    signature_list: EcPoint*, 
    tal_pub_key: EcPoint, 
    n_ciphers
) {
    if (n_ciphers == 0) {
        return ();
    }

    // check individual tuple
    verify_tuple(
        pk=pk_list, 
        cipher=cipher_list, 
        proof=proof_list, 
        signature=signature_list, 
        tal_pub_key=tal_pub_key
    );

    // call check_predicates recursively
    check_predicates(
        pk_list=pk_list+EcPoint.SIZE, 
        cipher_list=cipher_list+EGCipher.SIZE,
        proof_list=proof_list+BallotProof.SIZE,
        signature_list=signature_list+EcPoint.SIZE,
        tal_pub_key=tal_pub_key,
        n_ciphers=n_ciphers-1,
    );
    return ();
}

// Asserts a predicate for the input public key, ciphertext, ballot proof, and signature.
//
// Arguments:
//   pk - public key to verify
//   cipher - ciphertext to verify
//   proof - ballot proof to verify
func verify_tuple{ec_op_ptr: EcOpBuiltin*, hash_ptr: HashBuiltin*}(
    pk: EcPoint*, 
    cipher: EGCipher*, 
    proof: BallotProof*, 
    signature: EcPoint*, 
    tal_pub_key: EcPoint
) {
    alloc_locals;

    // unpack proof values and ciphertext
    local alpha:EcPoint = cast(cipher.c1,EcPoint);
    local beta:EcPoint = cast(cipher.c2,EcPoint);

    local cipher0:EGCipher* = cast(proof,EGCipher*);
    local cipher1:EGCipher* = cast(proof + EGCipher.SIZE, EGCipher*);
    local a0:EcPoint = cast(cipher0.c1,EcPoint);
    local b0:EcPoint = cast(cipher0.c2,EcPoint);
    local a1:EcPoint = cast(cipher1.c1,EcPoint);
    local b1:EcPoint = cast(cipher1.c2,EcPoint);

    local c_0 = proof.c_0;
    local c_1 = proof.c_1;
    local v_0 = proof.v_0;
    local v_1 = proof.v_1;

    // form message from hash chain of inputs
    let (local data_ptr) = alloc();
    assert [data_ptr] = 16;
    assert [data_ptr+1] = alpha.x; // K
    assert [data_ptr+2] = alpha.y;
    assert [data_ptr+3] = beta.x; // alpha
    assert [data_ptr+4] = beta.y;
    assert [data_ptr+5] = a0.x; // beta
    assert [data_ptr+6] = a0.y;
    assert [data_ptr+7] = b0.x; // a_0
    assert [data_ptr+8] = b0.y;
    assert [data_ptr+9] = a1.x; // b_0
    assert [data_ptr+10] = a1.y;
    assert [data_ptr+11] = b1.x; // a_1
    assert [data_ptr+12] = b1.y;
    assert [data_ptr+13] = c_0; // b_1
    assert [data_ptr+14] = c_1;
    assert [data_ptr+15] = v_0;
    assert [data_ptr+16] = v_1;
    let message = hash_chain(data_ptr);
    
    // assert valid signature
    let (res) = check_ecdsa_signature(message.hash,pk.x,signature.x,signature.y);
    assert res = TRUE;

    // check the NIZK proof for ballot correctness
    check_proof(proof,cipher,tal_pub_key);

    return ();
}

// Finds the total product of all of the input ciphertexts
//
// Arguments:
//   cipher_list - a pointer to the list of ciphertexts
//   n_ciphers - the number of ciphers in the list
//
// Returns:
//   product_c1 - the ec point representing the sum ciphertext c1
//   product_c2 - the ec point representing the sum ciphertext c2
func find_product(
    cipher_list: EGCipher*, n_ciphers
) -> (product_c1: EcPoint,product_c2: EcPoint) {
    alloc_locals;
    if (n_ciphers == 0) {
        return (
            product_c1=EcPoint(x=0,y=0),
            product_c2=EcPoint(x=0,y=0),
        );
    }

    local c1:EcPoint = cast(cipher_list.c1,EcPoint);
    local c2:EcPoint = cast(cipher_list.c2,EcPoint);
    let (local rest_prod_c1, local rest_prod_c2) = find_product(
        cipher_list=cipher_list+EGCipher.SIZE,
        n_ciphers=n_ciphers-1,
    );
    let final_c1 = ec_add(p=c1,q=rest_prod_c1);
    let final_c2 = ec_add(p=c2,q=rest_prod_c2);
    return (product_c1=final_c1.r, product_c2=final_c2.r);
}

// Constructs a list of leaves for hash_chain from the input list of public keys
//
// Arguments:
//   data_ptr - a pointer for the cells to write to
//   pk_list - a pointer to the list of public keys
//   n_keys - the number of keys in the list
//   head - the value of head to write to the last cell
//
// Returns:
//   data_ptr - the pointer to the next cell to write to after the function is applied
func form_key_leaves{hash_ptr: HashBuiltin*}(
    data_ptr:felt*, pk_list:EcPoint*, n_keys, head
) -> (data_ptr:felt*) {
    if (n_keys == 0) {
        assert [data_ptr] = head;
        return (data_ptr = data_ptr+1);
    }

    // hash current key to form next leaf
    let pk_x = pk_list.x;
    let pk_y = pk_list.y;
    let digest = hash2(pk_x,pk_y);
    assert [data_ptr] = digest.result;

    // call form_leaves recursively
    return form_key_leaves(
        data_ptr=data_ptr+1,
        pk_list=pk_list+EcPoint.SIZE,
        n_keys=n_keys-1,
        head=head,    
    );
}

// Constructs a list of leaves for hash_chain from the input list of ciphertexts
//
// Arguments:
//   data_ptr - a pointer for the cells to write to
//   cipher_list - a pointer to the list of ciphertexts
//   n_ciphers - the number of ciphers in the list
//   head - the value of head to write to the last cell
//
// Returns:
//   data_ptr - the pointer to the next cell to write to after the function is applied
func form_cipher_leaves{hash_ptr: HashBuiltin*}(
    data_ptr:felt*, cipher_list:EGCipher*, n_ciphers, head
) -> (data_ptr:felt*) {
    if (n_ciphers == 0) {
        assert [data_ptr] = head;
        return (data_ptr = data_ptr+1);
    }

    // hash current cipher to form next leaf
    let cipher_element = convert(cipher_list);
    let digest = hash2(0,cipher_element.elem);
    assert [data_ptr] = digest.result;

    // call form_leaves recursively
    return form_cipher_leaves(
        data_ptr=data_ptr+1,
        cipher_list=cipher_list+EGCipher.SIZE,
        n_ciphers=n_ciphers-1,
        head=head,    
    );
}

// Fetches the tallier input data.
// The validity of the data is not guaranteed and must be verified by the caller.
func get_inputs() -> (
    pk_list: EcPoint*, 
    cipher_list: EGCipher*, 
    proof_list: BallotProof*, 
    signature_list: EcPoint*,
    tal_pub_key: EcPoint*,
    n_ciphers: felt,
    hiding_value: felt
) {
    alloc_locals;
    local n_ciphers;
    local hiding_value;
    let (tal_pub_key: EcPoint*) = alloc();
    let (pk_list: EcPoint*) = alloc();
    let (cipher_list: EGCipher*) = alloc();
    let (proof_list: BallotProof*) = alloc();
    let (signature_list: EcPoint*) = alloc();

    %{
    ids.n_ciphers = len(program_input["cipher_list"])
    ids.hiding_value = program_input["hiding_value"]

    memory[ids.tal_pub_key.address_ + ids.EcPoint.x] = program_input["tal_pub_key"][0]
    memory[ids.tal_pub_key.address_ + ids.EcPoint.y] = program_input["tal_pub_key"][1]

    for i,key in enumerate(program_input["pk_list"]):
        base_addr = ids.pk_list.address_ + ids.EcPoint.SIZE * i
        memory[base_addr + ids.EcPoint.x] = key[0]
        memory[base_addr + ids.EcPoint.y] = key[1]

    for i,cipher in enumerate(program_input["cipher_list"]):
        base_addr = ids.cipher_list.address_ + ids.EGCipher.SIZE * i
        memory[base_addr + ids.EGCipher.c1 + ids.EcPoint.x] = cipher[0][0]
        memory[base_addr + ids.EGCipher.c1 + ids.EcPoint.y] = cipher[0][1]
        memory[base_addr + ids.EGCipher.c2 + ids.EcPoint.x] = cipher[1][0]
        memory[base_addr + ids.EGCipher.c2 + ids.EcPoint.y] = cipher[1][1]

    for i,proof in enumerate(program_input["proof_list"]):
        base_addr = ids.proof_list.address_ + ids.BallotProof.SIZE * i
        memory[
            base_addr + ids.BallotProof.cipher0 + ids.EGCipher.c1 + ids.EcPoint.x
            ] = proof['cipher0'][0][0]
        memory[
            base_addr + ids.BallotProof.cipher0 + ids.EGCipher.c1 + ids.EcPoint.y
            ] = proof['cipher0'][0][1]
        memory[
            base_addr + ids.BallotProof.cipher0 + ids.EGCipher.c2 + ids.EcPoint.x
            ] = proof['cipher0'][1][0]
        memory[
            base_addr + ids.BallotProof.cipher0 + ids.EGCipher.c2 + ids.EcPoint.y
            ] = proof['cipher0'][1][1]
        memory[
            base_addr + ids.BallotProof.cipher1 + ids.EGCipher.c1 + ids.EcPoint.x
            ] = proof['cipher1'][0][0]
        memory[
            base_addr + ids.BallotProof.cipher1 + ids.EGCipher.c1 + ids.EcPoint.y
            ] = proof['cipher1'][0][1]
        memory[
            base_addr + ids.BallotProof.cipher1 + ids.EGCipher.c2 + ids.EcPoint.x
            ] = proof['cipher1'][1][0]
        memory[
            base_addr + ids.BallotProof.cipher1 + ids.EGCipher.c2 + ids.EcPoint.y
            ] = proof['cipher1'][1][1]
        memory[base_addr + ids.BallotProof.c_0] = proof['c_0']
        memory[base_addr + ids.BallotProof.c_1] = proof['c_1']
        memory[base_addr + ids.BallotProof.v_0] = proof['v_0']
        memory[base_addr + ids.BallotProof.v_1] = proof['v_1']

    for i,signature in enumerate(program_input["signature_list"]):
        base_addr = ids.signature_list.address_ + ids.EcPoint.SIZE * i
        memory[base_addr + ids.EcPoint.x] = signature[0]
        memory[base_addr + ids.EcPoint.y] = signature[1]
    
    # check lengths of the input arrays
    assert len(program_input["cipher_list"]) == len(program_input["pk_list"])
    assert len(program_input["cipher_list"]) == len(program_input["proof_list"])
    assert len(program_input["cipher_list"]) == len(program_input["signature_list"]) 
    %}

    return (pk_list,cipher_list,proof_list,signature_list,tal_pub_key,n_ciphers,hiding_value);
}