from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import EcOpBuiltin, HashBuiltin
from starkware.cairo.common.ec import StarkCurve, ec_mul, ec_add
from starkware.cairo.common.ec_point import EcPoint
from starkware.cairo.common.hash_chain import hash_chain

from src.el_gamal import EGCipher

struct BallotProof {
    cipher0: EGCipher, // (a_0,b_0)
    cipher1: EGCipher, // (a_1,b_1)
    c_0: felt, 
    c_1: felt,
    v_0: felt,
    v_1: felt,
}

// Checks the NIZK proof equations that a ciphertext hides a zero or one.
//
// Arguments:
//   proof - a pointer to the proof values
//   cipher - a pointer to the ciphertext to validate
//   tal_pub_key - the tallier public key ec point
func check_proof{ec_op_ptr: EcOpBuiltin*, hash_ptr: HashBuiltin*}(
    proof: BallotProof*, cipher: EGCipher*, tal_pub_key: EcPoint
) {
    alloc_locals;

    local gen_point:EcPoint = EcPoint(
        x=StarkCurve.GEN_X,
        y=StarkCurve.GEN_Y
    );
    
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

    // form hash values to compute challenge c
    let (local data_ptr) = alloc();
    assert [data_ptr] = 14;
    assert [data_ptr+1] = tal_pub_key.x; // K
    assert [data_ptr+2] = tal_pub_key.y;
    assert [data_ptr+3] = alpha.x; // alpha
    assert [data_ptr+4] = alpha.y;
    assert [data_ptr+5] = beta.x; // beta
    assert [data_ptr+6] = beta.y;
    assert [data_ptr+7] = a0.x; // a_0
    assert [data_ptr+8] = a0.y;
    assert [data_ptr+9] = b0.x; // b_0
    assert [data_ptr+10] = b0.y;
    assert [data_ptr+11] = a1.x; // a_1
    assert [data_ptr+12] = a1.y;
    assert [data_ptr+13] = b1.x; // b_1
    assert [data_ptr+14] = b1.y;
    let (digest) = hash_chain(data_ptr=data_ptr); // h(14, h(K.x, h(...
    local challenge;
    %{
        EC_ORDER = 3618502788666131213697322783095070105526743751716087489154079457884512865583
        ids.challenge = (ids.c_0 + ids.c_1) % EC_ORDER
    %}
    assert digest = challenge;

    // assert challenge was computed correctly
    // assert_nn_le(challenge,order); // assert challenge < ORDER
    // assert_lt(c_0,order); // assert c_0 < ORDER
    // assert_lt(c_1,order); // assert c_1 < ORDER // 340282366920938463463374607431768211456 range check bound
    let check_rhs:EcPoint = ec_mul(challenge,gen_point);
    check_equation(c_0,gen_point,c_1,gen_point,check_rhs); // assert c_0 * G + c_1 * G = c * G

    check_equation(v_0,gen_point,c_0,alpha,a0); // assert v_0 * G + c_0 * alpha = a_0

    check_equation(v_0,tal_pub_key,c_0,beta,b0); // assert v_0 * K + c_0 * beta = b_0

    check_equation(v_1,gen_point,c_1,alpha,a1); // assert v_1 * G + c_1 * alpha = a_1

    // let diff = v_1 - c_1;
    local diff;
    %{
        EC_ORDER = 3618502788666131213697322783095070105526743751716087489154079457884512865583
        ids.diff = (ids.v_1 - ids.c_1) % EC_ORDER
    %}
    check_equation(diff,tal_pub_key,c_1,beta,b1); // assert (v_1-c_1) * K + c_1 * beta = b_1

    // assert diff was computed correctly
    // assert_lt(diff,order); // assert diff < ORDER
    // assert_lt(v_1,order); // assert v_1 < ORDER
    let check_rhs:EcPoint = ec_mul(v_1,gen_point);
    check_equation(diff,gen_point,c_1,gen_point,check_rhs); // assert diff * G + c_1 * G = v_1 * G

    return ();
}

// Checks one of the above equations for the NIZK proof:
// t1 * P1 + t2 * P2 = check_rhs
func check_equation{ec_op_ptr: EcOpBuiltin*}(
    t1: felt, p1: EcPoint, t2: felt, p2: EcPoint, check_rhs: EcPoint
) {
    alloc_locals;
    let (local check_1) = ec_mul(t1,p1); // t1 * P1
    let (local check_2) = ec_mul(t2,p2); // t2 * P2
    let check_lhs = ec_add(check_1,check_2); // t1 * P1 + t2 * P2
    equal_points(check_lhs.r,check_rhs);
    return ();
}

// Asserts that two elliptic curve points are equal
func equal_points(p1: EcPoint, p2: EcPoint) {
    assert p1.x = p2.x;
    assert p1.y = p2.y; 
    return ();
}