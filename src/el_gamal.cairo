from starkware.cairo.common.ec_point import EcPoint
// struct EcPoint {
//     x: felt,
//     y: felt,
// }
from starkware.cairo.common.ec import StarkCurve

struct EGCipher {
    c1: EcPoint,
    c2: EcPoint,
}

/// Maps a ciphertext non-injectively to a field element for hashing.
//
// Arguments:
//   cipher - an EGCipher
//
// Returns:
//   elem - the sum of the underlying felts for the EGCipher
func convert(cipher: EGCipher*) -> (elem: felt) {
    // unwrap felts a1, a2, b1, b2 from cipher.c1 and cipher.c2
    let a = cast(cipher.c1,EcPoint);
    let b = cast(cipher.c2,EcPoint);
    let a1 = a.x;
    let a2 = a.y;
    let b1 = b.x;
    let b2 = b.y;

    return (elem=a1+a2+b1+b2);
}