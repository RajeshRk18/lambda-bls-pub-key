use lambdaworks_math::cyclic_group::IsGroup;
use lambdaworks_math::elliptic_curve::short_weierstrass::curves::bls12_381::field_extension::BLS12381_PRIME_FIELD_ORDER;
use lambdaworks_math::elliptic_curve::short_weierstrass::curves::bls12_381::{
    curve::BLS12381Curve, twist::BLS12381TwistCurve,
};
use lambdaworks_math::elliptic_curve::short_weierstrass::point::ShortWeierstrassProjectivePoint;
use lambdaworks_math::elliptic_curve::traits::IsEllipticCurve;
use lambdaworks_math::unsigned_integer::element::UnsignedInteger;

// This variant is used when public key size needs to be reduced(48 bytes)
// and signature size is 96 bytes (an element of G_2)
// This is used in signature aggregation scheme where  multiple public keys are to be communicacted
fn g1_pub_key(secret_key: &str) -> ShortWeierstrassProjectivePoint<BLS12381Curve> {
    let gen = BLS12381Curve::generator();

    let sk_elem = UnsignedInteger::<6>::from_hex_unchecked(secret_key);

    // Range check
    assert!(sk_elem < BLS12381_PRIME_FIELD_ORDER);

    gen.operate_with_self(sk_elem).to_affine()
}

// This variant is used when signature size needs to be reduced (48 bytes)
// and public key size is 96 bytes
fn g2_pub_key(secret_key: &str) -> ShortWeierstrassProjectivePoint<BLS12381TwistCurve> {
    let gen = BLS12381TwistCurve::generator();

    let sk_elem = UnsignedInteger::<6>::from_hex_unchecked(secret_key);

    // Range check 
    assert!(sk_elem < BLS12381_PRIME_FIELD_ORDER);

    gen.operate_with_self(sk_elem).to_affine()
}

fn main() {
    let secret_key = "0x6C616D6264617370";

    // Public key using variant1 from https://datatracker.ietf.org/doc/html/draft-boneh-bls-signature-00#section-2
    println!("{:x}", g2_pub_key(secret_key));

    // Public key using variant2 from https://datatracker.ietf.org/doc/html/draft-boneh-bls-signature-00#section-2
    println!("{:?}", g1_pub_key(secret_key));

}
