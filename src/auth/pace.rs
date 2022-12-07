use sha1::{Sha1, Digest};
use sha2::{Sha256, Sha512};

pub struct HashAlg {
	pub name: &'static str,
	pub hash: for<'a> fn(&'a [u8]) -> Vec<u8>,
	pub descriptor: &'static [u8],
}

pub const HASH_SHA1: HashAlg = HashAlg { name: "SHA-1", hash: |input| Sha1::digest(input).to_vec(), descriptor: &[0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A] };
pub const HASH_SHA256: HashAlg = HashAlg { name: "SHA-256", hash: |input| Sha256::digest(input).to_vec(), descriptor: &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01] };
pub const HASH_SHA512: HashAlg = HashAlg { name: "SHA-512", hash: |input| Sha512::digest(input).to_vec(), descriptor: &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03] };
pub const HASHES: [HashAlg; 3] = [ HASH_SHA1, HASH_SHA256, HASH_SHA512 ];

pub struct PaceAlg {
	pub name: &'static str,
	// pub keygen: for<'a> fn(&'a [u8]) -> Vec<u8>,
	pub descriptor: &'static [u8],
}

pub const PACEALG_DH_GM_3DES_CBC_CBC: PaceAlg = PaceAlg { name: "DH, Generic Mapping, 3DES-CBC-CBC", descriptor: &[0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x01, 0x01] };
pub const PACEALG_DH_GM_AES_CMAC_128: PaceAlg = PaceAlg { name: "DH, Generic Mapping, AES-CMAC-128", descriptor: &[0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x01, 0x02] };
pub const PACEALG_DH_GM_AES_CMAC_192: PaceAlg = PaceAlg { name: "DH, Generic Mapping, AES-CMAC-192", descriptor: &[0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x01, 0x03] };
pub const PACEALG_DH_GM_AES_CMAC_256: PaceAlg = PaceAlg { name: "DH, Generic Mapping, AES-CMAC-256", descriptor: &[0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x01, 0x04] };
pub const PACEALG_DH_IM_3DES_CBC_CBC: PaceAlg = PaceAlg { name: "DH, Integrated Mapping, 3DES-CBC-CBC", descriptor: &[0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x03, 0x01] };
pub const PACEALG_DH_IM_AES_CMAC_128: PaceAlg = PaceAlg { name: "DH, Integrated Mapping, AES-CMAC-128", descriptor: &[0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x03, 0x02] };
pub const PACEALG_DH_IM_AES_CMAC_192: PaceAlg = PaceAlg { name: "DH, Integrated Mapping, AES-CMAC-192", descriptor: &[0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x03, 0x03] };
pub const PACEALG_DH_IM_AES_CMAC_256: PaceAlg = PaceAlg { name: "DH, Integrated Mapping, AES-CMAC-256", descriptor: &[0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x03, 0x04] };
pub const PACEALG_ECDH_GM_3DES_CBC_CBC: PaceAlg = PaceAlg { name: "ECDH, Generic Mapping, 3DES-CBC-CBC", descriptor: &[0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x01] };
pub const PACEALG_ECDH_GM_AES_CMAC_128: PaceAlg = PaceAlg { name: "ECDH, Generic Mapping, AES-CMAC-128", descriptor: &[0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x02] };
pub const PACEALG_ECDH_GM_AES_CMAC_192: PaceAlg = PaceAlg { name: "ECDH, Generic Mapping, AES-CMAC-192", descriptor: &[0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x03] };
pub const PACEALG_ECDH_GM_AES_CMAC_256: PaceAlg = PaceAlg { name: "ECDH, Generic Mapping, AES-CMAC-256", descriptor: &[0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x04] };
pub const PACEALG_ECDH_IM_3DES_CBC_CBC: PaceAlg = PaceAlg { name: "ECDH, Integrated Mapping, 3DES-CBC-CBC", descriptor: &[0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x04, 0x01] };
pub const PACEALG_ECDH_IM_AES_CMAC_128: PaceAlg = PaceAlg { name: "ECDH, Integrated Mapping, AES-CMAC-128", descriptor: &[0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x04, 0x02] };
pub const PACEALG_ECDH_IM_AES_CMAC_192: PaceAlg = PaceAlg { name: "ECDH, Integrated Mapping, AES-CMAC-192", descriptor: &[0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x04, 0x03] };
pub const PACEALG_ECDH_IM_AES_CMAC_256: PaceAlg = PaceAlg { name: "ECDH, Integrated Mapping, AES-CMAC-256", descriptor: &[0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x04, 0x04] };
pub const PACEALGS: [PaceAlg; 16] = [ PACEALG_DH_GM_3DES_CBC_CBC, PACEALG_DH_GM_AES_CMAC_128, PACEALG_DH_GM_AES_CMAC_192, PACEALG_DH_GM_AES_CMAC_256, PACEALG_ECDH_GM_3DES_CBC_CBC, PACEALG_ECDH_GM_AES_CMAC_128, PACEALG_ECDH_GM_AES_CMAC_192, PACEALG_ECDH_GM_AES_CMAC_256, PACEALG_DH_IM_3DES_CBC_CBC, PACEALG_DH_IM_AES_CMAC_128, PACEALG_DH_IM_AES_CMAC_192, PACEALG_DH_IM_AES_CMAC_256, PACEALG_ECDH_IM_3DES_CBC_CBC, PACEALG_ECDH_IM_AES_CMAC_128, PACEALG_ECDH_IM_AES_CMAC_192, PACEALG_ECDH_IM_AES_CMAC_256 ];

pub struct PaceSdp {
	pub id: u8,
	pub name: &'static str,
	pub size: u16,
}

pub const PACESDP_DH_GROUP22: PaceSdp = PaceSdp { id: 0, name: "1024-bit MODP Group with 160-bit Prime Order Subgroup", size: 1024 };
pub const PACESDP_DH_GROUP23: PaceSdp = PaceSdp { id: 1, name: "2048-bit MODP Group with 224-bit Prime Order Subgroup", size: 2048 };
pub const PACESDP_DH_GROUP24: PaceSdp = PaceSdp { id: 2, name: "2048-bit MODP Group with 256-bit Prime Order Subgroup", size: 2048 };
pub const PACESDP_SECP192R1: PaceSdp = PaceSdp { id: 8, name: "NIST P-192 (secp192r1)", size: 192 };
pub const PACESDP_SECP224R1: PaceSdp = PaceSdp { id: 10, name: "NIST P-224 (secp224r1)", size: 224 };
pub const PACESDP_SECP256R1: PaceSdp = PaceSdp { id: 12, name: "NIST P-256 (secp256r1)", size: 256 };
pub const PACESDP_SECP384R1: PaceSdp = PaceSdp { id: 15, name: "NIST P-384 (secp384r1)", size: 384 };
pub const PACESDP_SECP521R1: PaceSdp = PaceSdp { id: 18, name: "NIST P-521 (secp521r1)", size: 521 };
pub const PACESDP_BRAINPOOLP192R1: PaceSdp = PaceSdp { id: 9, name: "BrainpoolP192r1", size: 192 };
pub const PACESDP_BRAINPOOLP224R1: PaceSdp = PaceSdp { id: 11, name: "BrainpoolP224r1", size: 224 };
pub const PACESDP_BRAINPOOLP256R1: PaceSdp = PaceSdp { id: 13, name: "BrainpoolP256r1", size: 256 };
pub const PACESDP_BRAINPOOLP320R1: PaceSdp = PaceSdp { id: 14, name: "BrainpoolP320r1", size: 320 };
pub const PACESDP_BRAINPOOLP384R1: PaceSdp = PaceSdp { id: 16, name: "BrainpoolP384r1", size: 384 };
pub const PACESDP_BRAINPOOLP521R1: PaceSdp = PaceSdp { id: 17, name: "BrainpoolP521r1", size: 521 };
pub const PACESDPS: [PaceSdp; 14] = [ PACESDP_DH_GROUP22, PACESDP_DH_GROUP23, PACESDP_DH_GROUP24, PACESDP_SECP192R1, PACESDP_SECP224R1, PACESDP_SECP256R1, PACESDP_SECP384R1, PACESDP_SECP521R1, PACESDP_BRAINPOOLP192R1, PACESDP_BRAINPOOLP224R1, PACESDP_BRAINPOOLP256R1, PACESDP_BRAINPOOLP320R1, PACESDP_BRAINPOOLP384R1, PACESDP_BRAINPOOLP521R1 ];