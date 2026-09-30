package escp

import "encoding/hex"

// staticSBox is the post-KSA RC4 state used by the legacy static-key transport.
// It is fixed in every firmware and in the official utility (CVE-2017-8077).
var staticSBox = [256]byte{
	191, 155, 227, 202, 99, 162, 79, 104, 49, 18, 190, 164, 30, 76, 189, 131,
	23, 52, 86, 106, 207, 125, 126, 169, 196, 28, 172, 58, 188, 132, 160, 3,
	36, 120, 144, 168, 12, 231, 116, 44, 41, 97, 108, 213, 42, 198, 32, 148,
	218, 107, 247, 112, 204, 14, 66, 68, 91, 224, 206, 235, 33, 130, 203, 178,
	1, 134, 199, 78, 249, 123, 7, 145, 73, 208, 209, 100, 74, 115, 72, 118,
	8, 22, 243, 147, 64, 96, 5, 87, 60, 113, 233, 152, 31, 219, 143, 174,
	232, 153, 245, 158, 254, 70, 170, 75, 77, 215, 211, 59, 71, 133, 214, 157,
	151, 6, 46, 81, 94, 136, 166, 210, 4, 43, 241, 29, 223, 176, 67, 63,
	186, 137, 129, 40, 248, 255, 55, 15, 62, 183, 222, 105, 236, 197, 127, 54,
	179, 194, 229, 185, 37, 90, 237, 184, 25, 156, 173, 26, 187, 220, 2, 225,
	0, 240, 50, 251, 212, 253, 167, 17, 193, 205, 177, 21, 181, 246, 82, 226,
	38, 101, 163, 182, 242, 92, 20, 11, 95, 13, 230, 16, 121, 124, 109, 195,
	117, 39, 98, 239, 84, 56, 139, 161, 47, 201, 51, 135, 250, 10, 19, 150,
	45, 111, 27, 24, 142, 80, 85, 83, 234, 138, 216, 57, 93, 65, 154, 141,
	122, 34, 140, 128, 238, 88, 89, 9, 146, 171, 149, 53, 102, 61, 114, 69,
	217, 175, 103, 228, 35, 180, 252, 200, 192, 165, 159, 221, 244, 110, 119, 48,
}

// RSA public key used when the switch does not support the large key
// (util.From.bw() == false, e.g. firmware "1.0.0"). 64-bit modulus.
const rsaSmallModulusHex = "B3FAB9D6646D4EBF"

// RSA public key used by newer firmware (util.From.bw() == true). 1024-bit modulus.
const rsaBigModulusHex = "E5DDBB5F41342937AA6DB4E4ABE145251A9131B2983BC9CA3FF6E228C5C54DA460A232EAE97D5C9012E7D11669EB7003F6A65264F116294BD6C7897C62D2937DC5EB0D3F044251BA40F4E24E411C5F6C7B669594034B2288F72F161052344C18F94A33FB90ACF9B1D9BA984733A2D760DBD7C5BA8C87ACA281197E7BE7CC1A1D"

var (
	rsaSmallModulus = mustHex(rsaSmallModulusHex)
	rsaBigModulus   = mustHex(rsaBigModulusHex)
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
