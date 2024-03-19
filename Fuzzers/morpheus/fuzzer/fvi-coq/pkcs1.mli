
val length : 'a1 list -> int

val app : 'a1 list -> 'a1 list -> 'a1 list

val pred : int -> int

val add : int -> int -> int

val mul : int -> int -> int

val sub : int -> int -> int

val pow : int -> int -> int

val log2_iter : int -> int -> int -> int -> int

val log2 : int -> int

type byte =
| X00
| X01
| X02
| X03
| X04
| X05
| X06
| X07
| X08
| X09
| X0a
| X0b
| X0c
| X0d
| X0e
| X0f
| X10
| X11
| X12
| X13
| X14
| X15
| X16
| X17
| X18
| X19
| X1a
| X1b
| X1c
| X1d
| X1e
| X1f
| X20
| X21
| X22
| X23
| X24
| X25
| X26
| X27
| X28
| X29
| X2a
| X2b
| X2c
| X2d
| X2e
| X2f
| X30
| X31
| X32
| X33
| X34
| X35
| X36
| X37
| X38
| X39
| X3a
| X3b
| X3c
| X3d
| X3e
| X3f
| X40
| X41
| X42
| X43
| X44
| X45
| X46
| X47
| X48
| X49
| X4a
| X4b
| X4c
| X4d
| X4e
| X4f
| X50
| X51
| X52
| X53
| X54
| X55
| X56
| X57
| X58
| X59
| X5a
| X5b
| X5c
| X5d
| X5e
| X5f
| X60
| X61
| X62
| X63
| X64
| X65
| X66
| X67
| X68
| X69
| X6a
| X6b
| X6c
| X6d
| X6e
| X6f
| X70
| X71
| X72
| X73
| X74
| X75
| X76
| X77
| X78
| X79
| X7a
| X7b
| X7c
| X7d
| X7e
| X7f
| X80
| X81
| X82
| X83
| X84
| X85
| X86
| X87
| X88
| X89
| X8a
| X8b
| X8c
| X8d
| X8e
| X8f
| X90
| X91
| X92
| X93
| X94
| X95
| X96
| X97
| X98
| X99
| X9a
| X9b
| X9c
| X9d
| X9e
| X9f
| Xa0
| Xa1
| Xa2
| Xa3
| Xa4
| Xa5
| Xa6
| Xa7
| Xa8
| Xa9
| Xaa
| Xab
| Xac
| Xad
| Xae
| Xaf
| Xb0
| Xb1
| Xb2
| Xb3
| Xb4
| Xb5
| Xb6
| Xb7
| Xb8
| Xb9
| Xba
| Xbb
| Xbc
| Xbd
| Xbe
| Xbf
| Xc0
| Xc1
| Xc2
| Xc3
| Xc4
| Xc5
| Xc6
| Xc7
| Xc8
| Xc9
| Xca
| Xcb
| Xcc
| Xcd
| Xce
| Xcf
| Xd0
| Xd1
| Xd2
| Xd3
| Xd4
| Xd5
| Xd6
| Xd7
| Xd8
| Xd9
| Xda
| Xdb
| Xdc
| Xdd
| Xde
| Xdf
| Xe0
| Xe1
| Xe2
| Xe3
| Xe4
| Xe5
| Xe6
| Xe7
| Xe8
| Xe9
| Xea
| Xeb
| Xec
| Xed
| Xee
| Xef
| Xf0
| Xf1
| Xf2
| Xf3
| Xf4
| Xf5
| Xf6
| Xf7
| Xf8
| Xf9
| Xfa
| Xfb
| Xfc
| Xfd
| Xfe
| Xff

val to_bits : byte -> bool*(bool*(bool*(bool*(bool*(bool*(bool*bool))))))

val eqb : bool -> bool -> bool

module Nat :
 sig
  val eqb : int -> int -> bool

  val leb : int -> int -> bool
 end

val repeat : 'a1 -> int -> 'a1 list

val eqb0 : byte -> byte -> bool

val to_nat : byte -> int

val cat : 'a1 list -> 'a1 list -> 'a1 list

type atype = byte
  (* singleton inductive, whose constructor was t *)

type alength = byte
  (* singleton inductive, whose constructor was l *)

type avalue = byte list
  (* singleton inductive, whose constructor was v *)

type asn =
| Tlv of atype * alength * avalue
| Tlla of atype * alength * asn list

type asb = asn
  (* singleton inductive, whose constructor was b *)

val avalue_len : avalue -> int

val alg_asn_len : asn list -> int

val lasn_len : asn list -> int

val length_is_valid : alength -> bool

val algo_asn_to_length : asn list -> int

val alg_asn_is_valid : asn list -> bool

val asb_is_valid : asb -> bool

val atype_to_byte : atype -> byte list

val alength_to_byte : alength -> byte list

val avalue_to_byte : avalue -> byte list

val alg_asn_to_byte : asn list -> byte list

val lasn_to_byte : asn list -> byte list

val asb_to_byte : asb -> byte list

type pkcs_format =
| Pkcs of byte * byte * byte list * byte * asb

val padding_bytes_all_ff : byte list -> bool

val padding_bytes_length_ge_8_and_all_ff : byte list -> bool

val pkcs_format_is_valid : pkcs_format -> bool

val pkcs_format_to_byte : pkcs_format -> byte list

val is_power_of_two : int -> bool

type hash_function_id =
| Sha1
| Sha224
| Sha256
| Sha384
| Sha512

val h2oid : hash_function_id -> byte list

val h2len : hash_function_id -> int

type asb_len_pairs =
| Alp of asb * int * asb * int

val h2asn : hash_function_id -> byte list -> asb_len_pairs

val list_eq : byte list -> byte list -> bool

val signature_verification :
  byte list -> int -> byte list -> hash_function_id -> bool
