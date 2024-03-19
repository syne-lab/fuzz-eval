From Coq Require Extraction.
Set Warnings "-extraction-inside-module".
Extraction Language OCaml.
From mathcomp Require Import all_ssreflect ssrnat.
From Coq Require Import Psatz Lia Omega ZArith.
Require Import String Arith Strings.Byte Init.Byte Init.Nat Coq.Lists.List Coq.Program.Wf.
Import ListNotations. 
Delimit Scope byte_scope with byte.
Delimit Scope string_scope with string.
Open Scope list_scope.
Open Scope bool_scope.
Check true && false.

Section ASN.

(* Type for ASN Type *)
Inductive atype :=
  | t : byte -> atype.

(* Type for ASN Length *)
Inductive alength :=
  | l : byte -> alength.

(* Type for ASN Value *)
Inductive avalue := 
  | v : list byte -> avalue.

(* Type for ASN block *)
(* | tlv : atype -> forall (n:byte), vec byte (b2n n) -> asn *)
Inductive asn :=
  | tlv : atype -> alength -> avalue -> asn
  | tlla : atype -> alength -> list asn -> asn.


(* Type for an PKCS AS block *)
Inductive asb :=
  | b : asn -> asb.

(* Function to calculate the length of avalue *)
Definition avalue_len (av : avalue) : nat :=
  match av with
  | v li => length li
  end.

(* Function to calculate the length of algorithm identifier ASN *)
Fixpoint alg_asn_len (la : list asn) : nat :=
  match la with
  | h::rest => match h with
               | tlv  aty ale ava => 2 + (avalue_len ava) + (alg_asn_len rest)
               | _ => 0 (*TODO: Check if that's okay to have it like this*)
               end
  | nil => 0
  end.


(* Function to calculate the length of list of asn *)
Fixpoint lasn_len (la : list asn) : nat :=
  match la with
  | h::rest => match h with
               | tlv  aty ale ava => 2 + (avalue_len ava) + (lasn_len rest)
               | tlla aty ale ala => 2 + (alg_asn_len ala) + (lasn_len rest)
               end
  | nil => 0
  end.

(* Function to calculate the length of PKCS AS block *)
Definition asb_len (a : asb) : nat :=
  match a with
  | b va => match va with
            | tlla ty le la => 2 + (lasn_len la)
            | _ => 0
            end
  end.

(* Function to verify that the length value is valid *)
Definition length_is_valid (le : alength) : bool :=
  match le with
  | l byt => if (to_nat byt) <=? 127 then true else false
  end.

(* Function to parse algo id ASN to get hash message size based on the hash algo id used *)
Definition algo_asn_to_length (alg : list asn) : nat :=
  match alg with
  | h::rest => 
    match h with
    | tlv aty ale ava => 
      match ava with
      | v (x2b::x0e::x03::x02::x1a::nil)                     => 20 (* SHA1   *)
      | v (x60::x86::x48::x01::x65::x03::x04::x02::x04::nil) => 28 (* SHA224 *)
      | v (x60::x86::x48::x01::x65::x03::x04::x02::x01::nil) => 32 (* SHA256 *)
      | v (x60::x86::x48::x01::x65::x03::x04::x02::x02::nil) => 48 (* SHA384 *)
      | v (x60::x86::x48::x01::x65::x03::x04::x02::x03::nil) => 64 (* SHA512 *)
      | v _ => 0
      end
    | _ => 0
    end
  | nil => 0
  end.

(* Function to verify that the oid value is valid *)
Definition oid_is_valid (va : avalue) : bool :=
  match va with
  | v (x2b::x0e::x03::x02::x1a::nil)                     => true (* SHA1   *)
  | v (x60::x86::x48::x01::x65::x03::x04::x02::x04::nil) => true (* SHA224 *)
  | v (x60::x86::x48::x01::x65::x03::x04::x02::x01::nil) => true (* SHA256 *)
  | v (x60::x86::x48::x01::x65::x03::x04::x02::x02::nil) => true (* SHA384 *)
  | v (x60::x86::x48::x01::x65::x03::x04::x02::x03::nil) => true (* SHA512 *)
  | v _ => false
  end.

(* Function to verify that algo id ASN is valid *)
Definition alg_asn_is_valid (alg : list asn) : bool :=
  match alg with
  | h::rest => 
    match h with
    | tlv aty ale ava => 
      match aty, ale with
      | t x06, l lale => (((to_nat lale) =? (avalue_len ava)) &&
        (match rest with
         | nil => true
         | nh::nrest => 
           match nh with
           | tlv naty nale nava => 
             match naty, nale, nava with
             | t x05, l lnale, v vnava => (((to_nat lnale) =? 0) 
                && (match vnava with 
                    | nil => true
                    | _ => false
                    end))
             | _, _, _ => false
             end
           | _ => false
           end
         end))
      | _, _ => false
      end
    | _ => false
    end
  | nil => false
  end.

(* Definition to verify that PKCS AS block is valid *)
Definition asb_is_valid (gasb : asb) : bool :=
  match gasb with
  | b va => 
    match va with
    | tlla ty le la => 
      match ty, le with
      | t x30, l lle => 
        ((length_is_valid le) && ((to_nat lle) =? (lasn_len la)) && 
         (match la with
         | h::rest => 
           match h with
           | tlla (t x30) (l lnle) nla => 
             ((length_is_valid (l lnle)) && ((to_nat lnle) =? (lasn_len nla)) &&
              (alg_asn_is_valid nla) && 
                (match rest with
                 | nh::nrest => 
                   match nh with
                   | tlv tyh leh vah => 
                     match tyh, leh with
                     | t x04, l lleh => ((length_is_valid (l lleh)) && 
                       ((to_nat lleh) =? (algo_asn_to_length nla)) && 
                       ((to_nat lleh) =? (avalue_len vah)) &&
                        (match nrest with 
                        | nil => true
                        | _ => false
                        end))
                     | _, _ => false
                     end
                   | _ => false
                   end
                 | nil => false
                 end
                 ))
           | _ => false
           end
         | nil => false
         end
         ) 
        )
      | _, _ => false
      end
    | _ => false
    end
  end.

(* Some examples of AS Block Construction *)
Check b (tlla (t x30) (l x1f) (tlla (t x30) (l x07) ((tlv (t x06) (l x05) 
(v (x2b::x0e::x03::x02::x1a::nil)))::
(tlv (t x04) (l x14) (v nil))::nil)::nil)).
Check b (tlla (t x30) (l x2d) (tlla (t x30) (l x0d) ((tlv (t x06) (l x09) 
(v (x60::x86::x48::x01::x65::x03::x04::x02::x04::nil)))::
(tlv (t x05) (l x00) (v nil))::nil)::
(tlv (t x04) (l x1c) (v nil))::nil)).
Check b (tlla (t x30) (l x31) (tlla (t x30) (l x0d) ((tlv (t x06) (l x09) 
(v (x60::x86::x48::x01::x65::x03::x04::x02::x01::nil)))::
(tlv (t x05) (l x00) (v nil))::nil)::
(tlv (t x04) (l x20) (v nil))::nil)).
Check b (tlla (t x30) (l x41) (tlla (t x30) (l x0d) ((tlv (t x06) (l x09) 
(v (x60::x86::x48::x01::x65::x03::x04::x02::x02::nil)))::
(tlv (t x05) (l x00) (v nil))::nil)::
(tlv (t x04) (l x30) (v nil))::nil)).
Check b (tlla (t x30) (l x51) (tlla (t x30) (l x0d) ((tlv (t x06) (l x09) 
(v (x60::x86::x48::x01::x65::x03::x04::x02::x03::nil)))::
(tlv (t x05) (l x00) (v nil))::nil)::
(tlv (t x04) (l x40) (v nil))::nil)).

(* Some examples to test *)
Definition test_true_hello_world := b (tlla (t x30) (l x31) (tlla (t x30) (l x0d) ((tlv (t x06) (l x09) 
(v (x60::x86::x48::x01::x65::x03::x04::x02::x01::nil)))::
(tlv (t x05) (l x00) (v nil))::nil)::
(tlv (t x04) (l x20) 
(v (xb9::x4d::x27::xb9::x93::x4d::x3e::x08::xa5::x2e::x52::xd7::xda::x7d::xab::xfa::xc4::x84::xef::xe3::x7a::x53::
x80::xee::x90::x88::xf7::xac::xe2::xef::xcd::xe9::nil)))::nil)).

Eval compute in asb_len test_true_hello_world.
Eval compute in asb_is_valid test_true_hello_world.

Definition test_true_asn := b (tlla (t x30) (l x1f) (tlla (t x30) (l x07) 
((tlv (t x06) (l x05) (v (x2b::x0e::x03::x02::x1a::nil)))::
(tlv (t x04) (l x14) (v nil))::nil)::nil)).

Eval compute in asb_len test_true_asn.
Eval compute in asb_is_valid test_true_asn.

Definition test_false_oid := b (tlla (t x30) (l x31) (tlla (t x30) (l x0d) ((tlv (t x06) (l x09) 
(v (x60::x86::x48::x01::x65::x03::x04::x02::x01::x01::nil)))::
(tlv (t x05) (l x00) (v nil))::nil)::
(tlv (t x04) (l x20) 
(v (xb9::x4d::x27::xb9::x93::x4d::x3e::x08::xa5::x2e::x52::xd7::xda::x7d::xab::xfa::xc4::x84::xef::xe3::x7a::x53::
x80::xee::x90::x88::xf7::xac::xe2::xef::xcd::xe9::nil)))::nil)).

Eval compute in asb_len test_false_oid.
Eval compute in asb_is_valid test_false_oid.

Definition test_wrong_size := b (tlla (t x30) (l x35) (tlla (t x30) (l x0e) ((tlv (t x06) (l x0a) 
(v (x60::x86::x48::x01::x65::x03::x04::x02::x01::nil)))::
(tlv (t x05) (l x00) (v nil))::nil)::
(tlv (t x04) (l x20) 
(v (xb9::x4d::x27::xb9::x93::x4d::x3e::x08::xa5::x2e::x52::xd7::xda::x7d::xab::xfa::xc4::x84::xef::xe3::x7a::x53::
x80::xee::x90::x88::xf7::xac::xe2::xef::xcd::xe9::nil)))::nil)).

Eval compute in asb_len test_wrong_size.
Eval compute in asb_is_valid test_wrong_size.

Definition test_false_hello_world := b (tlla (t x30) (l x31) (tlla (t x30) (l x0d) ((tlv (t x06) (l x09) 
(v (x60::x86::x48::x01::x65::x03::x04::x02::x01::nil)))::
(tlv (t x05) (l x00) (v nil))::nil)::
(tlv (t x04) (l x20) 
(v (xb9::x4d::x27::xb9::x93::x4d::x3e::x08::xa5::x2e::x52::xd7::xda::x7d::xab::xfa::xc4::x84::xef::xe3::x7a::x53::
x80::xee::x90::x88::xf7::xac::xe2::xef::xcd::xe9::x00::nil)))::nil)).

Eval compute in asb_len test_false_hello_world.
Eval compute in asb_is_valid test_false_hello_world.

Definition test_false_tag := b (tlla (t xff) (l x1f) (tlla (t x30) (l x07) 
((tlv (t x06) (l x05) (v (x2b::x0e::x03::x02::x1a::nil)))::nil)::
(tlv (t x04) (l x14) (v nil))::nil)).

Eval compute in asb_len test_false_tag.
Eval compute in asb_is_valid test_false_tag.

Definition test_wrong_length2 := b (tlla (t x30) (l xff) (tlla (t x30) (l x07) 
((tlv (t x06) (l x05) (v (x2b::x0e::x03::x02::x1a::nil)))::nil)::
(tlv (t x04) (l x14) (v nil) )::nil)).

Eval compute in asb_len test_wrong_length2.
Eval compute in asb_is_valid test_wrong_length2.

Definition test_false_oid2 := b (tlla (t x30) (l x1f) (tlla (t x30) (l x07) 
((tlv (t x06) (l x05) (v (x2b::x0e::x03::x02::x1a::x00::nil)))::nil)::
(tlv (t x04) (l x14) (v nil))::nil)).

Eval compute in asb_len test_false_oid2.
Eval compute in asb_is_valid test_false_oid2.

(* Function to convert ASN's Type into a list of byte *)
Definition atype_to_byte (aty : atype) : list byte :=
  match aty with 
  | t byt => byt::nil
  end.

(* Function to convert ASN's Length into a list of byte *)
Definition alength_to_byte (ale : alength) : list byte :=
  match ale with 
  | l byt => byt::nil
  end.

(* Function to convert ASN's Value into a list of byte *)
Definition avalue_to_byte (ava : avalue) : list byte :=
  match ava with
  | v li => li
  end.

(* Function to convert ASN's algorithm identifier into a list of byte *)
Fixpoint alg_asn_to_byte (la : list asn) : list byte :=
  match la with
  | h::rest => match h with
               | tlv  aty ale ava => (atype_to_byte aty)++(alength_to_byte ale)++(avalue_to_byte ava)++(alg_asn_to_byte rest)
               | _ => nil 
               end
  | nil => nil
  end.


(* Function to convert ASN's top block into a list of byte *)
Fixpoint lasn_to_byte (la : list asn) : list byte :=
  match la with
  | h::rest => match h with
               | tlv  aty ale ava => (atype_to_byte aty)++(alength_to_byte ale)++(avalue_to_byte ava)++(lasn_to_byte rest)
               | tlla aty ale ala => (atype_to_byte aty)++(alength_to_byte ale)++(alg_asn_to_byte ala)++(lasn_to_byte rest)
               end
  | nil => nil
  end.

(* Function to convert PKCS AS block into a list of byte *)
Definition asb_to_byte (a : asb) : list byte :=
  match a with
  | b va => match va with
            | tlla ty le la => (atype_to_byte ty)++(alength_to_byte le)++(lasn_to_byte la)
            | _ => nil
            end
  end.


(* Tests *)
Eval compute in asb_to_byte test_true_asn.
Eval compute in asb_to_byte test_true_hello_world.
Eval compute in asb_to_byte test_false_tag.

End ASN.

Section PKCS_format.

(* Type for the PKCS structured input and output format *)
Inductive pkcs_format :=
  | pkcs : byte -> byte -> list byte -> byte -> asb -> pkcs_format.

(* Function to calculate the length of the PKCS structured input and output format *)
Definition pkcs_format_len (st : pkcs_format) : nat :=
  match st with
  | pkcs gz1 gbt gpb gz2 gasb => 3 + (length gpb) + (asb_len gasb)
  end.

(* Function to verify that the padding is valid (i.e., it contains a list of 'xff' bytes) *)
Fixpoint padding_bytes_all_ff (li : list byte) : bool :=
  match li with
  | xff::rest => padding_bytes_all_ff rest
  | _::rest => false
  | nil => true
  end.

(* Function to verify padding length is at least and its values are all 'xff's *)
Definition padding_bytes_length_ge_8_and_all_ff (gpb : list byte) : bool :=
  if (8 <=? (length gpb)) then (padding_bytes_all_ff gpb) else false.

(* Function to verify that PKCS format is valid *)
Definition pkcs_format_is_valid (st : pkcs_format) : bool :=
  match st with
  | pkcs gz1 gbt gpb gz2 gasb => ((Byte.eqb gz1 x00) && 
                                  (Byte.eqb gbt x01) && 
                                  (padding_bytes_length_ge_8_and_all_ff gpb) && 
                                  (Byte.eqb gz2 x00) && 
                                  (asb_is_valid gasb))
  end.

(* Some examples to test *)
Definition test_true_pkcs := pkcs (x00) (x01) 
(xff::xff::xff::xff::xff::xff::xff::xff::xff::xff::xff::xff::xff::xff::xff::xff::xff::nil) 
(x00) 
(b (tlla (t x30) (l x31) (tlla (t x30) (l x0d) ((tlv (t x06) (l x09) 
(v (x60::x86::x48::x01::x65::x03::x04::x02::x01::nil)))::
(tlv (t x05) (l x00) (v nil))::nil)::
(tlv (t x04) (l x20) 
(v (xb9::x4d::x27::xb9::x93::x4d::x3e::x08::xa5::x2e::x52::xd7::xda::x7d::xab::xfa::xc4::x84::xef::xe3::x7a::x53::
x80::xee::x90::x88::xf7::xac::xe2::xef::xcd::xe9::nil)))::nil))).

Definition test_false_zero := pkcs (x01) (x01) 
(xff::xff::xff::xff::xff::xff::xff::xff::xff::xff::xff::xff::xff::xff::xff::xff::xff::nil) 
(x00) 
(b (tlla (t x30) (l x31) (tlla (t x30) (l x0d) ((tlv (t x06) (l x09) 
(v (x60::x86::x48::x01::x65::x03::x04::x02::x01::nil)))::
(tlv (t x05) (l x00) (v nil))::nil)::
(tlv (t x04) (l x20) 
(v (xb9::x4d::x27::xb9::x93::x4d::x3e::x08::xa5::x2e::x52::xd7::xda::x7d::xab::xfa::xc4::x84::xef::xe3::x7a::x53::
x80::xee::x90::x88::xf7::xac::xe2::xef::xcd::xe9::nil)))::nil))).

Definition test_false_bt := pkcs (x00) (x30) 
(xff::xff::xff::xff::xff::xff::xff::xff::xff::xff::xff::xff::xff::xff::xff::xff::xff::nil) 
(x00) 
(b (tlla (t x30) (l x31) (tlla (t x30) (l x0d) ((tlv (t x06) (l x09) 
(v (x60::x86::x48::x01::x65::x03::x04::x02::x01::nil)))::
(tlv (t x05) (l x00) (v nil))::nil)::
(tlv (t x04) (l x20) 
(v (xb9::x4d::x27::xb9::x93::x4d::x3e::x08::xa5::x2e::x52::xd7::xda::x7d::xab::xfa::xc4::x84::xef::xe3::x7a::x53::
x80::xee::x90::x88::xf7::xac::xe2::xef::xcd::xe9::nil)))::nil))).

Definition test_false_padding_length := pkcs (x00) (x01) 
(xff::xff::nil) 
(x00) 
(b (tlla (t x30) (l x31) (tlla (t x30) (l x0d) ((tlv (t x06) (l x09) 
(v (x60::x86::x48::x01::x65::x03::x04::x02::x01::nil)))::
(tlv (t x05) (l x00) (v nil))::nil)::
(tlv (t x04) (l x20) 
(v (xb9::x4d::x27::xb9::x93::x4d::x3e::x08::xa5::x2e::x52::xd7::xda::x7d::xab::xfa::xc4::x84::xef::xe3::x7a::x53::
x80::xee::x90::x88::xf7::xac::xe2::xef::xcd::xe9::nil)))::nil))).

Definition test_false_padding_value := pkcs (x00) (x01) 
(xff::xff::xff::xff::xff::xff::xff::xff::xff::xff::xff::xff::xff::xff::xff::xff::x00::nil) 
(x00) 
(b (tlla (t x30) (l x31) (tlla (t x30) (l x0d) ((tlv (t x06) (l x09) 
(v (x60::x86::x48::x01::x65::x03::x04::x02::x01::nil)))::
(tlv (t x05) (l x00) (v nil))::nil)::
(tlv (t x04) (l x20) 
(v (xb9::x4d::x27::xb9::x93::x4d::x3e::x08::xa5::x2e::x52::xd7::xda::x7d::xab::xfa::xc4::x84::xef::xe3::x7a::x53::
x80::xee::x90::x88::xf7::xac::xe2::xef::xcd::xe9::nil)))::nil))).

Definition test_false_zero2 := pkcs (x00) (x01) 
(xff::xff::xff::xff::xff::xff::xff::xff::xff::xff::xff::xff::xff::xff::xff::xff::xff::nil) 
(x30) 
(b (tlla (t x30) (l x31) (tlla (t x30) (l x0d) ((tlv (t x06) (l x09) 
(v (x60::x86::x48::x01::x65::x03::x04::x02::x01::nil)))::
(tlv (t x05) (l x00) (v nil))::nil)::
(tlv (t x04) (l x20) 
(v (xb9::x4d::x27::xb9::x93::x4d::x3e::x08::xa5::x2e::x52::xd7::xda::x7d::xab::xfa::xc4::x84::xef::xe3::x7a::x53::
x80::xee::x90::x88::xf7::xac::xe2::xef::xcd::xe9::nil)))::nil))).

(* Results *) 
Eval compute in pkcs_format_len test_true_pkcs.
Eval compute in pkcs_format_is_valid test_true_pkcs.
Eval compute in pkcs_format_len test_false_zero.
Eval compute in pkcs_format_is_valid test_false_zero.
Eval compute in pkcs_format_len test_false_bt.
Eval compute in pkcs_format_is_valid test_false_bt.
Eval compute in pkcs_format_len test_false_padding_length.
Eval compute in pkcs_format_is_valid test_false_padding_length.
Eval compute in pkcs_format_len test_false_padding_value.
Eval compute in pkcs_format_is_valid test_false_padding_value.
Eval compute in pkcs_format_len test_false_zero2.
Eval compute in pkcs_format_is_valid test_false_zero2.


(* Function to convert a PKCS structured input and output format into bytes *)
Definition pkcs_format_to_byte (st : pkcs_format) : list byte :=
  if (pkcs_format_is_valid st) then
    match st with 
    | pkcs gz1 gbt gpb gz2 gasb => (gz1::gbt::nil)++(gpb)++(gz2::nil)++(asb_to_byte gasb)
    end
  else nil.

(* Tests *)
Eval compute in pkcs_format_to_byte test_true_pkcs.
Eval compute in pkcs_format_to_byte test_false_zero.

(* More Tests *)
Definition correct_format := pkcs (x00) (x01)
(xff::xff::xff::xff::xff::xff::xff::xff::xff::xff::nil) (x00)
(b (tlla (t x30) (l x31) (tlla (t x30) (l x0d) ((tlv (t x06) (l x09) 
(v (x60::x86::x48::x01::x65::x03::x04::x02::x01::nil)))::
(tlv (t x05) (l x00) (v nil))::nil)::
(tlv (t x04) (l x20) 
(v (xb9::x4d::x27::xb9::x93::x4d::x3e::x08::xa5::x2e::x52::xd7::xda::x7d::xab::xfa::xc4::x84::xef::xe3::x7a::x53::
x80::xee::x90::x88::xf7::xac::xe2::xef::xcd::xe9::nil)))::nil))).

Definition wrong_first_byte_wrong_padding_wrong_value := pkcs (x01) (x01)
(x01::x01::x01::x01::x01::x01::x01::x01::nil) (x00)
(b (tlla (t x30) (l x31) (tlla (t x30) (l x0d) ((tlv (t x06) (l x09) 
(v (x60::x86::x48::x01::x65::x03::x04::x02::x01::nil)))::
(tlv (t x05) (l x00) (v nil))::nil)::
(tlv (t x04) (l x20) 
(v (xb9::x4d::x27::xb9::x93::x4d::x3e::x08::xa5::x2e::x52::xd7::xda::x7d::xab::xfa::xc4::x84::xef::xe3
::x7a::x53::x80::xee::x90::x88::xf7::xac::xe2::xef::xcd::xe9::x01::x01::nil)))::nil))).

Definition wrong_first_byte_wrong_second_byte_wrong_padding_wrong_value := pkcs (x01) (x00)
(x01::x01::x01::x01::x01::x01::x01::x01::nil) (x00)
(b (tlla (t x30) (l x31) (tlla (t x30) (l x0d) ((tlv (t x06) (l x09) 
(v (x60::x86::x48::x01::x65::x03::x04::x02::x01::nil)))::
(tlv (t x05) (l x00) (v nil))::nil)::
(tlv (t x04) (l x20) 
(v (xb9::x4d::x27::xb9::x93::x4d::x3e::x08::xa5::x2e::x52::xd7::xda::x7d::xab::xfa::xc4::x84::xef::xe3
::x7a::x53::x80::xee::x90::x88::xf7::xac::xe2::xef::xcd::xe9::x01::x01::nil)))::nil))).

Definition wrong_padding_wrong_value := pkcs (x00) (x01)
(x01::x01::x01::x01::x01::x01::x01::x01::nil) (x00)
(b (tlla (t x30) (l x31) (tlla (t x30) (l x0d) ((tlv (t x06) (l x09) 
(v (x60::x86::x48::x01::x65::x03::x04::x02::x01::nil)))::
(tlv (t x05) (l x00) (v nil))::nil)::
(tlv (t x04) (l x20) 
(v (xb9::x4d::x27::xb9::x93::x4d::x3e::x08::xa5::x2e::x52::xd7::xda::x7d::xab::xfa::xc4::x84::xef::xe3
::x7a::x53::x80::xee::x90::x88::xf7::xac::xe2::xef::xcd::xe9::x00::x00::nil)))::nil))).

Definition wrong_second_byte_wrong_padding_wrong_value := pkcs (x00) (x02)
(xff::xff::xff::xff::xff::xff::xff::xff::xff::xff::nil) (x00)
(b (tlla (t x30) (l x31) (tlla (t x30) (l x0d) ((tlv (t x06) (l x09) 
(v (x60::x86::x48::x01::x65::x03::x04::x02::x01::nil)))::
(tlv (t x05) (l x00) (v nil))::nil)::
(tlv (t x04) (l x20) 
(v (xb9::x4d::x27::xb9::x93::x4d::x3e::x08::xa5::x2e::x52::xd7::xda::x7d::xab::xfa::xc4::x84::xef::xe3
::x7a::x53::x80::xee::x90::x88::xf7::xac::xe2::xef::xcd::xe9::x00::x00::nil)))::nil))).

Definition wrong_second_byte_wrong_padding_wrong_value2 := pkcs (x00) (x02)
(x01::x01::x01::x01::x01::x01::x01::x01::nil) (x00)
(b (tlla (t x30) (l x31) (tlla (t x30) (l x0d) ((tlv (t x06) (l x09) 
(v (x60::x86::x48::x01::x65::x03::x04::x02::x01::nil)))::
(tlv (t x05) (l x00) (v nil))::nil)::
(tlv (t x04) (l x20) 
(v (xb9::x4d::x27::xb9::x93::x4d::x3e::x08::xa5::x2e::x52::xd7::xda::x7d::xab::xfa::xc4::x84::xef::xe3
::x7a::x53::x80::xee::x90::x88::xf7::xac::xe2::xef::xcd::xe9::x00::x00::nil)))::nil))).

Definition wrong_null_parameter := pkcs (x00) (x01)
(xff::xff::xff::xff::xff::xff::xff::xff::xff::xff::nil) (x00)
(b (tlla (t x30) (l x31) (tlla (t x30) (l x0d) ((tlv (t x06) (l x09) 
(v (x60::x86::x48::x01::x65::x03::x04::x02::x01::nil)))::
(tlv (t x05) (l x02) (v nil))::nil)::
(tlv (t x04) (l x20) 
(v (xb9::x4d::x27::xb9::x93::x4d::x3e::x08::xa5::x2e::x52::xd7::xda::x7d::xab::xfa::xc4::x84::xef::xe3::x7a::x53::
x80::xee::x90::x88::xf7::xac::xe2::xef::xcd::xe9::nil)))::nil))).

Definition wrong_oid := pkcs (x00) (x01)
(xff::xff::xff::xff::xff::xff::xff::xff::xff::xff::nil) (x00)
(b (tlla (t x30) (l x31) (tlla (t x30) (l x0d) ((tlv (t x06) (l x09) 
(v (x60::x86::x48::x01::x65::x03::x04::x02::x01::x01::x01::nil)))::
(tlv (t x05) (l x00) (v nil))::nil)::
(tlv (t x04) (l x20) 
(v (xb9::x4d::x27::xb9::x93::x4d::x3e::x08::xa5::x2e::x52::xd7::xda::x7d::xab::xfa::xc4::x84::xef::xe3::x7a::x53::
x80::xee::x90::x88::xf7::xac::xe2::xef::xcd::xe9::nil)))::nil))).

(* Results *) 
Eval compute in pkcs_format_is_valid correct_format.
Eval compute in pkcs_format_is_valid wrong_first_byte_wrong_padding_wrong_value.
Eval compute in pkcs_format_is_valid wrong_first_byte_wrong_second_byte_wrong_padding_wrong_value.
Eval compute in pkcs_format_is_valid wrong_padding_wrong_value.
Eval compute in pkcs_format_is_valid wrong_second_byte_wrong_padding_wrong_value.
Eval compute in pkcs_format_is_valid wrong_second_byte_wrong_padding_wrong_value2.
Eval compute in pkcs_format_is_valid wrong_null_parameter.
Eval compute in pkcs_format_is_valid wrong_oid.

End PKCS_format.

Definition is_power_of_two (n : nat): bool :=
  pow 2 (log2 n) =? n.

(* Type for hash function identifier *)
Inductive hash_function_id :=
  | sha1
  | sha224
  | sha256
  | sha384
  | sha512.

(* Function to convert hash function ID to its OID as list of bytes *)
Definition h2oid (hfi : hash_function_id) : list byte :=
  match hfi with
  | sha1   => (x2b::x0e::x03::x02::x1a::nil)
  | sha224 => (x60::x86::x48::x01::x65::x03::x04::x02::x04::nil)
  | sha256 => (x60::x86::x48::x01::x65::x03::x04::x02::x01::nil)
  | sha384 => (x60::x86::x48::x01::x65::x03::x04::x02::x02::nil)
  | sha512 => (x60::x86::x48::x01::x65::x03::x04::x02::x03::nil)
  end.

(* Function to convert hash function ID to its hash digest size *)
Definition h2len (hfi : hash_function_id) : nat :=
  match hfi with
  | sha1   => 20
  | sha224 => 28
  | sha256 => 32
  | sha384 => 48
  | sha512 => 64
  end.

(* Type for pairs ((ASB1, N), (ASB2, N) *)
Inductive asb_len_pairs :=
  | alp : asb -> nat -> asb -> nat -> asb_len_pairs.

(* Function to convert hash function ID to a structure contains pairs of its encoded AS block and the length of that asn *)
Definition h2asn (hfi : hash_function_id) (hv : list byte) : asb_len_pairs :=
  match hfi with
  | sha1   => (alp (b (tlla (t x30) (l x21) (tlla (t x30) (l x09) 
                      ((tlv (t x06) (l x05) 
                            (v (h2oid sha1)))::
                       (tlv (t x05) (l x00) (v nil))::nil)::
                      (tlv (t x04) (l x14) (v hv))::nil)))
                   (length (asb_to_byte (b (tlla (t x30) (l x21) (tlla (t x30) (l x09) 
                      ((tlv (t x06) (l x05) 
                            (v (h2oid sha1)))::
                       (tlv (t x05) (l x00) (v nil))::nil)::
                      (tlv (t x04) (l x14) (v hv))::nil))) )) 
                   (b (tlla (t x30) (l x1f) (tlla (t x30) (l x07) 
                      ((tlv (t x06) (l x05) 
                            (v (h2oid sha1)))::nil)::
                      (tlv (t x04) (l x14) (v hv))::nil)))
                   (length (asb_to_byte (b (tlla (t x30) (l x1f) (tlla (t x30) (l x07) 
                      ((tlv (t x06) (l x05) 
                            (v (h2oid sha1)))::nil)::
                      (tlv (t x04) (l x14) (v hv))::nil)))))
              )
  | sha224 => (alp (b (tlla (t x30) (l x2d) (tlla (t x30) (l x0d) 
                      ((tlv (t x06) (l x09) 
                            (v (h2oid sha224)))::
                       (tlv (t x05) (l x00) (v nil))::nil)::
                      (tlv (t x04) (l x1c) (v hv))::nil)))
                   (length (asb_to_byte (b (tlla (t x30) (l x2d) (tlla (t x30) (l x0d) 
                      ((tlv (t x06) (l x09) 
                            (v (h2oid sha224)))::
                       (tlv (t x05) (l x00) (v nil))::nil)::
                      (tlv (t x04) (l x1c) (v hv))::nil)))))
                   (b (tlla (t x30) (l x2b) (tlla (t x30) (l x0b) 
                      ((tlv (t x06) (l x09) 
                            (v (h2oid sha224)))::nil)::
                      (tlv (t x04) (l x1c) (v hv))::nil)))
                   (length (asb_to_byte (b (tlla (t x30) (l x2b) (tlla (t x30) (l x0b) 
                      ((tlv (t x06) (l x09) 
                            (v (h2oid sha224)))::nil)::
                      (tlv (t x04) (l x1c) (v hv))::nil)))))
              )
  | sha256 => (alp (b (tlla (t x30) (l x31) (tlla (t x30) (l x0d) 
                      ((tlv (t x06) (l x09) 
                            (v (h2oid sha256)))::
                       (tlv (t x05) (l x00) (v nil))::nil)::
                      (tlv (t x04) (l x20) (v hv))::nil)))
                   (length (asb_to_byte (b (tlla (t x30) (l x31) (tlla (t x30) (l x0d) 
                      ((tlv (t x06) (l x09) 
                            (v (h2oid sha256)))::
                       (tlv (t x05) (l x00) (v nil))::nil)::
                      (tlv (t x04) (l x20) (v hv))::nil)))))
                   (b (tlla (t x30) (l x2f) (tlla (t x30) (l x0b) 
                      ((tlv (t x06) (l x09) 
                            (v (h2oid sha256)))::nil)::
                      (tlv (t x04) (l x20) (v hv))::nil)))
                   (length (asb_to_byte (b (tlla (t x30) (l x2f) (tlla (t x30) (l x0b) 
                      ((tlv (t x06) (l x09) 
                            (v (h2oid sha256)))::nil)::
                      (tlv (t x04) (l x20) (v hv))::nil)))))
              )
  | sha384 => (alp (b (tlla (t x30) (l x41) (tlla (t x30) (l x0d) 
                      ((tlv (t x06) (l x09) 
                            (v (h2oid sha384)))::
                       (tlv (t x05) (l x00) (v nil))::nil)::
                      (tlv (t x04) (l x30) (v hv))::nil)))
                   (length (asb_to_byte (b (tlla (t x30) (l x41) (tlla (t x30) (l x0d) 
                      ((tlv (t x06) (l x09) 
                            (v (h2oid sha384)))::
                       (tlv (t x05) (l x00) (v nil))::nil)::
                      (tlv (t x04) (l x30) (v hv))::nil)))))
                   (b (tlla (t x30) (l x3f) (tlla (t x30) (l x0b) 
                      ((tlv (t x06) (l x09) 
                            (v (h2oid sha384)))::nil)::
                      (tlv (t x04) (l x30) (v hv))::nil)))
                   (length (asb_to_byte (b (tlla (t x30) (l x3f) (tlla (t x30) (l x0b) 
                      ((tlv (t x06) (l x09) 
                            (v (h2oid sha384)))::nil)::
                      (tlv (t x04) (l x30) (v hv))::nil)))))
              )
  | sha512 => (alp (b (tlla (t x30) (l x51) (tlla (t x30) (l x0d) 
                      ((tlv (t x06) (l x09) 
                            (v (h2oid sha512)))::
                       (tlv (t x05) (l x00) (v nil))::nil)::
                      (tlv (t x04) (l x40) (v hv))::nil)))
                   (length (asb_to_byte (b (tlla (t x30) (l x51) (tlla (t x30) (l x0d) 
                      ((tlv (t x06) (l x09) 
                            (v (h2oid sha512)))::
                       (tlv (t x05) (l x00) (v nil))::nil)::
                      (tlv (t x04) (l x40) (v hv))::nil)))))
                   (b (tlla (t x30) (l x4f) (tlla (t x30) (l x0b) 
                      ((tlv (t x06) (l x09) 
                            (v (h2oid sha512)))::nil)::
                      (tlv (t x04) (l x40) (v hv))::nil)))
                   (length (asb_to_byte (b (tlla (t x30) (l x4f) (tlla (t x30) (l x0b) 
                      ((tlv (t x06) (l x09) 
                            (v (h2oid sha512)))::nil)::
                      (tlv (t x04) (l x40) (v hv))::nil)))))
              )
  end.

Lemma alp_injective : 
    forall (a1 a2 a1' a2' : asb) (l1 l2 l1' l2': nat),
      alp a1 l1 a2 l2 = alp a1' l1' a2' l2' -> a1 = a1' /\ l1 = l1' /\ a2 = a2' /\ l2 = l2'.
Proof.
  intros.
  injection H.
  intros.
  subst.
  do 4! constructor.
Qed.

Theorem h2asn_asb_len_correlation:
    forall (hfi : hash_function_id) (hv : list byte) (a1 a2 : asb) (l1 l2 : nat),
    h2asn hfi hv = alp a1 l1 a2 l2 -> length (asb_to_byte a1) = l1 /\  length (asb_to_byte a2) = l2.
Proof.
  intros.
  split.
  unfold h2asn in H. destruct hfi in H. 
    apply alp_injective in H. destruct H as (Ha1 & Hl1 & Ha2 & Hl2). rewrite Ha1 in Hl1. apply Hl1.
    apply alp_injective in H. destruct H as (Ha1 & Hl1 & Ha2 & Hl2). rewrite Ha1 in Hl1. apply Hl1.
    apply alp_injective in H. destruct H as (Ha1 & Hl1 & Ha2 & Hl2). rewrite Ha1 in Hl1. apply Hl1.
    apply alp_injective in H. destruct H as (Ha1 & Hl1 & Ha2 & Hl2). rewrite Ha1 in Hl1. apply Hl1.
    apply alp_injective in H. destruct H as (Ha1 & Hl1 & Ha2 & Hl2). rewrite Ha1 in Hl1. apply Hl1.
  unfold h2asn in H. destruct hfi in H. 
    apply alp_injective in H. destruct H as (Ha1 & Hl1 & Ha2 & Hl2). rewrite Ha2 in Hl2. apply Hl2.
    apply alp_injective in H. destruct H as (Ha1 & Hl1 & Ha2 & Hl2). rewrite Ha2 in Hl2. apply Hl2.
    apply alp_injective in H. destruct H as (Ha1 & Hl1 & Ha2 & Hl2). rewrite Ha2 in Hl2. apply Hl2.
    apply alp_injective in H. destruct H as (Ha1 & Hl1 & Ha2 & Hl2). rewrite Ha2 in Hl2. apply Hl2.
    apply alp_injective in H. destruct H as (Ha1 & Hl1 & Ha2 & Hl2). rewrite Ha2 in Hl2. apply Hl2.
Qed.

(* Function to verify that two lists are equal *)
Fixpoint list_eq (l1 : list byte) (l2 : list byte) : bool :=
  match l1, l2 with
  | t1::rest1, t2::rest2 => ((Byte.eqb t1 t2) && (list_eq rest1 rest2))
  | nil, nil => true
  | _, _ => false
  end.


(* Test *)
Eval compute in list_eq (pkcs_format_to_byte test_true_pkcs) (pkcs_format_to_byte test_true_pkcs).
Eval compute in list_eq (pkcs_format_to_byte test_false_zero) (pkcs_format_to_byte test_true_pkcs).


Theorem list_eq_correctness: forall (l1 l2: list byte),
  list_eq l1 l2 = true -> (forall (i : nat), nth_error l1 i = nth_error l2 i).
Proof.
  intros l1.
  induction l1 as [| n l1' IHl1'].
  - (* l1 = nil *)
    intros l2 eq. 
    destruct l2 as [| n' l2'] eqn:E.
    + (* l2 = nil *) 
      reflexivity.
    + (* l2 = cons n l2' *)
      unfold list_eq in eq. 
      discriminate eq.
  - (* l1 = cons n l1' *)
    intros l2 eq.
    destruct l2 as [| n' l2'] eqn:E.
    + (* l2 = nil *)
      unfold list_eq in eq.
      discriminate eq.
    + (* l2 = cons n l2' *)
      intros i. destruct i as [| i'] eqn:E'.
        * (* i = O *)
          simpl. simpl in eq. apply andb_prop in eq. apply proj1 in eq. apply byte_dec_bl in eq.
          f_equal. apply eq.
        * (* i = S i' *)
         simpl. apply IHl1'. simpl in eq. apply andb_prop in eq. apply proj2 in eq. apply eq.
Qed.

Definition signature_verification (gib : list byte) (gpm : nat) (ghv : list byte) (ghfi : hash_function_id) : bool :=
  if (((is_power_of_two gpm) &&
      ((length gib) =? (gpm))) && 
      ((length ghv) =? (h2len ghfi))) then
    match (h2asn ghfi ghv) with 
    | alp gasb1 glen1 gasb2 glen2 => 
      if (pkcs_format_is_valid 
            (pkcs (x00) (x01) (repeat xff ((gpm - glen1) - 3)) (x00) gasb1)) 
      && (pkcs_format_is_valid 
            (pkcs (x00) (x01) (repeat xff ((gpm - glen2) - 3)) (x00) gasb2))
      then
        (list_eq gib (pkcs_format_to_byte 
                        (pkcs (x00) (x01) (repeat xff ((gpm - glen1) - 3)) (x00) gasb1))
        ||
        list_eq gib (pkcs_format_to_byte 
                        (pkcs (x00) (x01) (repeat xff ((gpm - glen2) - 3)) (x00) gasb2)))
      else false
    end
  else false.

(* Tests *)
Definition correct_input := (x00::x01::xff::xff::xff::xff::xff::xff::xff::xff::xff::xff::x00::
                             x30::x31::x30::x0d::x06::x09::x60::x86::x48::x01::x65::x03::x04::
                             x02::x01::x05::x00::x04::x20::xb9::x4d::x27::xb9::x93::x4d::x3e::
                             x08::xa5::x2e::x52::xd7::xda::x7d::xab::xfa::xc4::x84::xef::xe3::
                             x7a::x53::x80::xee::x90::x88::xf7::xac::xe2::xef::xcd::xe9::nil).

Definition correct_hash_value := (xb9::x4d::x27::xb9::x93::x4d::x3e::x08::xa5::x2e::x52::
                                  xd7::xda::x7d::xab::xfa::xc4::x84::xef::xe3::x7a::x53::
                                  x80::xee::x90::x88::xf7::xac::xe2::xef::xcd::xe9::nil).

Eval compute in pkcs_format_len correct_format.
Eval compute in pkcs_format_is_valid correct_format.
Eval compute in list_eq correct_input (pkcs_format_to_byte correct_format).
Eval compute in signature_verification correct_input 64 correct_hash_value sha256.


Lemma length_repeat_elim: 
    forall (b : byte) (m : nat), length (repeat b m) = m. 
Proof.
  intros.
  unfold repeat. induction m.
  * (* [] *)
    simpl. reflexivity.
  * (* S m *)
    simpl. rewrite IHm. reflexivity.
Qed.

Lemma eq_from_nth_error {A : Type} (l1 l2 : list A) :
  (forall i, nth_error l1 i = nth_error l2 i) -> l1 = l2.
Proof.
  elim: l1 l2 => [ | a l1 IH] [ | a' l2] //.
      by move=> abs; have := (abs 0).
    by move=> abs; have := (abs 0).
  move=> cmp; congr (_ :: _).
    by have := (cmp 0) => /= [[]].
  apply: IH=> i; exact (cmp i.+1).
Qed.

Lemma nth_error_repeat_elim:
    forall (i j : nat) (b : byte), j < i -> nth_error (repeat b i) j = Some b.
Proof.
  intros.
  unfold repeat. generalize dependent i. induction j as [| j' IHj'].
  * (* j = 0 *)
    intros. destruct i as [| i'] eqn:Heq.
    * (* i = 0 *)
      simpl. apply (rwP leP) in H. lia. 
    * (* i = S i' *)
      simpl. reflexivity.
  * (* j = S j' *)
    intros. destruct i as [| i'] eqn:Heq.
    * (* i = 0 *)
      simpl. apply (rwP leP) in H. lia. 
    * (* i = S i' *)
      simpl. apply IHj'. apply (rwP leP) in H. rewrite -?(rwP leP). lia. 
Qed.

Lemma build_from_spec : 
    forall (a_len b_len : nat) (a b : list byte),
    ((((Datatypes.length a = a_len /\
    Datatypes.length b = b_len) /\
    7 < a_len - b_len - 3) /\
    nth_error a 0 = Some x00) /\
    nth_error a 1 = Some x01) /\
    (forall i : nat, (1 < i) /\ (i < a_len - b_len - 1) ->
    nth_error a i = Some xff) /\
    nth_error a (a_len - b_len - 1) = Some x00 /\
    (forall j : nat, (0 <= j) /\ (j < b_len) ->
    nth_error a (a_len - b_len + j) = nth_error b j) 
    ->
    a = [x00;x01] ++ repeat xff (a_len - b_len - 3) ++ [x00] ++ b.
Proof. 
  intros.
  destruct H as (HH1 & HH2). destruct HH1 as (HH1 & HA1). destruct HH1 as (HH1 & HA0).
  destruct HH1 as (HH1 & HLenRel). destruct HH1 as (HLenA & HLenB). destruct HH2 as (HRep & HH2).
  destruct HH2 as (HEnd & HB). 
  apply eq_from_nth_error. 
  intros i.
  have [/eqP i_is_0 | i_is_not_0] := boolP(i == 0).
    rewrite i_is_0. simpl in HA0. simpl. apply HA0.
    have [/eqP i_is_1 | i_is_not_1] := boolP(i == 1).
    rewrite i_is_1. simpl in HA1. simpl. apply HA1.
      have [i_lt_border | is_larger] := boolP(i < a_len - b_len - 1).
        rewrite -?(minusE) in i_lt_border.  
        assert (i_is_gt_1 := conj i_is_not_0 i_is_not_1).
        assert (Hg1: forall (n : nat), is_true (n != 0) /\ is_true (n != 1) -> is_true (1 < n)).
          intros. destruct H as (H1 & H2). move/eqP: H1 => H1. move/eqP: H2 => H2. rewrite -?(rwP ltP). lia.
        apply Hg1 in i_is_gt_1.  
        assert (HPrem := conj i_is_gt_1 i_lt_border). apply HRep in HPrem. 
        move/ltP: i_is_gt_1 => i_is_gt_1.
        move/ltP: i_lt_border => i_lt_border. 
        move/leP: HLenRel => HLenRel. rewrite -?(plusE) in HLenRel.
        (*move/ltP: HLenBLo => HLenBLo. *)
        rewrite HPrem. rewrite nth_error_app2. rewrite nth_error_app1. 
        simpl. rewrite nth_error_repeat_elim. reflexivity.
        rewrite -?(minusE). rewrite -?(rwP ltP). simpl; lia.
        rewrite repeat_length. rewrite -?(minusE). simpl; lia.
        simpl; lia.
        have [i_eq_border | i_is_not_eq_border] := boolP(i == a_len - b_len - 1).
          assert (HRewrite := i_eq_border). 
          move/eqP: HRewrite => HRewrite.
          rewrite HRewrite. rewrite HEnd.
          rewrite nth_error_app2. rewrite nth_error_app2. rewrite nth_error_app1.
          rewrite repeat_length. simpl. rewrite -?(minusE). 
          assert (arithmetic_difficulty: forall (i j : nat),  
              ((((i - j)%coq_nat - 1)%coq_nat - 2)%coq_nat - ((i - j)%coq_nat - 3)%coq_nat)%coq_nat = 0).
                rewrite -?minusE. intros. lia.
          rewrite arithmetic_difficulty.
          simpl. reflexivity. 
          rewrite repeat_length. rewrite -?(minusE). simpl. lia.
          rewrite repeat_length. rewrite -?(minusE). simpl. lia. 
          move/leP: HLenRel => HLenRel. rewrite -?(minusE, plusE) in HLenRel.
          (*move/ltP: HLenBLo => HLenBLo.*) rewrite -?(minusE). simpl. lia.
          have [i_lt_a_len | i_not_lt_a_len ] := boolP(i < a_len).
          rewrite nth_error_app2. rewrite nth_error_app2. rewrite nth_error_app2.
          rewrite repeat_length. simpl. 
          rewrite <- HB. simpl. apply f_equal.
          move/leP: HLenRel => HLenRel. rewrite -?(minusE, plusE) in HLenRel.
          (*move/ltP: HLenBLo => HLenBLo.*) rewrite -?(minusE). 
          move/ltP: i_lt_a_len => i_lt_a_len. rewrite -?(minusE) in i_is_not_eq_border.
          move/eqP: i_is_not_eq_border => i_is_not_eq_border. move/ltP: is_larger => is_larger. rewrite -?(minusE) in is_larger.
          rewrite -?(minusE, plusE). move/eqP: i_is_not_0 => i_is_not_0. 
          simpl; lia.
          move/leP: HLenRel => HLenRel. rewrite -?(minusE, plusE) in HLenRel.
          (*move/ltP: HLenBLo => HLenBLo.*) rewrite -?(minusE). 
          move/ltP: i_lt_a_len => i_lt_a_len. rewrite -?(minusE) in i_is_not_eq_border.
          move/eqP: i_is_not_eq_border => i_is_not_eq_border. move/ltP: is_larger => is_larger. rewrite -?(minusE) in is_larger.
          move/eqP: i_is_not_0 => i_is_not_0. 
          split. 
          rewrite -?(rwP leP). simpl; lia.
          rewrite -?(rwP ltP). simpl; lia.
          rewrite repeat_length. rewrite -?(minusE).
          move/leP: HLenRel => HLenRel. rewrite -?(minusE, plusE) in HLenRel.
          (*move/ltP: HLenBLo => HLenBLo.*) rewrite -?(minusE). 
          move/ltP: i_lt_a_len => i_lt_a_len. rewrite -?(minusE) in i_is_not_eq_border.
          move/eqP: i_is_not_eq_border => i_is_not_eq_border. move/ltP: is_larger => is_larger. rewrite -?(minusE) in is_larger.
          move/eqP: i_is_not_0 => i_is_not_0. 
          simpl; lia.
          rewrite repeat_length. rewrite -?(minusE).
          move/leP: HLenRel => HLenRel. rewrite -?(minusE, plusE) in HLenRel.
          (*move/ltP: HLenBLo => HLenBLo.*) rewrite -?(minusE). 
          move/ltP: i_lt_a_len => i_lt_a_len. rewrite -?(minusE) in i_is_not_eq_border.
          move/eqP: i_is_not_eq_border => i_is_not_eq_border. move/ltP: is_larger => is_larger. rewrite -?(minusE) in is_larger.
          move/eqP: i_is_not_0 => i_is_not_0. 
          simpl; lia.
          move/leP: HLenRel => HLenRel. rewrite -?(minusE, plusE) in HLenRel.
          (*move/ltP: HLenBLo => HLenBLo.*) rewrite -?(minusE). 
          move/ltP: i_lt_a_len => i_lt_a_len. rewrite -?(minusE) in i_is_not_eq_border.
          move/eqP: i_is_not_eq_border => i_is_not_eq_border. move/ltP: is_larger => is_larger. rewrite -?(minusE) in is_larger.
          move/eqP: i_is_not_0 => i_is_not_0. 
          simpl; lia. 
          rewrite <- leqNgt in i_not_lt_a_len. 
          assert (i_not_lt_a_len1 := i_not_lt_a_len).
          rewrite <- HLenA in i_not_lt_a_len.
          move/leP: i_not_lt_a_len => i_not_lt_a_len. 
          apply nth_error_None in i_not_lt_a_len. 
          rewrite i_not_lt_a_len. 
          assert (Helper: forall (n : nat) (l : list byte), nth_error l n = None -> None = nth_error l n). 
            intros. rewrite H. reflexivity.
          apply Helper.   
          apply nth_error_None.
          rewrite app_length. rewrite app_length. rewrite app_length. 
          rewrite repeat_length. rewrite HLenB.
          move/leP: HLenRel => HLenRel. rewrite -?(minusE, plusE) in HLenRel.
          (*move/ltP: HLenBLo => HLenBLo.*) rewrite -?(minusE, plusE). 
          rewrite -?(minusE) in i_is_not_eq_border.
          move/eqP: i_is_not_eq_border => i_is_not_eq_border. 
          move/leP: i_not_lt_a_len1 => i_not_lt_a_len1.
          rewrite <- leqNgt in is_larger.
          move/leP: is_larger => is_larger. rewrite -?(minusE) in is_larger.
          move/eqP: i_is_not_0 => i_is_not_0. rewrite -?(rwP leP). 
          simpl; lia.  
Qed.

Lemma custom_simpl_to_zero: 
    forall (i j : nat), i - j - 1 - 2 - (i - j - 3) = 0. 
Proof.
  lia.
Qed.

Lemma list_eq_reflex: 
    forall (l1 : list byte), list_eq l1 l1 = true. 
Proof.
  intros.
  induction l1 as [| n l1' IHl1'].
  - (* l1 = nil *)
    unfold list_eq. reflexivity.
  - (* l1 = cons n l1' *)
    unfold list_eq. fold list_eq. apply Bool.andb_true_iff. split. apply byte_dec_lb. reflexivity. apply IHl1'.
Qed. 

Lemma padding_bytes_all_xff_repeat_xff_true: 
    forall (l : nat), padding_bytes_all_ff (repeat xff l) = true. 
Proof.
  intros l.
  unfold padding_bytes_all_ff. 
  induction l as [| l' IHl'].
  * (* l = O *)
    simpl. reflexivity.
  * (* l = S l' *)
    simpl. apply IHl'.
Qed.

(* The signature verification correctness theorem from the specification *)
Theorem signature_verification_correctness : 
    forall (buff : list byte) (n : nat) (hval : list byte) (halgo : hash_function_id),
      ((signature_verification buff n hval halgo) = true)
      <->
      ((pow 2 (log2 n) = n) /\
       ((length buff) = (n)) /\
       ((length hval) = (h2len halgo)) /\
       ((nth_error buff 0) = (Some x00)) /\
       ((nth_error buff 1) = (Some x01)) /\
       (exists (l1 l2 : nat) (a1 a2 : asb), ((h2asn halgo hval) = (alp a1 l1 a2 l2)) /\ 
         asb_is_valid a1 /\ asb_is_valid a2 /\
         ((n - l1) - 3 >= 8) /\ ((n - l2) - 3 >= 8) /\
         (((forall (i : nat), ((i >= 2) /\ (i < ((n - l1) - 1))) -> ((nth_error buff i) = (Some xff))) /\
          ((nth_error buff ((n - l1) - 1) ) = (Some x00)) /\
          (forall (j : nat), ((j >= 0) /\ (j < l1)) -> ((nth_error buff ((n - l1) + j)) = (nth_error (asb_to_byte a1) j)))
         ) \/
         ((forall (i : nat), ((i >= 2) /\ (i < ((n - l2) - 1))) -> ((nth_error buff i) = (Some xff))) /\
          ((nth_error buff ((n - l2) - 1)) = (Some x00)) /\
          (forall (j : nat), ((j >= 0) /\ (j < l2)) -> ((nth_error buff ((n - l2) + j)) = (nth_error (asb_to_byte a2) j)))
         ))
      )).
Proof.
  split.
  (* -> *)
  intros.
  unfold signature_verification in H.
  destruct ((is_power_of_two n) &&
            (length buff =? n) && 
            (length hval =? h2len halgo)) eqn:Heq1.
  - (* true branch *) 
    destruct (h2asn halgo hval) as [asb1 al1 asb2 al2] eqn:Heq3 in H.
    + destruct 
           ((pkcs_format_is_valid 
             (pkcs (x00) (x01) (repeat xff ((n - al1) - 3)) (x00) asb1)) 
        && (pkcs_format_is_valid 
             (pkcs (x00) (x01) (repeat xff ((n - al2) - 3)) (x00) asb2))) eqn:Heq2.
      * (* true branch *)
        apply Bool.andb_true_iff in Heq2. destruct Heq2 as (Heq2A & Heq2B).
        apply Bool.orb_prop in H. 
        destruct H as [HA|HB]. (* buff is equal to either explict null or impilict null structure *)
        ** (* HA is true *)
          repeat split. (* spilt the goal into subgoals based on conjunctions *)
          (* prove that n is power of two *)
          unfold is_power_of_two in Heq1.
          apply Bool.andb_true_iff in Heq1. destruct Heq1 as (Heq1A & Heq1B).
          apply Bool.andb_true_iff in Heq1A. destruct Heq1A as (Heq1A & Heq1C).
          apply beq_nat_true in Heq1A. 
          apply Heq1A.
          (* prove that buffer length equals n *)
          apply Bool.andb_true_iff in Heq1. destruct Heq1 as (Heq1A & Heq1B).
          apply Bool.andb_true_iff in Heq1A. destruct Heq1A as (Heq1A & Heq1C).
          apply beq_nat_true in Heq1C.
          apply Heq1C.
          (* prove that hash value length equals to what is supposed to be *)
          apply Bool.andb_true_iff in Heq1. destruct Heq1 as (Heq1A & Heq1B).
          apply Bool.andb_true_iff in Heq1A. destruct Heq1A as (Heq1A & Heq1C).
          apply beq_nat_true in Heq1B. 
          apply Heq1B.
          (* prove that buff index 0 is byte x00 *)
          eapply list_eq_correctness in HA. instantiate ( 1 := 0 ) in HA. unfold pkcs_format_to_byte in HA. 
          rewrite ifT in HA. (* it takes if's true branch, because we know that from Heq2A and add the cond as a subgoal *)        
            simpl in HA. simpl. apply HA. 
          apply Heq2A. 
          eapply list_eq_correctness in HA. instantiate ( 1 := 1 ) in HA. unfold pkcs_format_to_byte in HA. 
          rewrite ifT in HA. (* it takes if's true branch, because we know that from Heq2A and add the cond as a subgoal *)        
            simpl in HA. simpl. apply HA. 
          apply Heq2A.
          (* proving asb part *)
          exists al1. exists al2. exists asb1. exists asb2.
            split. apply Heq3.
            repeat split.
            unfold pkcs_format_is_valid in Heq2A. apply Bool.andb_true_iff in Heq2A. destruct Heq2A as (Heq2A & AsbA). apply AsbA.
            unfold pkcs_format_is_valid in Heq2B. apply Bool.andb_true_iff in Heq2B. destruct Heq2B as (Heq2B & AsbB). apply AsbB.
            (* minimum length A *) 
              unfold pkcs_format_is_valid in Heq2A. apply Bool.andb_true_iff in Heq2A.
              destruct Heq2A as (Heq2A1 & Heq2A2).  apply Bool.andb_true_iff in Heq2A1.
              destruct Heq2A1 as (Heq2A1 & Heq2A3). apply Bool.andb_true_iff in Heq2A1.
              destruct Heq2A1 as (Heq2A1 & Heq2A4). apply Bool.andb_true_iff in Heq2A1.
              destruct Heq2A1 as (Heq2A1 & Heq2A5).
              unfold padding_bytes_length_ge_8_and_all_ff in Heq2A4.
              rewrite <- Bool.andb_lazy_alt in Heq2A4. apply Bool.andb_true_iff in Heq2A4.
              destruct Heq2A4 as (Heq2A4A & Heq2A4B). apply leb_complete in Heq2A4A. 
              rewrite length_repeat_elim in Heq2A4A.
              rewrite -?(rwP ltP). (* this rewrite is crucial before lia *) lia.
              (* minimum length B *) 
              unfold pkcs_format_is_valid in Heq2B. apply Bool.andb_true_iff in Heq2B.
              destruct Heq2B as (Heq2B1 & Heq2B2).  apply Bool.andb_true_iff in Heq2B1.
              destruct Heq2B1 as (Heq2B1 & Heq2B3). apply Bool.andb_true_iff in Heq2B1.
              destruct Heq2B1 as (Heq2B1 & Heq2B4). apply Bool.andb_true_iff in Heq2B1.
              destruct Heq2B1 as (Heq2B1 & Heq2B5).
              unfold padding_bytes_length_ge_8_and_all_ff in Heq2B4.
              rewrite <- Bool.andb_lazy_alt in Heq2B4. apply Bool.andb_true_iff in Heq2B4.
              destruct Heq2B4 as (Heq2B4A & Heq2B4B). apply leb_complete in Heq2B4A.
              rewrite length_repeat_elim in Heq2B4A.
              rewrite -?(rwP ltP). (* this rewrite is crucial before lia *) lia.

            left. repeat split.

              (* padding bytes are all xFF *)
              intros i i_range.
              eapply list_eq_correctness in HA. instantiate ( 1 := i ) in HA. unfold pkcs_format_to_byte in HA. 
              rewrite ifT in HA. (* it takes if's true branch, because we know that from Heq2A and add the cond as a subgoal *)        
              rewrite nth_error_app2 in HA. simpl in HA. rewrite nth_error_app1 in HA.
              rewrite nth_error_repeat_elim in HA. apply HA.
              destruct i_range as (i_range_l & i_range_u). 
              rewrite -?(rwP ltP). apply (rwP ltP) in i_range_u. apply (rwP ltP) in i_range_l. lia.
              rewrite repeat_length. destruct i_range as (i_range_l & i_range_u). apply (rwP ltP) in i_range_u. apply (rwP ltP) in i_range_l. lia.
              simpl. destruct i_range as (i_range_l & i_range_u). apply (rwP ltP) in i_range_u. apply (rwP ltP) in i_range_l. lia.
              apply Heq2A.

              (* after padding bytes we have x00 *)
              eapply list_eq_correctness in HA. instantiate ( 1 := (n - al1 - 1) ) in HA. unfold pkcs_format_to_byte in HA. 
              rewrite ifT in HA. (* it takes if's true branch, because we know that from Heq2A and add the cond as a subgoal *)        
              rewrite nth_error_app2 in HA. rewrite nth_error_app2 in HA. rewrite nth_error_app1 in HA. simpl in HA. 
              rewrite length_repeat_elim in HA.
              rewrite custom_simpl_to_zero in HA. simpl in HA. apply HA.
              simpl. rewrite length_repeat_elim. lia. 
              simpl. rewrite length_repeat_elim. lia.
              simpl. 
                unfold pkcs_format_is_valid in Heq2A. apply Bool.andb_true_iff in Heq2A.
                destruct Heq2A as (Heq2A1 & Heq2A2).  apply Bool.andb_true_iff in Heq2A1.
                destruct Heq2A1 as (Heq2A1 & Heq2A3). apply Bool.andb_true_iff in Heq2A1.
                destruct Heq2A1 as (Heq2A1 & Heq2A4). apply Bool.andb_true_iff in Heq2A1.
                destruct Heq2A1 as (Heq2A1 & Heq2A5).
                unfold padding_bytes_length_ge_8_and_all_ff in Heq2A4.
                rewrite <- Bool.andb_lazy_alt in Heq2A4. apply Bool.andb_true_iff in Heq2A4.
                destruct Heq2A4 as (Heq2A4A & Heq2A4B). apply leb_complete in Heq2A4A.
                rewrite length_repeat_elim in Heq2A4A. lia. 
                apply Heq2A.
                
              (* after x00 byte we have asb structure *)
              intros j j_range. 
              eapply list_eq_correctness in HA. instantiate ( 1 := (n - al1 + j)%coq_nat ) in HA. unfold pkcs_format_to_byte in HA. 
              rewrite ifT in HA. (* it takes if's true branch, because we know that from Heq2A and add the cond as a subgoal *)        
              rewrite nth_error_app2 in HA. rewrite nth_error_app2 in HA. rewrite nth_error_app2 in HA. simpl in HA.
              rewrite length_repeat_elim in HA. 
              
              assert (j_range' := j_range).  destruct j_range' as (j_range1 & j_range2).
              apply (rwP leP) in j_range1. apply (rwP ltP) in j_range2. 
              assert (Heq2A' := Heq2A). 
              unfold pkcs_format_is_valid in Heq2A'. apply Bool.andb_true_iff in Heq2A'.
              destruct Heq2A' as (Heq2A1' & Heq2A2').  apply Bool.andb_true_iff in Heq2A1'.
              destruct Heq2A1' as (Heq2A1' & Heq2A3'). apply Bool.andb_true_iff in Heq2A1'.
              destruct Heq2A1' as (Heq2A1' & Heq2A4'). apply Bool.andb_true_iff in Heq2A1'.
              destruct Heq2A1' as (Heq2A1' & Heq2A5').
              unfold padding_bytes_length_ge_8_and_all_ff in Heq2A4'.
              rewrite <- Bool.andb_lazy_alt in Heq2A4'. apply Bool.andb_true_iff in Heq2A4'.
              destruct Heq2A4' as (Heq2A4A' & Heq2A4B'). apply leb_complete in Heq2A4A'.
              rewrite length_repeat_elim in Heq2A4A'.
              rewrite -?(rwP ltP). rewrite HA. apply f_equal. lia.

              simpl. rewrite length_repeat_elim.   
  
              assert (j_range' := j_range).  destruct j_range' as (j_range1 & j_range2).
              apply (rwP leP) in j_range1. apply (rwP ltP) in j_range2. 
              assert (Heq2A' := Heq2A). 
              unfold pkcs_format_is_valid in Heq2A'. apply Bool.andb_true_iff in Heq2A'.
              destruct Heq2A' as (Heq2A1' & Heq2A2').  apply Bool.andb_true_iff in Heq2A1'.
              destruct Heq2A1' as (Heq2A1' & Heq2A3'). apply Bool.andb_true_iff in Heq2A1'.
              destruct Heq2A1' as (Heq2A1' & Heq2A4'). apply Bool.andb_true_iff in Heq2A1'.
              destruct Heq2A1' as (Heq2A1' & Heq2A5').
              unfold padding_bytes_length_ge_8_and_all_ff in Heq2A4'.
              rewrite <- Bool.andb_lazy_alt in Heq2A4'. apply Bool.andb_true_iff in Heq2A4'.
              destruct Heq2A4' as (Heq2A4A' & Heq2A4B'). apply leb_complete in Heq2A4A'.
              rewrite length_repeat_elim in Heq2A4A'.
              rewrite -?(rwP ltP). lia.

              simpl. rewrite length_repeat_elim.
              destruct j_range as (j_range_l & j_range_u). 
              apply (rwP ltP) in j_range_u. apply (rwP leP) in j_range_l. lia.
              simpl. destruct j_range as (j_range_l & j_range_u). 
                apply (rwP ltP) in j_range_u. apply (rwP leP) in j_range_l.
                unfold pkcs_format_is_valid in Heq2A. apply Bool.andb_true_iff in Heq2A.
                destruct Heq2A as (Heq2A1 & Heq2A2).  apply Bool.andb_true_iff in Heq2A1.
                destruct Heq2A1 as (Heq2A1 & Heq2A3). apply Bool.andb_true_iff in Heq2A1.
                destruct Heq2A1 as (Heq2A1 & Heq2A4). apply Bool.andb_true_iff in Heq2A1.
                destruct Heq2A1 as (Heq2A1 & Heq2A5).
                unfold padding_bytes_length_ge_8_and_all_ff in Heq2A4.
                rewrite <- Bool.andb_lazy_alt in Heq2A4. apply Bool.andb_true_iff in Heq2A4.
                destruct Heq2A4 as (Heq2A4A & Heq2A4B). apply leb_complete in Heq2A4A.
                rewrite length_repeat_elim in Heq2A4A. lia. 
                apply Heq2A.
        ** (* HB is true *)
          repeat split. (* spilt the goal into subgoals based on conjunctions *)
          (* prove that n is power of two *)
          unfold is_power_of_two in Heq1.
          apply Bool.andb_true_iff in Heq1. destruct Heq1 as (Heq1A & Heq1B).
          apply Bool.andb_true_iff in Heq1A. destruct Heq1A as (Heq1A & Heq1C).
          apply beq_nat_true in Heq1A. 
          apply Heq1A.
          (* prove that buffer length equals n *)
          apply Bool.andb_true_iff in Heq1. destruct Heq1 as (Heq1A & Heq1B).
          apply Bool.andb_true_iff in Heq1A. destruct Heq1A as (Heq1A & Heq1C).
          apply beq_nat_true in Heq1C.
          apply Heq1C.
          (* prove that hash value length equals to what is supposed to be *)
          apply Bool.andb_true_iff in Heq1. destruct Heq1 as (Heq1A & Heq1B).
          apply Bool.andb_true_iff in Heq1A. destruct Heq1A as (Heq1A & Heq1C).
          apply beq_nat_true in Heq1B. 
          apply Heq1B.
          (* prove that buff index 0 is byte x00 *) 
          eapply list_eq_correctness in HB. instantiate ( 1 := 0 ) in HB. unfold pkcs_format_to_byte in HB. 
          rewrite ifT in HB. (* it takes if's true branch, because we know that from Heq2B and add the cond as a subgoal *)        
            simpl in HB. simpl. apply HB. 
          apply Heq2B.
          eapply list_eq_correctness in HB. instantiate ( 1 := 1 ) in HB. unfold pkcs_format_to_byte in HB. 
          rewrite ifT in HB. (* it takes if's true branch, because we know that from Heq2B and add the cond as a subgoal *)        
            simpl in HB. simpl. apply HB. 
          apply Heq2B.
          (* proving asb part *)
          exists al1. exists al2. exists asb1. exists asb2.
            split. apply Heq3.
            repeat split.
            unfold pkcs_format_is_valid in Heq2A. apply Bool.andb_true_iff in Heq2A. destruct Heq2A as (Heq2A & AsbA). apply AsbA.
            unfold pkcs_format_is_valid in Heq2B. apply Bool.andb_true_iff in Heq2B. destruct Heq2B as (Heq2B & AsbB). apply AsbB.
            (* minimum length A *) 
              unfold pkcs_format_is_valid in Heq2A. apply Bool.andb_true_iff in Heq2A.
              destruct Heq2A as (Heq2A1 & Heq2A2).  apply Bool.andb_true_iff in Heq2A1.
              destruct Heq2A1 as (Heq2A1 & Heq2A3). apply Bool.andb_true_iff in Heq2A1.
              destruct Heq2A1 as (Heq2A1 & Heq2A4). apply Bool.andb_true_iff in Heq2A1.
              destruct Heq2A1 as (Heq2A1 & Heq2A5).
              unfold padding_bytes_length_ge_8_and_all_ff in Heq2A4.
              rewrite <- Bool.andb_lazy_alt in Heq2A4. apply Bool.andb_true_iff in Heq2A4.
              destruct Heq2A4 as (Heq2A4A & Heq2A4B). apply leb_complete in Heq2A4A.
              rewrite length_repeat_elim in Heq2A4A.
              rewrite -?(rwP ltP). (* this rewrite is crucial before lia *) lia.
              (* minimum length B *) 
              unfold pkcs_format_is_valid in Heq2B. apply Bool.andb_true_iff in Heq2B.
              destruct Heq2B as (Heq2B1 & Heq2B2).  apply Bool.andb_true_iff in Heq2B1.
              destruct Heq2B1 as (Heq2B1 & Heq2B3). apply Bool.andb_true_iff in Heq2B1.
              destruct Heq2B1 as (Heq2B1 & Heq2B4). apply Bool.andb_true_iff in Heq2B1.
              destruct Heq2B1 as (Heq2B1 & Heq2B5).
              unfold padding_bytes_length_ge_8_and_all_ff in Heq2B4.
              rewrite <- Bool.andb_lazy_alt in Heq2B4. apply Bool.andb_true_iff in Heq2B4.
              destruct Heq2B4 as (Heq2B4A & Heq2B4B). apply leb_complete in Heq2B4A.
              rewrite length_repeat_elim in Heq2B4A.
              rewrite -?(rwP ltP). (* this rewrite is crucial before lia *) lia.

            right. repeat split.
              
              (* padding bytes are all xFF *)
              intros i i_range. 
              eapply list_eq_correctness in HB. instantiate ( 1 := i ) in HB. unfold pkcs_format_to_byte in HB. 
              rewrite ifT in HB. (* it takes if's true branch, because we know that from Heq2B and add the cond as a subgoal *)        
              rewrite nth_error_app2 in HB. simpl in HB. rewrite nth_error_app1 in HB.
              rewrite nth_error_repeat_elim in HB. apply HB.
              destruct i_range as (i_range_l & i_range_u). 
              rewrite -?(rwP ltP). apply (rwP ltP) in i_range_u. apply (rwP ltP) in i_range_l. lia.
              rewrite repeat_length. destruct i_range as (i_range_l & i_range_u). apply (rwP ltP) in i_range_u. apply (rwP ltP) in i_range_l. lia.
              simpl. destruct i_range as (i_range_l & i_range_u). apply (rwP ltP) in i_range_u. apply (rwP ltP) in i_range_l. lia.
              apply Heq2B.

              (* after padding bytes we have x00 *)
              eapply list_eq_correctness in HB. instantiate ( 1 := (n - al2 - 1) ) in HB. unfold pkcs_format_to_byte in HB. 
              rewrite ifT in HB. (* it takes if's true branch, because we know that from Heq2B and add the cond as a subgoal *)        
              rewrite nth_error_app2 in HB. rewrite nth_error_app2 in HB. rewrite nth_error_app1 in HB. simpl in HB. 
              rewrite length_repeat_elim in HB.
              rewrite custom_simpl_to_zero in HB. simpl in HB. apply HB.
              simpl. rewrite length_repeat_elim. lia. 
              simpl. rewrite length_repeat_elim. lia.
              simpl. 
                unfold pkcs_format_is_valid in Heq2B. apply Bool.andb_true_iff in Heq2B.
                destruct Heq2B as (Heq2B1 & Heq2B2).  apply Bool.andb_true_iff in Heq2B1.
                destruct Heq2B1 as (Heq2B1 & Heq2B3). apply Bool.andb_true_iff in Heq2B1.
                destruct Heq2B1 as (Heq2B1 & Heq2B4). apply Bool.andb_true_iff in Heq2B1.
                destruct Heq2B1 as (Heq2B1 & Heq2B5).
                unfold padding_bytes_length_ge_8_and_all_ff in Heq2B4.
                rewrite <- Bool.andb_lazy_alt in Heq2B4. apply Bool.andb_true_iff in Heq2B4.
                destruct Heq2B4 as (Heq2B4A & Heq2B4B). apply leb_complete in Heq2B4A.
                rewrite length_repeat_elim in Heq2B4A. lia. 
                apply Heq2B.
                
              (* after x00 byte we have asb structure *)
              intros j j_range.
              eapply list_eq_correctness in HB. instantiate ( 1 := (n - al2 + j) ) in HB. unfold pkcs_format_to_byte in HB. 
              rewrite ifT in HB. (* it takes if's true branch, because we know that from Heq2B and add the cond as a subgoal *)        
              rewrite nth_error_app2 in HB. rewrite nth_error_app2 in HB. rewrite nth_error_app2 in HB. simpl in HB.
              rewrite length_repeat_elim in HB.

              assert (j_range' := j_range).  destruct j_range' as (j_range1 & j_range2).
              apply (rwP leP) in j_range1. apply (rwP ltP) in j_range2. 
              assert (Heq2A' := Heq2B). 
              unfold pkcs_format_is_valid in Heq2A'. apply Bool.andb_true_iff in Heq2A'.
              destruct Heq2A' as (Heq2A1' & Heq2A2').  apply Bool.andb_true_iff in Heq2A1'.
              destruct Heq2A1' as (Heq2A1' & Heq2A3'). apply Bool.andb_true_iff in Heq2A1'.
              destruct Heq2A1' as (Heq2A1' & Heq2A4'). apply Bool.andb_true_iff in Heq2A1'.
              destruct Heq2A1' as (Heq2A1' & Heq2A5').
              unfold padding_bytes_length_ge_8_and_all_ff in Heq2A4'.
              rewrite <- Bool.andb_lazy_alt in Heq2A4'. apply Bool.andb_true_iff in Heq2A4'.
              destruct Heq2A4' as (Heq2A4A' & Heq2A4B'). apply leb_complete in Heq2A4A'.
              rewrite length_repeat_elim in Heq2A4A'.
              rewrite -?(rwP ltP). rewrite HB. apply f_equal. lia.

              simpl. rewrite length_repeat_elim.

              assert (j_range' := j_range).  destruct j_range' as (j_range1 & j_range2).
              apply (rwP leP) in j_range1. apply (rwP ltP) in j_range2. 
              assert (Heq2A' := Heq2B). 
              unfold pkcs_format_is_valid in Heq2A'. apply Bool.andb_true_iff in Heq2A'.
              destruct Heq2A' as (Heq2A1' & Heq2A2').  apply Bool.andb_true_iff in Heq2A1'.
              destruct Heq2A1' as (Heq2A1' & Heq2A3'). apply Bool.andb_true_iff in Heq2A1'.
              destruct Heq2A1' as (Heq2A1' & Heq2A4'). apply Bool.andb_true_iff in Heq2A1'.
              destruct Heq2A1' as (Heq2A1' & Heq2A5').
              unfold padding_bytes_length_ge_8_and_all_ff in Heq2A4'.
              rewrite <- Bool.andb_lazy_alt in Heq2A4'. apply Bool.andb_true_iff in Heq2A4'.
              destruct Heq2A4' as (Heq2A4A' & Heq2A4B'). apply leb_complete in Heq2A4A'.
              rewrite length_repeat_elim in Heq2A4A'.
              rewrite -?(rwP ltP). lia.

              simpl. rewrite length_repeat_elim.
              destruct j_range as (j_range_l & j_range_u). 
              apply (rwP ltP) in j_range_u. apply (rwP leP) in j_range_l. lia.
              simpl. destruct j_range as (j_range_l & j_range_u). 
                apply (rwP ltP) in j_range_u. apply (rwP leP) in j_range_l.
                unfold pkcs_format_is_valid in Heq2B. apply Bool.andb_true_iff in Heq2B.
                destruct Heq2B as (Heq2B1 & Heq2B2).  apply Bool.andb_true_iff in Heq2B1.
                destruct Heq2B1 as (Heq2B1 & Heq2B3). apply Bool.andb_true_iff in Heq2B1.
                destruct Heq2B1 as (Heq2B1 & Heq2B4). apply Bool.andb_true_iff in Heq2B1.
                destruct Heq2B1 as (Heq2B1 & Heq2B5).
                unfold padding_bytes_length_ge_8_and_all_ff in Heq2B4.
                rewrite <- Bool.andb_lazy_alt in Heq2B4. apply Bool.andb_true_iff in Heq2B4.
                destruct Heq2B4 as (Heq2B4A & Heq2B4B). apply leb_complete in Heq2B4A.
                rewrite length_repeat_elim in Heq2B4A. lia. 
                apply Heq2B.

      * (* false branch *) (* trivially true cause antecedant is false *)
        discriminate.
  - (* false branch *) (* trivially true cause antecedant is false *)
    discriminate.

  (* <- *) 
  intros. destruct H as (HLog2 & H). destruct H as (HBuffEqN & H). destruct H as (HHvalLen & H).
  destruct H as (Buff0 & H). destruct H as (Buff1 & H). 
  unfold signature_verification. rewrite ifT. destruct (h2asn halgo hval) as [a1 l1 a2 l2] eqn:HeqPair. 
  destruct H as (l1' & H). destruct H as (l2' & H).
  destruct H as (a1' & H). destruct H as (a2' & H).  destruct H as (HeqPair' & H). 
  apply alp_injective in HeqPair'. 
    destruct HeqPair' as (Ha1a1' & HeqPair'). 
    destruct HeqPair' as (Hl1l1' & HeqPair').
    destruct HeqPair' as (Ha2a2' & Hl2l2'). 
    rewrite <- Ha1a1' in H. rewrite <- Hl1l1' in H. rewrite <- Ha2a2' in H. rewrite <- Hl2l2' in H. 
  destruct H as (AsbA & AsbB & NL1_Rel & NL2_Rel & H).
  assert (HeqPair' := HeqPair).
  apply h2asn_asb_len_correlation in HeqPair'. destruct HeqPair' as (Ha1_len & Ha2_len).
  destruct H as [HA | HB].
    (* HA *)  
    rewrite ifT. apply Bool.orb_true_intro. left. 
    unfold pkcs_format_to_byte. rewrite ifT. simpl. 
      (* Form the spec to be used by build_from_spec *)
      assert (HBuff_1 := conj HBuffEqN Ha1_len).
      assert (HBuff_2 := conj HBuff_1 NL1_Rel).
      assert (HBuff_3 := conj HBuff_2 Buff0).
      assert (HBuff_4 := conj HBuff_3 Buff1).
      assert (HBuff_5 := conj HBuff_4 HA).
      apply build_from_spec in HBuff_5.
      rewrite HBuff_5. simpl.
      apply list_eq_reflex.

      (* validity *)
      unfold pkcs_format_is_valid. 
        apply Bool.andb_true_iff. split. apply Bool.andb_true_iff. split.
        apply Bool.andb_true_iff. split. apply Bool.andb_true_iff. split.
        apply byte_dec_lb. reflexivity. apply byte_dec_lb. reflexivity.
        unfold padding_bytes_length_ge_8_and_all_ff. rewrite ifT. 
        apply padding_bytes_all_xff_repeat_xff_true.
        apply leb_correct. rewrite repeat_length. apply (rwP ltP) in NL1_Rel. lia.
        apply byte_dec_lb. reflexivity. apply AsbA.
        apply Bool.andb_true_iff. split.
        unfold pkcs_format_is_valid. 
          apply Bool.andb_true_iff. split. apply Bool.andb_true_iff. split.
          apply Bool.andb_true_iff. split. apply Bool.andb_true_iff. split.
          apply byte_dec_lb. reflexivity. apply byte_dec_lb. reflexivity.
          unfold padding_bytes_length_ge_8_and_all_ff. rewrite ifT. 
          apply padding_bytes_all_xff_repeat_xff_true.
          apply leb_correct. rewrite repeat_length. apply (rwP ltP) in NL1_Rel. lia.
          apply byte_dec_lb. reflexivity. apply AsbA.
        unfold pkcs_format_is_valid. 
          apply Bool.andb_true_iff. split. apply Bool.andb_true_iff. split.
          apply Bool.andb_true_iff. split. apply Bool.andb_true_iff. split.
          apply byte_dec_lb. reflexivity. apply byte_dec_lb. reflexivity.
          unfold padding_bytes_length_ge_8_and_all_ff. rewrite ifT. 
          apply padding_bytes_all_xff_repeat_xff_true.
          apply leb_correct. rewrite repeat_length. apply (rwP ltP) in NL2_Rel. lia.
          apply byte_dec_lb. reflexivity. apply AsbB.
    
    (* HB *)
    rewrite ifT. apply Bool.orb_true_intro. right. 
    unfold pkcs_format_to_byte. rewrite ifT. simpl. 
      (* Form the spec to be used by build_from_spec *)
      assert (HBuff_1 := conj HBuffEqN Ha2_len).
      assert (HBuff_2 := conj HBuff_1 NL2_Rel).
      assert (HBuff_3 := conj HBuff_2 Buff0).
      assert (HBuff_4 := conj HBuff_3 Buff1).
      assert (HBuff_5 := conj HBuff_4 HB).
      apply build_from_spec in HBuff_5.
      rewrite HBuff_5. simpl.
      apply list_eq_reflex.

      (* validity *)
      unfold pkcs_format_is_valid. 
        apply Bool.andb_true_iff. split. apply Bool.andb_true_iff. split.
        apply Bool.andb_true_iff. split. apply Bool.andb_true_iff. split.
        apply byte_dec_lb. reflexivity. apply byte_dec_lb. reflexivity.
        unfold padding_bytes_length_ge_8_and_all_ff. rewrite ifT. 
        apply padding_bytes_all_xff_repeat_xff_true.
        apply leb_correct. rewrite repeat_length. apply (rwP ltP) in NL2_Rel. lia.
        apply byte_dec_lb. reflexivity. apply AsbB.
        apply Bool.andb_true_iff. split.
        unfold pkcs_format_is_valid. 
          apply Bool.andb_true_iff. split. apply Bool.andb_true_iff. split.
          apply Bool.andb_true_iff. split. apply Bool.andb_true_iff. split.
          apply byte_dec_lb. reflexivity. apply byte_dec_lb. reflexivity.
          unfold padding_bytes_length_ge_8_and_all_ff. rewrite ifT. 
          apply padding_bytes_all_xff_repeat_xff_true.
          apply leb_correct. rewrite repeat_length. apply (rwP ltP) in NL1_Rel. lia.
          apply byte_dec_lb. reflexivity. apply AsbA.
        unfold pkcs_format_is_valid. 
          apply Bool.andb_true_iff. split. apply Bool.andb_true_iff. split.
          apply Bool.andb_true_iff. split. apply Bool.andb_true_iff. split.
          apply byte_dec_lb. reflexivity. apply byte_dec_lb. reflexivity.
          unfold padding_bytes_length_ge_8_and_all_ff. rewrite ifT. 
          apply padding_bytes_all_xff_repeat_xff_true.
          apply leb_correct. rewrite repeat_length. apply (rwP ltP) in NL2_Rel. lia.
          apply byte_dec_lb. reflexivity. apply AsbB.

  (* n is power of two and lengths match *)
  apply Bool.andb_true_iff. split. apply Bool.andb_true_iff. split. unfold is_power_of_two. apply Nat.eqb_eq. apply HLog2.
  apply Nat.eqb_eq. apply HBuffEqN.
  apply Nat.eqb_eq. apply HHvalLen.
Qed.

(* Causes Coq to use OCaml's definitions of bool, list, etc in the extracted code      *)
(* We want our extracted functions to be compatible with, i.e. callable by, ordinary *)
(* OCaml code. So we want to use OCaml's standard definition.                        *)
Extract Inductive bool => "bool" [ "true" "false" ].
Extract Inductive list => "list" [ "[]" "(::)" ].
Extract Inductive prod => "(*)"  [ "(,)" ].
Extract Inductive nat => int [ "0" "succ" ] "(fun fO fS n -> if n=0 then fO () else fS (n-1))".

Recursive Extraction signature_verification.
Extraction "pkcs1.ml" signature_verification.
