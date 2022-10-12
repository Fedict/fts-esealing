Intro
-----
Simple eSealing (server signing) service based on the a subset of the TS 119 432 standard
https://www.etsi.org/deliver/etsi_ts/119400_119499/119432/01.01.01_60/ts_119432v010101p.pdf

More specifically, we decided to implement the JSON binding for the following 3 functions/endpoints:
 /credentials/list
 /credentials/info
 /signatures/signHash
For more info, see "BOSA eSealing proposal 5.docx"

The classes in src/main/java/com/bosa/esealing/model/ are based on the definitions in this standard.
As choice for the 'SAD' data, a JWS (signed JSON) containing the hashes to be signed has been chosen.

The actual logic is in src/main/java/com/bosa/esealing/service.
It contains a HsmPkcs11.java that goes to an HSM via pkcs11 to access the eSealing keys/certs and to sign with them.
There is also a HsmSoft.java containing a harcoded keystore, in case no HSM is present.

Currently, the HSM that is used for the demo is softhsm2, see hsm/ for more info.
But it should be possible to use any HSM that allows for multiple slots (see HsmPkcs11.java for more info)

Usage
----- 
This service is meant as a proof of concept and a demo.
However, it could be used for real if a real HSM operated in a trust center would be used,
accompanied by the necessary access controls, policies, certification, audits, ...

Important to note is that the setup of the keys for the customers (generation of the keys on the HSM,
issuing certificates for these keys and importing the certificate chains) is NOT part of this solution;
it is expected to be done already.
