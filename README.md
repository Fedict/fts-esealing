This is for esealing.

IMPORTANT Warning :

    This code uses https://github.com/xipki/pkcs11wrapper
    To use pkcs11wrapper in JDK 17 or above, please add the following java option:

                --add-exports=jdk.crypto.cryptoki/sun.security.pkcs11.wrapper=ALL-UNNAMED

    Failing to do so will cause the below error : 

        Exception in thread "main" java.lang.IllegalAccessError: class iaik.pkcs.pkcs11.Module (in unnamed module @0x18769467) cannot access class sun.security.pkcs11.wrapper.PKCS11Exception (in module jdk.crypto.cryptoki) because module jdk.crypto.cryptoki does not export sun.security.pkcs11.wrapper to unnamed module @0x18769467
        at iaik.pkcs.pkcs11.Module.initialize(Module.java:323)
        at com.bosa.esealing.TestPkcs11.main(TestPkcs11.java:55)

