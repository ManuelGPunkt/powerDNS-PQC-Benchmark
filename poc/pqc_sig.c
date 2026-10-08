#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <oqs/oqs.h>


/* ============================================================
 * Generische Struktur für einen Signaturalgorithmus
 * ============================================================ */

struct signature_t {
    OQS_STATUS status;

    uint8_t *public_key;
    uint8_t *secret_key;
    uint8_t *signature;

    size_t signature_len;
    size_t message_len;
};


/* ============================================================
 * Typen für die liboqs-Funktionszeiger
 * ============================================================ */

typedef OQS_STATUS (*keypair_func_t)(
    uint8_t *public_key,
    uint8_t *secret_key
);

typedef OQS_STATUS (*sign_func_t)(
    uint8_t *signature,
    size_t *signature_len,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *secret_key
);

typedef OQS_STATUS (*verify_func_t)(
    const uint8_t *message,
    size_t message_len,
    const uint8_t *signature,
    size_t signature_len,
    const uint8_t *public_key
);


/* ============================================================
 * Generische Funktion:
 *
 * 1. Speicher mit Struct verbinden
 * 2. Keypair erzeugen
 * 3. Nachricht signieren
 * 4. Signatur verifizieren
 * ============================================================ */

OQS_STATUS sign_and_verify(
    const char *algname,
    const char *message_to_sign,
    struct signature_t *sig,

    uint8_t *public_key,
    uint8_t *secret_key,
    uint8_t *signature,

    keypair_func_t keypair_function,
    sign_func_t sign_function,
    verify_func_t verify_function
)
{
    /* --------------------------------------------------------
     * Pointer auf den extern bereitgestellten Speicher setzen
     * -------------------------------------------------------- */

    sig->public_key = public_key;
    sig->secret_key = secret_key;
    sig->signature  = signature;


    /* --------------------------------------------------------
     * Nachrichtenlänge bestimmen
     * -------------------------------------------------------- */

    sig->message_len = strlen(message_to_sign);


    /* --------------------------------------------------------
     * Anfangswerte
     * -------------------------------------------------------- */

    sig->signature_len = 0;
    sig->status = OQS_ERROR;


    /* --------------------------------------------------------
     * Informationen ausgeben
     * -------------------------------------------------------- */

    printf("\n========================================\n");
    printf("%s\n", algname);
    printf("========================================\n");

    printf("Nachricht:        %s\n", message_to_sign);
    printf("Nachrichtenlänge: %zu\n", sig->message_len);

    printf("Public Key:       %p\n",
           (void *)sig->public_key);

    printf("Secret Key:       %p\n",
           (void *)sig->secret_key);

    printf("Signature:        %p\n",
           (void *)sig->signature);


    /* --------------------------------------------------------
     * Keypair erzeugen
     * -------------------------------------------------------- */

    sig->status = keypair_function(
        sig->public_key,
        sig->secret_key
    );

    if (sig->status != OQS_SUCCESS) {
        printf("[%s] Fehler bei der Schlüsselerzeugung!\n",
               algname);

        return sig->status;
    }

    printf("[%s] Keypair erfolgreich erzeugt.\n",
           algname);


    /* --------------------------------------------------------
     * Nachricht signieren
     * -------------------------------------------------------- */

    sig->status = sign_function(
        sig->signature,
        &sig->signature_len,
        (const uint8_t *)message_to_sign,
        sig->message_len,
        sig->secret_key
    );

    if (sig->status != OQS_SUCCESS) {
        printf("[%s] Fehler beim Signieren!\n",
               algname);

        return sig->status;
    }

    printf("[%s] Signatur erfolgreich erzeugt.\n",
           algname);

    printf("[%s] Signaturlänge: %zu\n",
           algname,
           sig->signature_len);


    /* --------------------------------------------------------
     * Signatur verifizieren
     * -------------------------------------------------------- */

    sig->status = verify_function(
        (const uint8_t *)message_to_sign,
        sig->message_len,
        sig->signature,
        sig->signature_len,
        sig->public_key
    );

    if (sig->status != OQS_SUCCESS) {
        printf("[%s] Verification failed!\n",
               algname);

        return sig->status;
    }

    printf("[%s] Verification success!\n",
           algname);


    return OQS_SUCCESS;
}


/* ============================================================
 * Beispielprogramm
 * ============================================================ */

int main(void)
{
    const char *message_to_sign =
        "diese Nachricht soll signiert und verifiziert werden";


    /* ========================================================
     * ML-DSA-44 Speicher
     * ======================================================== */

    uint8_t mldsa_public_key[
        OQS_SIG_ml_dsa_44_length_public_key
    ];

    uint8_t mldsa_secret_key[
        OQS_SIG_ml_dsa_44_length_secret_key
    ];

    uint8_t mldsa_signature[
        OQS_SIG_ml_dsa_44_length_signature
    ];


    /* ========================================================
     * Struct für ML-DSA
     * ======================================================== */

    struct signature_t mldsa = {0};


    /* ========================================================
     * ML-DSA ausführen
     * ======================================================== */

    OQS_STATUS status = sign_and_verify(
        "ML-DSA-44",
        message_to_sign,
        &mldsa,

        mldsa_public_key,
        mldsa_secret_key,
        mldsa_signature,

        OQS_SIG_ml_dsa_44_keypair,
        OQS_SIG_ml_dsa_44_sign,
        OQS_SIG_ml_dsa_44_verify
    );


    if (status != OQS_SUCCESS) {
        fprintf(stderr,
                "ML-DSA-44 fehlgeschlagen.\n");

        return EXIT_FAILURE;
    }


    printf("\nML-DSA-44 erfolgreich abgeschlossen.\n");
    
    
    /* ============================================================
    * Falcon initialisieren
    * ============================================================ */
    
    struct signature_t falcon = {0};

    uint8_t falcon_public_key[
        OQS_SIG_falcon_512_length_public_key
    ];

    uint8_t falcon_secret_key[
        OQS_SIG_falcon_512_length_secret_key
    ];

    uint8_t falcon_signature[
        OQS_SIG_falcon_512_length_signature
    ];

    OQS_STATUS status_falcon = sign_and_verify(
        "Falcon-512",
        message_to_sign,
        &falcon,

        falcon_public_key,
        falcon_secret_key,
        falcon_signature,

        OQS_SIG_falcon_512_keypair,
        OQS_SIG_falcon_512_sign,
        OQS_SIG_falcon_512_verify
    );
    
    if (status_falcon != OQS_SUCCESS) {
      fprintf(stderr, "Falcon-512 fehlgeschlagen!\n");
      return EXIT_FAILURE;
      }
      
    puts("Falcon-512 erfolgreich!");


    /* ============================================================
    * Mayo initialisieren
    * ============================================================ */

struct signature_t mayo = {0};

uint8_t mayo_public_key[
    OQS_SIG_mayo_1_length_public_key
];

uint8_t mayo_secret_key[
    OQS_SIG_mayo_1_length_secret_key
];

uint8_t mayo_signature[
    OQS_SIG_mayo_1_length_signature
];

OQS_STATUS status_mayo = sign_and_verify(
    "Mayo-1",
    message_to_sign,
    &mayo,

    mayo_public_key,
    mayo_secret_key,
    mayo_signature,

    OQS_SIG_mayo_1_keypair,
    OQS_SIG_mayo_1_sign,
    OQS_SIG_mayo_1_verify
);

    if (status_mayo != OQS_SUCCESS) {
      fprintf(stderr, "Falcon-512 fehlgeschlagen!\n");
      return EXIT_FAILURE;
      }
      
    puts("Mayo_1 erfolgreich!");


    /* ============================================================
    * CROSS initialisieren
    * ============================================================ */
    
    struct signature_t cross = {0};

    uint8_t cross_public_key[
        OQS_SIG_cross_rsdp_128_balanced_length_public_key
    ];

    uint8_t cross_secret_key[
        OQS_SIG_cross_rsdp_128_balanced_length_secret_key
    ];

    uint8_t cross_signature[
        OQS_SIG_cross_rsdp_128_balanced_length_signature
    ];

    OQS_STATUS status_cross = sign_and_verify(
        "CROSS",
        message_to_sign,
        &cross,

        cross_public_key,
        cross_secret_key,
        cross_signature,

        OQS_SIG_cross_rsdp_128_balanced_keypair,
        OQS_SIG_cross_rsdp_128_balanced_sign,
        OQS_SIG_cross_rsdp_128_balanced_verify
    );
    
    if (status_cross != OQS_SUCCESS) {
      fprintf(stderr, "Falcon-512 fehlgeschlagen!\n");
      return EXIT_FAILURE;
      }
      
    puts("CROSS erfolgreich!");

    /* ============================================================
    * SLH_DSA initialisieren
    * ============================================================ */
    
    struct signature_t slhdsa = {0};

    uint8_t slhdsa_public_key[
        OQS_SIG_slh_dsa_pure_sha2_128s_length_public_key
    ];

    uint8_t slhdsa_secret_key[
        OQS_SIG_slh_dsa_pure_sha2_128s_length_secret_key
    ];

    uint8_t slhdsa_signature[
        OQS_SIG_slh_dsa_pure_sha2_128s_length_signature
    ];

    OQS_STATUS status_slhdsa = sign_and_verify(
        "SLH_DSA",
        message_to_sign,
        &slhdsa,

        slhdsa_public_key,
        slhdsa_secret_key,
        slhdsa_signature,

        OQS_SIG_slh_dsa_pure_sha2_128s_keypair,
        OQS_SIG_slh_dsa_pure_sha2_128s_sign,
        OQS_SIG_slh_dsa_pure_sha2_128s_verify
    );
    
    if (status_slhdsa = OQS_SUCCESS) {
      fprintf(stderr, "SLH_DSA fehlgeschlagen!\n");
      return EXIT_FAILURE;
      }
      
    puts("SLH_DSA erfolgreich!");


    /* ============================================================
    * UOV initialisieren
    * ============================================================ */
    
    struct signature_t uov = {0};

    uint8_t uov_public_key[
        OQS_SIG_uov_ov_Is_length_public_key
    ];

    uint8_t uov_secret_key[
        OQS_SIG_uov_ov_Is_length_secret_key
    ];

    uint8_t uov_signature[
        OQS_SIG_uov_ov_Is_length_signature
    ];

    OQS_STATUS status_uov = sign_and_verify(
        "UOV",
        message_to_sign,
        &uov,

        uov_public_key,
        uov_secret_key,
        uov_signature,

        OQS_SIG_uov_ov_Is_keypair,
        OQS_SIG_uov_ov_Is_sign,
        OQS_SIG_uov_ov_Is_verify
    );
    
    if (status_uov = OQS_SUCCESS) {
      fprintf(stderr, "UOV fehlgeschlagen!\n");
      return EXIT_FAILURE;
      }
      
    puts("UOV erfolgreich!");


    /* ============================================================
    * SNOVA initialisieren
    * ============================================================ */
    
    struct signature_t snova = {0};

    uint8_t snova_public_key[
        OQS_SIG_snova_SNOVA_I_K_length_public_key
    ];

    uint8_t snova_secret_key[
        OQS_SIG_snova_SNOVA_I_K_length_secret_key
    ];

    uint8_t snova_signature[
        OQS_SIG_snova_SNOVA_I_K_length_signature
    ];

    OQS_STATUS status_snova = sign_and_verify(
        "SNOVA",
        message_to_sign,
        &snova,

        snova_public_key,
        snova_secret_key,
        snova_signature,

        OQS_SIG_snova_SNOVA_I_K_keypair,
        OQS_SIG_snova_SNOVA_I_K_sign,
        OQS_SIG_snova_SNOVA_I_K_verify
    );
    
    if (status_snova = OQS_SUCCESS) {
      fprintf(stderr, "SNOVA fehlgeschlagen!\n");
      return EXIT_FAILURE;
      }
      
    puts("SNOVA erfolgreich!");


    /* ============================================================
    * MQOM initialisieren
    * ============================================================ */
    
    struct signature_t mqom = {0};

    uint8_t mqom_public_key[
        OQS_SIG_mqom_mqom3_cat1_gf16_fast_ct_length_public_key
    ];

    uint8_t mqom_secret_key[
        OQS_SIG_mqom_mqom3_cat1_gf16_fast_ct_length_secret_key
    ];

    uint8_t mqom_signature[
        OQS_SIG_mqom_mqom3_cat1_gf16_fast_ct_length_signature
    ];

    OQS_STATUS status_mqom = sign_and_verify(
        "MQOM",
        message_to_sign,
        &mqom,

        mqom_public_key,
        mqom_secret_key,
        mqom_signature,

        OQS_SIG_mqom_mqom3_cat1_gf16_fast_ct_keypair,
        OQS_SIG_mqom_mqom3_cat1_gf16_fast_ct_sign,
        OQS_SIG_mqom_mqom3_cat1_gf16_fast_ct_verify
    );
    
    if (status_mqom = OQS_SUCCESS) {
      fprintf(stderr, "MQOM fehlgeschlagen!\n");
      return EXIT_FAILURE;
      }
      
    puts("MQOM erfolgreich!");

    return EXIT_SUCCESS;
}

