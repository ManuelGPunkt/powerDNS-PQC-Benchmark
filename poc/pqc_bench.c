/*
 * pqc_bench.c — Benchmark für PQC-Signaturalgorithmen (liboqs)
 *
 * Misst keypair / sign / verify pro Algorithmus einzeln, N-mal,
 * und schreibt jede Messung als Zeile in eine CSV-Datei:
 *
 *   algorithm,operation,iteration,time_ns
 *
 * Aufruf:
 *   ./pqc_bench [iterationen] [ausgabe.csv]
 *   (Standard: 100 Iterationen, pqc_bench.csv)
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <oqs/oqs.h>

typedef OQS_STATUS (*keypair_func_t)(uint8_t *public_key, uint8_t *secret_key);
typedef OQS_STATUS (*sign_func_t)(uint8_t *signature, size_t *signature_len,
                                  const uint8_t *message, size_t message_len,
                                  const uint8_t *secret_key);
typedef OQS_STATUS (*verify_func_t)(const uint8_t *message, size_t message_len,
                                    const uint8_t *signature, size_t signature_len,
                                    const uint8_t *public_key);

struct bench_alg_t {
    const char *name;
    size_t public_key_len;
    size_t secret_key_len;
    size_t signature_len; /* maximale Signaturlänge */
    keypair_func_t keypair;
    sign_func_t sign;
    verify_func_t verify;
};

static const struct bench_alg_t ALGORITHMS[] = {
#ifdef OQS_ENABLE_SIG_ml_dsa_44
    { "ML-DSA-44",
      OQS_SIG_ml_dsa_44_length_public_key,
      OQS_SIG_ml_dsa_44_length_secret_key,
      OQS_SIG_ml_dsa_44_length_signature,
      OQS_SIG_ml_dsa_44_keypair, OQS_SIG_ml_dsa_44_sign, OQS_SIG_ml_dsa_44_verify },
#endif
#ifdef OQS_ENABLE_SIG_falcon_512
    { "Falcon-512",
      OQS_SIG_falcon_512_length_public_key,
      OQS_SIG_falcon_512_length_secret_key,
      OQS_SIG_falcon_512_length_signature,
      OQS_SIG_falcon_512_keypair, OQS_SIG_falcon_512_sign, OQS_SIG_falcon_512_verify },
#endif
#ifdef OQS_ENABLE_SIG_mayo_1
    { "MAYO-1",
      OQS_SIG_mayo_1_length_public_key,
      OQS_SIG_mayo_1_length_secret_key,
      OQS_SIG_mayo_1_length_signature,
      OQS_SIG_mayo_1_keypair, OQS_SIG_mayo_1_sign, OQS_SIG_mayo_1_verify },
#endif
#ifdef OQS_ENABLE_SIG_snova_SNOVA_I_K
    { "SNOVA-I-K",
      OQS_SIG_snova_SNOVA_I_K_length_public_key,
      OQS_SIG_snova_SNOVA_I_K_length_secret_key,
      OQS_SIG_snova_SNOVA_I_K_length_signature,
      OQS_SIG_snova_SNOVA_I_K_keypair, OQS_SIG_snova_SNOVA_I_K_sign, OQS_SIG_snova_SNOVA_I_K_verify },
#endif
#ifdef OQS_ENABLE_SIG_mqom_mqom3_cat1_gf16_fast_ct
    { "MQOM3-cat1-gf16",
      OQS_SIG_mqom_mqom3_cat1_gf16_fast_ct_length_public_key,
      OQS_SIG_mqom_mqom3_cat1_gf16_fast_ct_length_secret_key,
      OQS_SIG_mqom_mqom3_cat1_gf16_fast_ct_length_signature,
      OQS_SIG_mqom_mqom3_cat1_gf16_fast_ct_keypair, OQS_SIG_mqom_mqom3_cat1_gf16_fast_ct_sign,
      OQS_SIG_mqom_mqom3_cat1_gf16_fast_ct_verify },
#endif
#ifdef OQS_ENABLE_SIG_slh_dsa_pure_sha2_128s
    { "SLH-DSA-SHA2-128s",
      OQS_SIG_slh_dsa_pure_sha2_128s_length_public_key,
      OQS_SIG_slh_dsa_pure_sha2_128s_length_secret_key,
      OQS_SIG_slh_dsa_pure_sha2_128s_length_signature,
      OQS_SIG_slh_dsa_pure_sha2_128s_keypair, OQS_SIG_slh_dsa_pure_sha2_128s_sign,
      OQS_SIG_slh_dsa_pure_sha2_128s_verify },
#endif
#ifdef OQS_ENABLE_SIG_cross_rsdp_128_balanced
    { "CROSS-rsdp-128-balanced",
      OQS_SIG_cross_rsdp_128_balanced_length_public_key,
      OQS_SIG_cross_rsdp_128_balanced_length_secret_key,
      OQS_SIG_cross_rsdp_128_balanced_length_signature,
      OQS_SIG_cross_rsdp_128_balanced_keypair, OQS_SIG_cross_rsdp_128_balanced_sign,
      OQS_SIG_cross_rsdp_128_balanced_verify },
#endif
};

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

int main(int argc, char **argv)
{
    const char *message = "diese Nachricht soll signiert und verifiziert werden";
    size_t message_len = strlen(message);

    int iterations = 100;
    const char *outpath = "pqc_bench.csv";

    if (argc > 1) {
        iterations = atoi(argv[1]);
        if (iterations <= 0) {
            fprintf(stderr, "Ungültige Iterationszahl: %s\n", argv[1]);
            return EXIT_FAILURE;
        }
    }
    if (argc > 2) {
        outpath = argv[2];
    }

    FILE *out = fopen(outpath, "w");
    if (out == NULL) {
        perror("fopen");
        return EXIT_FAILURE;
    }
    fprintf(out, "algorithm,operation,iteration,time_ns\n");

    size_t num_algs = sizeof(ALGORITHMS) / sizeof(ALGORITHMS[0]);

    for (size_t a = 0; a < num_algs; a++) {
        const struct bench_alg_t *alg = &ALGORITHMS[a];

        uint8_t *public_key = malloc(alg->public_key_len);
        uint8_t *secret_key = malloc(alg->secret_key_len);
        uint8_t *signature  = malloc(alg->signature_len);
        if (public_key == NULL || secret_key == NULL || signature == NULL) {
            fprintf(stderr, "Speicherfehler bei %s\n", alg->name);
            fclose(out);
            return EXIT_FAILURE;
        }

        printf("[%s] %d Iterationen ...\n", alg->name, iterations);
        fflush(stdout);

        uint64_t start, end;
        size_t signature_len = 0;

        /* ---- keypair: 1x Warm-up, dann N Messungen ---- */
        alg->keypair(public_key, secret_key);
        for (int i = 0; i < iterations; i++) {
            start = now_ns();
            if (alg->keypair(public_key, secret_key) != OQS_SUCCESS) {
                fprintf(stderr, "[%s] keypair fehlgeschlagen\n", alg->name);
                fclose(out);
                return EXIT_FAILURE;
            }
            end = now_ns();
            fprintf(out, "%s,keypair,%d,%llu\n", alg->name, i,
                    (unsigned long long)(end - start));
        }

        /* ---- sign: 1x Warm-up, dann N Messungen ---- */
        alg->sign(signature, &signature_len, (const uint8_t *)message, message_len, secret_key);
        for (int i = 0; i < iterations; i++) {
            start = now_ns();
            if (alg->sign(signature, &signature_len, (const uint8_t *)message,
                          message_len, secret_key) != OQS_SUCCESS) {
                fprintf(stderr, "[%s] sign fehlgeschlagen\n", alg->name);
                fclose(out);
                return EXIT_FAILURE;
            }
            end = now_ns();
            fprintf(out, "%s,sign,%d,%llu\n", alg->name, i,
                    (unsigned long long)(end - start));
        }

        /* ---- verify: 1x Warm-up, dann N Messungen (immer dieselbe Signatur) ---- */
        alg->verify((const uint8_t *)message, message_len, signature, signature_len, public_key);
        for (int i = 0; i < iterations; i++) {
            start = now_ns();
            if (alg->verify((const uint8_t *)message, message_len, signature,
                            signature_len, public_key) != OQS_SUCCESS) {
                fprintf(stderr, "[%s] verify fehlgeschlagen\n", alg->name);
                fclose(out);
                return EXIT_FAILURE;
            }
            end = now_ns();
            fprintf(out, "%s,verify,%d,%llu\n", alg->name, i,
                    (unsigned long long)(end - start));
        }

        free(public_key);
        free(secret_key);
        free(signature);
    }

    fclose(out);
    printf("Fertig. Ergebnisse in %s\n", outpath);
    return EXIT_SUCCESS;
}
