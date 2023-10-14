/*
 * Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <assert.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#define MAX_PATH FILENAME_MAX

#include "App.h"
#include "Enclave_u.h"
#include "sgx_urts.h"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char* msg;
    const char* sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {SGX_ERROR_UNEXPECTED, "Unexpected error occurred.", NULL},
    {SGX_ERROR_INVALID_PARAMETER, "Invalid parameter.", NULL},
    {SGX_ERROR_OUT_OF_MEMORY, "Out of memory.", NULL},
    {SGX_ERROR_ENCLAVE_LOST, "Power transition occurred.",
     "Please refer to the sample \"PowerTransition\" for details."},
    {SGX_ERROR_INVALID_ENCLAVE, "Invalid enclave image.", NULL},
    {SGX_ERROR_INVALID_ENCLAVE_ID, "Invalid enclave identification.", NULL},
    {SGX_ERROR_INVALID_SIGNATURE, "Invalid enclave signature.", NULL},
    {SGX_ERROR_OUT_OF_EPC, "Out of EPC memory.", NULL},
    {SGX_ERROR_NO_DEVICE, "Invalid SGX device.",
     "Please make sure SGX module is enabled in the BIOS, and install SGX "
     "driver afterwards."},
    {SGX_ERROR_MEMORY_MAP_CONFLICT, "Memory map conflicted.", NULL},
    {SGX_ERROR_INVALID_METADATA, "Invalid enclave metadata.", NULL},
    {SGX_ERROR_DEVICE_BUSY, "SGX device was busy.", NULL},
    {SGX_ERROR_INVALID_VERSION, "Enclave version was invalid.", NULL},
    {SGX_ERROR_INVALID_ATTRIBUTE, "Enclave was not authorized.", NULL},
    {SGX_ERROR_ENCLAVE_FILE_ACCESS, "Can't open enclave file.", NULL},
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret) {
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist / sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if (ret == sgx_errlist[idx].err) {
            if (NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }

    if (idx == ttl)
        printf(
            "Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer "
            "Reference\" for more details.\n",
            ret);
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
sgx_status_t initialize_enclave(void) {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL,
                             &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return ret;
    }

    return ret;
}

/* OCall functions */
void ocall_print_string(const char* str) {
    /* Proxy/Bridge will check the length and null-terminate
     * the input string to prevent buffer overflow.
     */
    printf("%s", str);
}

void ocall_dot_product(int* arr1, int* arr2, int* result, size_t cnt) {
    sgx_status_t retval;
    sgx_status_t status =
        ecall_dot_product(global_eid, &retval, arr1, arr2, result, cnt);

    if (status != SGX_SUCCESS) {
        printf("Error: 0x00%x\n", status);
    }
}

sgx_status_t benchmark_dot_product(bool secure, size_t cnt) {
    sgx_status_t status = SGX_SUCCESS;

    int* arr1 = (int*)malloc(cnt * sizeof(int));
    int* arr2 = (int*)malloc(cnt * sizeof(int));

    for (size_t i = 0; i < cnt; i++) {
        arr1[i] = (i + 1 % 100);
        arr2[i] = (cnt - i) % 100;
    }

    int result;

    struct timeval tval_before, tval_after, tval_result;

    gettimeofday(&tval_before, NULL);
    if (secure) {
        ocall_dot_product(arr1, arr2, &result, cnt);
    } else {
        result = 0;
        for (size_t i = 0; i < cnt; i++) {
            result += arr1[i] * arr2[i];
        }
    }
    gettimeofday(&tval_after, NULL);
    timersub(&tval_after, &tval_before, &tval_result);

    if (secure) {
        printf("Secure mode ON: ");
    } else {
        printf("Secure mode OFF: ");
    }
    printf("Time elapsed: %ld.%06ld seconds\n", (long int)tval_result.tv_sec,
           (long int)tval_result.tv_usec);

    printf("Result: %d\n", result);

    free(arr1);
    free(arr2);

    return SGX_SUCCESS;
}

/* Application entry */
int SGX_CDECL main(int argc, char* argv[]) {
    (void)(argc);
    (void)(argv);

    sgx_status_t ret;

    /* Initialize the enclave */
    if ((ret = initialize_enclave()) < 0) {
        printf("Enter a character before exit ...\n");
        getchar();
        return -1;
    }

    int benchmark_repeats = atoi(argv[2]);

    for (int i = 0; i < benchmark_repeats; i++) {
        printf("------Test number %d------\n", i + 1);
        benchmark_dot_product(true, atoi(argv[1]));
        benchmark_dot_product(false, atoi(argv[1]));
        printf("-------------------\n");
    }

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);

    printf("Info: DotProductBenchmark successfully returned.\n");

    // printf("Enter a character before exit ...\n");
    // getchar();
    return 0;
}
