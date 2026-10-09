/*
 * Himmelcloak PAM skeleton load test.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>

/* The test application supplies PAM's callback; no input is collected. */
static int deny_conversation(int count, const struct pam_message **messages,
                             struct pam_response **responses, void *context)
{
    (void)count;
    (void)messages;
    (void)responses;
    (void)context;
    return PAM_CONV_ERR;
}

static int check_result(const char *operation, int actual, int expected)
{
    printf("%s: %d (expected %d)\n", operation, actual, expected);
    return actual == expected;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s CONFIG_DIRECTORY\n", argv[0]);
        return EXIT_FAILURE;
    }

    const struct pam_conv conversation = {
        .conv = deny_conversation,
        .appdata_ptr = NULL,
    };
    pam_handle_t *handle = NULL;
    const int start = pam_start_confdir("himmelcloak-s1", "himmelcloak-smoke-user",
                                        &conversation, argv[1], &handle);
    if (!check_result("pam_start_confdir", start, PAM_SUCCESS)) {
        return EXIT_FAILURE;
    }

    /* Deliberately exercise each denying stub through the real PAM stack. */
    const int authentication = pam_authenticate(handle, PAM_SILENT);
    const int account = pam_acct_mgmt(handle, PAM_SILENT);
    const int credentials = pam_setcred(handle, PAM_ESTABLISH_CRED | PAM_SILENT);

    int passed = check_result("pam_authenticate", authentication, PAM_AUTH_ERR);
    passed &= check_result("pam_acct_mgmt", account, PAM_PERM_DENIED);
    passed &= check_result("pam_setcred", credentials, PAM_CRED_ERR);
    passed &= check_result("pam_end", pam_end(handle, credentials), PAM_SUCCESS);

    puts(passed ? "PAM load smoke test: PASS" : "PAM load smoke test: FAIL");
    return passed ? EXIT_SUCCESS : EXIT_FAILURE;
}
