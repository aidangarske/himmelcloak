/*
 * Himmelcloak PAM conversation round-trip test (HC-41).
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Loads the conversation-selftest build of pam_himmelcloak.so through the real
 * Linux-PAM stack. This program plays the login program: it answers the
 * module's username and password prompts and records every message it is shown.
 */

#define _POSIX_C_SOURCE 200809L /* strdup under -std=c11 */

#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SEEN 8
#define TEST_USERNAME "alice"
#define TEST_PASSWORD "correct-horse-battery-staple"

enum mode { ANSWER, FAIL_CONVERSATION, MISSING_PASSWORD };

struct script {
    enum mode mode;
    int seen_count;
    int seen_style[MAX_SEEN];
    char seen_text[MAX_SEEN][128];
};

static char *copy(const char *text)
{
    char *result = strdup(text);
    if (result == NULL) {
        abort();
    }
    return result;
}

static int scripted_conversation(int count, const struct pam_message **messages,
                                 struct pam_response **responses, void *context)
{
    struct script *script = context;

    for (int i = 0; i < count; i++) {
        if (script->seen_count < MAX_SEEN) {
            script->seen_style[script->seen_count] = messages[i]->msg_style;
            snprintf(script->seen_text[script->seen_count],
                     sizeof script->seen_text[0], "%s", messages[i]->msg);
            script->seen_count++;
        }
    }
    if (script->mode == FAIL_CONVERSATION) {
        return PAM_CONV_ERR;
    }

    struct pam_response *reply = calloc((size_t)count, sizeof *reply);
    if (reply == NULL) {
        return PAM_BUF_ERR;
    }
    for (int i = 0; i < count; i++) {
        if (messages[i]->msg_style == PAM_PROMPT_ECHO_ON) {
            reply[i].resp = copy(TEST_USERNAME);
        } else if (messages[i]->msg_style == PAM_PROMPT_ECHO_OFF &&
                   script->mode != MISSING_PASSWORD) {
            reply[i].resp = copy(TEST_PASSWORD);
        }
    }
    *responses = reply;
    return PAM_SUCCESS;
}

static int check_int(const char *what, int actual, int expected)
{
    printf("%s: %d (expected %d)\n", what, actual, expected);
    return actual == expected;
}

static int check_message(const struct script *script, int index, int style, const char *text)
{
    if (index >= script->seen_count) {
        printf("message %d: missing (expected style %d \"%s\")\n", index, style, text);
        return 0;
    }
    printf("message %d: style %d \"%s\"\n", index, script->seen_style[index],
           script->seen_text[index]);
    return script->seen_style[index] == style && strcmp(script->seen_text[index], text) == 0;
}

static int run(const char *config_dir, struct script *script, int expected_auth)
{
    const struct pam_conv conversation = {
        .conv = scripted_conversation,
        .appdata_ptr = script,
    };
    pam_handle_t *handle = NULL;
    int passed = check_int("pam_start_confdir",
                           pam_start_confdir("himmelcloak-roundtrip", TEST_USERNAME,
                                             &conversation, config_dir, &handle),
                           PAM_SUCCESS);
    if (!passed) {
        return 0;
    }
    int authentication = pam_authenticate(handle, 0);
    passed &= check_int("pam_authenticate", authentication, expected_auth);
    passed &= check_int("pam_acct_mgmt", pam_acct_mgmt(handle, 0), PAM_PERM_DENIED);
    passed &= check_int("pam_end", pam_end(handle, authentication), PAM_SUCCESS);
    return passed;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s CONFIG_DIRECTORY\n", argv[0]);
        return EXIT_FAILURE;
    }
    int passed = 1;

    puts("== Full round trip: prompts answered, login still denied");
    struct script answered = {.mode = ANSWER};
    passed &= run(argv[1], &answered, PAM_AUTH_ERR);
    passed &= check_message(&answered, 0, PAM_PROMPT_ECHO_ON, "Username: ");
    passed &= check_message(&answered, 1, PAM_PROMPT_ECHO_OFF, "Password: ");
    passed &= check_message(&answered, 2, PAM_TEXT_INFO,
                            "Conversation round trip: username " TEST_USERNAME
                            ", password 28 bytes");
    passed &= check_int("messages shown", answered.seen_count, 3);
    for (int i = 0; i < answered.seen_count; i++) {
        if (strstr(answered.seen_text[i], TEST_PASSWORD) != NULL) {
            puts("password was echoed back to the login program");
            passed = 0;
        }
    }

    puts("== Login program cannot show the prompt");
    struct script failed = {.mode = FAIL_CONVERSATION};
    passed &= run(argv[1], &failed, PAM_CONV_ERR);
    passed &= check_int("messages shown", failed.seen_count, 1);

    puts("== Login program returns no password");
    struct script missing = {.mode = MISSING_PASSWORD};
    passed &= run(argv[1], &missing, PAM_CONV_ERR);
    passed &= check_int("messages shown", missing.seen_count, 2);

    puts(passed ? "PAM conversation round trip: PASS" : "PAM conversation round trip: FAIL");
    return passed ? EXIT_SUCCESS : EXIT_FAILURE;
}
