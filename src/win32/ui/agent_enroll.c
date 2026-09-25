/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <ctype.h>
#include <process.h>
#include <stdbool.h>
#include "shared.h"
#include "os_win32ui.h"
#include "../os_win.h"
#include "agent_auth_cli.h"

/* Matches W_ETOKEN_MAX_FILE_BYTES (token_bootstrap.h): wazuh-agent-auth rejects anything
 * at or above that size, so the input box is capped the same way. */
#define ENROLL_TOKEN_MAX 8192
#define ENROLL_AUTH_EXE  "wazuh-agent-auth.exe"

typedef struct {
    const char *caption;
    const char *prompt;
    char *out_buf;
    size_t out_sz;
} enroll_dlg_ctx_t;

/* Tokens are base64url; a paste that line-wraps can pick up whitespace/CR/LF that must
 * not end up in the token file. */
static void strip_token_whitespace(char *buf)
{
    char *src = buf;
    char *dst = buf;

    while (*src) {
        if (!isspace((unsigned char)*src)) {
            *dst++ = *src;
        }
        src++;
    }
    *dst = '\0';
}

static BOOL CALLBACK EnrollDlgProc(HWND hwnd, UINT message, WPARAM wParam,
        __attribute__((unused))LPARAM lParam)
{
    switch (message) {
        case WM_INITDIALOG: {
            enroll_dlg_ctx_t *ctx = (enroll_dlg_ctx_t *)lParam;
            SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR)ctx);
            SetWindowText(hwnd, ctx->caption);
            SetDlgItemText(hwnd, IDC_ENROLL_PROMPT, ctx->prompt);
            SendDlgItemMessage(hwnd, IDC_ENROLL_TOKEN, EM_LIMITTEXT, ENROLL_TOKEN_MAX - 1, 0);
            return TRUE;
        }

        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case IDC_ENROLL_OK: {
                    enroll_dlg_ctx_t *ctx = (enroll_dlg_ctx_t *)GetWindowLongPtr(hwnd, GWLP_USERDATA);
                    GetDlgItemText(hwnd, IDC_ENROLL_TOKEN, ctx->out_buf, (int)ctx->out_sz);
                    strip_token_whitespace(ctx->out_buf);

                    if (ctx->out_buf[0] == '\0') {
                        MessageBox(hwnd, "Please enter an enrollment token.",
                                   ctx->caption, MB_OK | MB_ICONWARNING);
                        break;
                    }

                    EndDialog(hwnd, IDOK);
                    break;
                }
                case IDC_ENROLL_CANCELBTN:
                    EndDialog(hwnd, IDCANCEL);
                    break;
            }
            break;

        case WM_CLOSE:
            EndDialog(hwnd, IDCANCEL);
            break;

        default:
            return FALSE;
    }
    return TRUE;
}

/* Prompts for a token; returns 1 with out_token filled in on OK, 0 on Cancel */
static int ask_for_token(HWND hwnd, const char *caption, const char *prompt,
                          char *out_token, size_t out_sz)
{
    enroll_dlg_ctx_t ctx = { caption, prompt, out_token, out_sz };
    out_token[0] = '\0';

    return DialogBoxParam(GetModuleHandle(NULL), MAKEINTRESOURCE(IDD_ENROLL), hwnd,
                           EnrollDlgProc, (LPARAM)&ctx) == IDOK;
}

/* Same definition the CLI itself uses: whether client.keys carries an id, not whether
 * the manager still has this agent registered. */
static int is_agent_registered(void)
{
    return config_inst.agentid != NULL && strcmp(config_inst.agentid, ST_NOTSET) != 0;
}

static const char *agent_auth_exit_message(int exit_code, bool force_enroll, bool certs_only)
{
    switch (exit_code) {
        case AGENT_AUTH_OK:
            if (certs_only) {
                return "Trust anchor and manager address refreshed.";
            }
            return force_enroll ? "Agent re-enrolled; it received a new id."
                                 : "Agent enrolled.";
        case AGENT_AUTH_ERR_USAGE:
            return "wazuh-agent-auth could not run (usage error or a local problem). "
                   "Check ossec.log for details.";
        case AGENT_AUTH_ERR_TOKEN:
            return "The enrollment token is invalid or malformed.";
        case AGENT_AUTH_ERR_ANCHOR:
            return "Could not establish trust with the manager (certificate or pin mismatch).";
        case AGENT_AUTH_ERR_ENROLL:
            return "The manager refused the enrollment request.";
        case AGENT_AUTH_ERR_COMMIT:
            return "Enrolled, but the result could not be saved locally. The agent still "
                   "belongs to its previous manager.";
        case AGENT_AUTH_ERR_CONFIG:
            return "Enrolled and saved, but the configuration could not be updated to point "
                   "at the new manager.";
        default:
            return "Could not run wazuh-agent-auth.exe.";
    }
}

/* Writes the token to a secure temp file, runs wazuh-agent-auth.exe with it, then
 * refreshes the Manager/Key display the same way &Refresh and Start/Stop/Restart do. */
static void invoke_wazuh_agent_auth(HWND hwnd, const char *title, const char *token,
                                     bool force_enroll, bool certs_only)
{
    char tmp_path[OS_FLSIZE + 1] = "enroll_token.XXXXXX";
    FILE *fp;
    const char *argv[6];
    int argc = 0;
    intptr_t exit_code;
    bool succeeded = false;

    /* wazuh-agent-auth refuses outright while the service is running -- it loads the
     * agent's identity once, at startup. */
    if (CheckServiceRunning()) {
        if (MessageBox(hwnd,
                        "The Wazuh agent service must be stopped before this can run. Stop it now?",
                        title, MB_YESNO | MB_ICONQUESTION) != IDYES) {
            return;
        }

        os_stop_service();

        /* os_stop_service()'s own 300ms sleep is a race-mitigation nicety, not a real wait --
         * module teardown can take far longer, and wazuh-agent-auth refuses to run against
         * anything but a fully stopped service (SERVICE_STOP_PENDING included). Same wait loop
         * win_agent.c's run_service_restart() uses after its own os_stop_service() call. */
        {
            const DWORD timeoutMs = 45000;
            const DWORD sleepIntervalMs = 500;
            DWORD startTime = GetTickCount();

            while (CheckServiceRunning()) {
                if (GetTickCount() - startTime > timeoutMs) {
                    MessageBox(hwnd, "The Wazuh agent service did not stop within the expected time.",
                               title, MB_OK | MB_ICONERROR);
                    return;
                }
                Sleep(sleepIntervalMs);
            }
        }
    }

    /* mkstemp_ex() creates the file with an Administrators+SYSTEM-only DACL from the
     * moment it's created -- same primitive token_bootstrap.c uses for the trust anchor. */
    if (mkstemp_ex(tmp_path) < 0) {
        MessageBox(hwnd, "Could not create a temporary file for the token.",
                   title, MB_OK | MB_ICONERROR);
        config_read(hwnd);
        gen_server_info(hwnd);
        return;
    }

    if (fp = wfopen(tmp_path, "w"), !fp) {
        unlink(tmp_path);
        MessageBox(hwnd, "Could not write the token to a temporary file.",
                   title, MB_OK | MB_ICONERROR);
        config_read(hwnd);
        gen_server_info(hwnd);
        return;
    }

    fputs(token, fp);
    fclose(fp);

    argv[argc++] = ENROLL_AUTH_EXE;
    argv[argc++] = "--token-file";
    argv[argc++] = tmp_path;

    if (force_enroll) {
        argv[argc++] = "--force-enroll";
    } else if (certs_only) {
        argv[argc++] = "--certs-only";
    }

    argv[argc] = NULL;

    /* wazuh-agent-auth never deletes --token-file itself (it may be stdin, '-'), so this
     * UI owns cleanup -- same as token_bootstrap.c unlinking the installer's one-shot
     * enrollment token once it has been consumed. */
    exit_code = _spawnv(_P_WAIT, ENROLL_AUTH_EXE, argv);
    unlink(tmp_path);

    if (exit_code < 0) {
        MessageBox(hwnd, "Could not run wazuh-agent-auth.exe.", title, MB_OK | MB_ICONERROR);
    } else {
        int result_code = (int)exit_code;
        UINT icon = result_code == AGENT_AUTH_OK ? MB_ICONINFORMATION : MB_ICONWARNING;
        succeeded = result_code == AGENT_AUTH_OK;
        MessageBox(hwnd, agent_auth_exit_message(result_code, force_enroll, certs_only),
                   title, MB_OK | icon);
    }

    config_read(hwnd);
    gen_server_info(hwnd);

    /* Only offer to (re)start once this actually worked -- on failure the service is left
     * exactly as this function found it, whether that meant stopping it above or not. Keyed
     * off the live service state, not off whether this call was the one that stopped it, so
     * a service that was already stopped before Enroll/Update CA was clicked still gets
     * offered a start after a successful run. */
    if (succeeded && !CheckServiceRunning()) {
        if (MessageBox(hwnd, "Start the Wazuh agent service now?", title,
                        MB_YESNO | MB_ICONQUESTION) == IDYES) {
            if (os_start_service()) {
                SendMessage(hStatus, SB_SETTEXT, 0, (LPARAM)"Started");
            }
            config_read(hwnd);
            gen_server_info(hwnd);
        }
    }
}

int run_agent_enroll(HWND hwnd)
{
    char token[ENROLL_TOKEN_MAX];
    bool force_enroll = false;

    config_read(hwnd);

    if (is_agent_registered()) {
        char confirm_msg[256];
        snprintf(confirm_msg, sizeof(confirm_msg),
                 "This agent is already enrolled (id=%s). Force-enrolling will register it "
                 "again and it will receive a NEW id. Continue?",
                 config_inst.agentid);

        if (!ask_for_token(hwnd, "Enroll Agent", "Paste the enrollment token:", token, sizeof(token))) {
            return 0;
        }

        if (MessageBox(hwnd, confirm_msg, "Enroll Agent", MB_YESNO | MB_ICONWARNING) != IDYES) {
            return 0;
        }

        force_enroll = true;
    } else {
        if (!ask_for_token(hwnd, "Enroll Agent", "Paste the enrollment token:", token, sizeof(token))) {
            return 0;
        }
    }

    invoke_wazuh_agent_auth(hwnd, "Enroll Agent", token, force_enroll, false);
    return 0;
}

int run_agent_certs_only(HWND hwnd)
{
    char token[ENROLL_TOKEN_MAX];

    config_read(hwnd);

    if (!is_agent_registered()) {
        MessageBox(hwnd, "This agent is not enrolled yet. Use Enroll first.",
                   "Update CA", MB_OK | MB_ICONWARNING);
        return 0;
    }

    if (!ask_for_token(hwnd, "Update CA",
                        "Paste the enrollment token (used to refresh the trust anchor and manager address):",
                        token, sizeof(token))) {
        return 0;
    }

    invoke_wazuh_agent_auth(hwnd, "Update CA", token, false, true);
    return 0;
}
