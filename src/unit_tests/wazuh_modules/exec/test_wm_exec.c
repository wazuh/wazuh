/*
 * Copyright (C) 2023, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <stdlib.h>
#include "shared.h"
#include "../../../wazuh_modules/wmodules.h"

#include "../../wrappers/wazuh/shared/list_op_wrappers.h"
#include "../../wrappers/posix/signal_wrappers.h"
#ifdef WIN32
#include "../../wrappers/windows/processthreadsapi_wrappers.h"
#include "../../wrappers/windows/synchapi_wrappers.h"
#endif

#define COMMAND u8"Powershell -c \"@{ winCounter = (Get-Counter '\\mémoire\\mégaoctets disponibles').CounterSamples[0] } | ConvertTo-Json -compress\""
#define COMMAND2 u8"Powershell -c \"@{ winCounter = (Get-Counter '\\processeur(_total)\\% temps processeur').CounterSamples[0] } | ConvertTo-Json -compress\""


extern OSList * wm_children_list;
#ifndef WIN32
#include <signal.h>
#include <sys/wait.h>
int wm_exec_exit_code(int status);
pid_t __real_fork(void); // The real fork(), reachable despite this binary wrapping it globally
#endif

int __wrap_sleep (unsigned int __seconds) {
    return mock();
}

#ifndef WIN32
int __real_kill(pid_t pid, int sig);
static bool fork_spawns_holder; // Start a long-lived process right before the real fork, as another module thread could
static pid_t holder_pid;
#endif

pid_t __wrap_fork(void) {
#ifndef WIN32
    if (fork_spawns_holder) {
        if ((holder_pid = __real_fork()) == 0) {
            execlp("sleep", "sleep", "5", (char *)NULL);
            _exit(1);
        }
        return __real_fork();
    }
#endif
    return mock_type(pid_t);
}

void __wrap_exit(__attribute__((unused))int code) {
    function_called();
    return;
}

static int setup_modules(void ** state) {
    *state = NULL;
    // wm_kill_timeout to default value
    wm_kill_timeout = 0;
    wm_children_pool_init();
    // Release list for custom usage
    OSList_Destroy(wm_children_list);
    test_mode = true;
    wm_children_list = NULL;
    return 0;
}

static int teardown_modules(void ** state) {
    // wm_kill_timeout to default value
    wm_kill_timeout = 0;
    test_mode = false;
    return 0;
}

#ifdef WIN32
static void expect_job_breakaway(BOOL result) {
    expect_value(wrap_SetInformationJobObject, hJob, (HANDLE)0x10);
    expect_value(wrap_SetInformationJobObject, JobObjectInformationClass, JobObjectBasicLimitInformation);
    expect_value(wrap_SetInformationJobObject, LimitFlags, JOB_OBJECT_LIMIT_BREAKAWAY_OK);
    will_return(wrap_SetInformationJobObject, result);

    if (!result) {
        expect_any(__wrap__mdebug1, formatted_msg);
    }
}

#define READ_PIPE ((HANDLE)0xA1)
#define WRITE_PIPE ((HANDLE)0xA2)
#define READER_THREAD ((HANDLE)0x20)

// Everything up to the reader thread creation, for a command run with its output collected
static void expect_spawn_with_output(void) {
    will_return(wrap_CreatePipe, TRUE);
    will_return(wrap_CreatePipe, READ_PIPE);
    will_return(wrap_CreatePipe, WRITE_PIPE);
    expect_value(wrap_SetHandleInformation, hObject, WRITE_PIPE);
    expect_value(wrap_SetHandleInformation, dwMask, HANDLE_FLAG_INHERIT);
    expect_value(wrap_SetHandleInformation, dwFlags, 1);
    will_return(wrap_SetHandleInformation, TRUE);
    expect_any(__wrap__mdebug2, formatted_msg);
    expect_any(wrap_CreateProcessW, lpCommandLine);
    will_return(wrap_CreateProcessW, TRUE);
    expect_value(wrap_CloseHandle, hObject, WRITE_PIPE);
    will_return(wrap_CloseHandle, TRUE);
    expect_function_call(wrap_CreateJobObjectW);
    will_return(wrap_CreateJobObjectW, (HANDLE)0x10);
    expect_job_breakaway(TRUE);
    expect_value(wrap_AssignProcessToJobObject, hJob, (HANDLE)0x10);
    will_return(wrap_AssignProcessToJobObject, TRUE);
    expect_function_call(wrap_ResumeThread);
    will_return(wrap_ResumeThread, 1);
    will_return(wrap_CreateThread, READER_THREAD);
}

static void expect_wait(DWORD result) {
    expect_any(wrap_WaitForSingleObject, hMutex);
    expect_any(wrap_WaitForSingleObject, value);
    will_return(wrap_WaitForSingleObject, result);
}

// Bytes the next ReadFile() returns; NULL data fills them with 'A'
static void expect_read(const char * data, DWORD length) {
    will_return(wrap_ReadFile, data);
    will_return(wrap_ReadFile, length);
    will_return(wrap_ReadFile, TRUE);
}

static void expect_peek(DWORD avail, BOOL result) {
    will_return(wrap_PeekNamedPipe, avail);
    will_return(wrap_PeekNamedPipe, result);
}

// Output the command left in the pipe: a peek that reports it, then the read that takes it
static void expect_data(const char * data, DWORD length) {
    expect_peek(length, TRUE);
    expect_read(data, length);
}

// The pipe was closed by every writer: the reader sees the end of the data
static void expect_end_of_data(void) {
    expect_peek(0, FALSE);
}

// A command that still holds the pipe open without writing: the reader polls once
static void expect_idle_poll(void) {
    expect_peek(0, TRUE);
    expect_any(wrap_Sleep, dwMilliseconds);
}

// Mirrors ThreadInfo up to stop in wm_exec.c: keep the field order and types in sync
typedef struct {
    CHAR * output;
    size_t length;
    size_t capacity;
    HANDLE pipe;
    volatile LONG stop;
} reader_state_t;

// Stands for wm_exec() asking the reader to stop while it sleeps
static void request_reader_stop(void) {
    reader_state_t * state = (reader_state_t *)wrap_CreateThread_last_param();

    InterlockedExchange(&state->stop, 1);
}

// Handles closed once the command is done: the job, the process and its main thread
static void expect_final_close(void) {
    expect_value(wrap_CloseHandle, hObject, READER_THREAD);
    will_return(wrap_CloseHandle, TRUE);
    expect_value(wrap_CloseHandle, hObject, (HANDLE)0x10);
    will_return(wrap_CloseHandle, TRUE);
    expect_any(wrap_CloseHandle, hObject);
    will_return(wrap_CloseHandle, TRUE);
    expect_any(wrap_CloseHandle, hObject);
    will_return(wrap_CloseHandle, TRUE);
}

static void expect_abandoned_warning(void) {
    expect_string(__wrap__mwarn, formatted_msg, "at wm_exec(): Could not collect the command output.");
}

// The reader that was left running exits now, after wm_exec() told it to stop: it must not touch the pipe,
// and as the last owner it frees the state and the pipe
static void finish_abandoned_reader(void) {
    expect_value(wrap_CloseHandle, hObject, READ_PIPE);
    will_return(wrap_CloseHandle, TRUE);
    wrap_CreateThread_run_last();
}

static int setup_reader_thread(void ** state) {
    wrap_CreateThread_reset();
    wrap_Sleep_set_callback(NULL);
    return 0;
}

static int teardown_reader_thread(void ** state) {
    wrap_CreateThread_reset();
    wrap_Sleep_set_callback(NULL);
    return 0;
}
#endif

static void test_wm_exec_accented_command(void ** state) {
#ifdef WIN32
    size_t size = mbstowcs(NULL, COMMAND, 0);
    wchar_t *wcommand = calloc(size, sizeof(wchar_t));
    mbstowcs(wcommand, COMMAND, size);

    expect_any(__wrap__mdebug2, formatted_msg);
    expect_string(wrap_CreateProcessW, lpCommandLine, wcommand);
    will_return(wrap_CreateProcessW, TRUE);
    expect_function_call(wrap_CreateJobObjectW);
    will_return(wrap_CreateJobObjectW, (HANDLE)0x10);
    expect_job_breakaway(TRUE);
    expect_value(wrap_AssignProcessToJobObject, hJob, (HANDLE)0x10);
    will_return(wrap_AssignProcessToJobObject, TRUE);
    expect_function_call(wrap_ResumeThread);
    will_return(wrap_ResumeThread, 1);
    expect_any(wrap_WaitForSingleObject, hMutex);
    expect_any(wrap_WaitForSingleObject, value);
    will_return(wrap_WaitForSingleObject, 0);
    expect_any(wrap_CloseHandle, hObject);
    will_return(wrap_CloseHandle, FALSE);
    expect_any(wrap_CloseHandle, hObject);
    will_return(wrap_CloseHandle, FALSE);
    expect_any(wrap_CloseHandle, hObject);
    will_return(wrap_CloseHandle, FALSE);
    assert_int_equal(0, wm_exec(COMMAND, NULL, NULL, 0, NULL));

    free(wcommand);
#else
    printf("not implemented yet!\n");
#endif
}

static void test_wm_exec_not_accented_command(void ** state) {
#ifdef WIN32
    size_t size = mbstowcs(NULL, COMMAND2, 0);
    wchar_t *wcommand = calloc(size, sizeof(wchar_t));
    mbstowcs(wcommand, COMMAND2, size);

    expect_any(__wrap__mdebug2, formatted_msg);
    expect_string(wrap_CreateProcessW, lpCommandLine, wcommand);
    will_return(wrap_CreateProcessW, TRUE);
    expect_function_call(wrap_CreateJobObjectW);
    will_return(wrap_CreateJobObjectW, (HANDLE)0x10);
    expect_job_breakaway(TRUE);
    expect_value(wrap_AssignProcessToJobObject, hJob, (HANDLE)0x10);
    will_return(wrap_AssignProcessToJobObject, TRUE);
    expect_function_call(wrap_ResumeThread);
    will_return(wrap_ResumeThread, 1);
    expect_any(wrap_WaitForSingleObject, hMutex);
    expect_any(wrap_WaitForSingleObject, value);
    will_return(wrap_WaitForSingleObject, 0);
    expect_any(wrap_CloseHandle, hObject);
    will_return(wrap_CloseHandle, FALSE);
    expect_any(wrap_CloseHandle, hObject);
    will_return(wrap_CloseHandle, FALSE);
    expect_any(wrap_CloseHandle, hObject);
    will_return(wrap_CloseHandle, FALSE);
    assert_int_equal(0, wm_exec(COMMAND2, NULL, NULL, 0, NULL));

    free(wcommand);
#else
    printf("not implemented yet!\n");
#endif
}

static void test_wm_exec_createprocess_fails_with_output(void ** state) {
#ifdef WIN32
    char *output = NULL;
    int status = 0;
    const char *command = "invalid_command.exe";

    // Mock CreatePipe - simulate successful pipe creation
    will_return(wrap_CreatePipe, TRUE);
    will_return(wrap_CreatePipe, (HANDLE)0x1234);  // hReadPipe (tinfo.pipe)
    will_return(wrap_CreatePipe, (HANDLE)0x5678);  // hWritePipe (sinfo.hStdOutput)

    // Mock SetHandleInformation - success
    expect_value(wrap_SetHandleInformation, hObject, (HANDLE)0x5678);
    expect_value(wrap_SetHandleInformation, dwMask, HANDLE_FLAG_INHERIT);
    expect_value(wrap_SetHandleInformation, dwFlags, 1);
    will_return(wrap_SetHandleInformation, TRUE);

    expect_any(__wrap__mdebug2, formatted_msg);

    // Mock CreateProcessW to FAIL
    expect_any(wrap_CreateProcessW, lpCommandLine);
    will_return(wrap_CreateProcessW, FALSE);

    // Expect mwarn call (from the fix)
    expect_any(__wrap__mwarn, formatted_msg);

    // IMPORTANT: Verify CloseHandle is called twice to clean up pipes
    expect_value(wrap_CloseHandle, hObject, (HANDLE)0x1234);  // tinfo.pipe
    will_return(wrap_CloseHandle, TRUE);
    expect_value(wrap_CloseHandle, hObject, (HANDLE)0x5678);  // sinfo.hStdOutput
    will_return(wrap_CloseHandle, TRUE);

    // Execute wm_exec with output (so pipes are created)
    int result = wm_exec(command, &output, &status, 5, NULL);

    // Verify error is returned
    assert_int_equal(result, -1);
    assert_null(output);
#else
    printf("not implemented yet!\n");
#endif
}

static void test_wm_exec_sethandleinformation_fails(void ** state) {
#ifdef WIN32
    char *output = NULL;
    int status = 0;
    const char *command = "test_command.exe";

    // Mock CreatePipe - simulate successful pipe creation
    will_return(wrap_CreatePipe, TRUE);
    will_return(wrap_CreatePipe, (HANDLE)0xABCD);  // hReadPipe (tinfo.pipe)
    will_return(wrap_CreatePipe, (HANDLE)0xEF01);  // hWritePipe (sinfo.hStdOutput)

    // Mock SetHandleInformation - FAILS
    expect_value(wrap_SetHandleInformation, hObject, (HANDLE)0xEF01);
    expect_value(wrap_SetHandleInformation, dwMask, HANDLE_FLAG_INHERIT);
    expect_value(wrap_SetHandleInformation, dwFlags, 1);
    will_return(wrap_SetHandleInformation, FALSE);  // FAILS

    // Expect merror call
    expect_any(__wrap__merror, formatted_msg);

    // IMPORTANT: Verify CloseHandle is called twice to clean up pipes
    expect_value(wrap_CloseHandle, hObject, (HANDLE)0xABCD);  // tinfo.pipe
    will_return(wrap_CloseHandle, TRUE);
    expect_value(wrap_CloseHandle, hObject, (HANDLE)0xEF01);  // sinfo.hStdOutput
    will_return(wrap_CloseHandle, TRUE);

    // Execute wm_exec with output
    int result = wm_exec(command, &output, &status, 5, NULL);

    // Verify error is returned
    assert_int_equal(result, -1);
    assert_null(output);
#else
    printf("not implemented yet!\n");
#endif
}

static void test_wm_exec_timeout_terminates_job(void ** state) {
#ifdef WIN32
    expect_any(__wrap__mdebug2, formatted_msg);
    expect_any(wrap_CreateProcessW, lpCommandLine);
    will_return(wrap_CreateProcessW, TRUE);
    expect_function_call(wrap_CreateJobObjectW);
    will_return(wrap_CreateJobObjectW, (HANDLE)0x10);
    expect_job_breakaway(TRUE);
    expect_value(wrap_AssignProcessToJobObject, hJob, (HANDLE)0x10);
    will_return(wrap_AssignProcessToJobObject, TRUE);
    expect_function_call(wrap_ResumeThread);
    will_return(wrap_ResumeThread, 1);
    expect_any(wrap_WaitForSingleObject, hMutex);
    expect_any(wrap_WaitForSingleObject, value);
    will_return(wrap_WaitForSingleObject, WAIT_TIMEOUT);
    expect_value(wrap_TerminateJobObject, hJob, (HANDLE)0x10);
    will_return(wrap_TerminateJobObject, TRUE);
    expect_value(wrap_CloseHandle, hObject, (HANDLE)0x10);
    will_return(wrap_CloseHandle, TRUE);
    expect_any(wrap_CloseHandle, hObject);
    will_return(wrap_CloseHandle, TRUE);
    expect_any(wrap_CloseHandle, hObject);
    will_return(wrap_CloseHandle, TRUE);

    assert_int_equal(WM_ERROR_TIMEOUT, wm_exec(COMMAND2, NULL, NULL, 1, NULL));
#else
    printf("not implemented yet!\n");
#endif
}

static void test_wm_exec_job_assignment_fails_terminates_process(void ** state) {
#ifdef WIN32
    expect_any(__wrap__mdebug2, formatted_msg);
    expect_any(wrap_CreateProcessW, lpCommandLine);
    will_return(wrap_CreateProcessW, TRUE);
    expect_function_call(wrap_CreateJobObjectW);
    will_return(wrap_CreateJobObjectW, (HANDLE)0x10);
    expect_job_breakaway(TRUE);
    expect_value(wrap_AssignProcessToJobObject, hJob, (HANDLE)0x10);
    will_return(wrap_AssignProcessToJobObject, FALSE);
    expect_any(__wrap__mdebug1, formatted_msg);
    expect_value(wrap_CloseHandle, hObject, (HANDLE)0x10);
    will_return(wrap_CloseHandle, TRUE);
    expect_function_call(wrap_ResumeThread);
    will_return(wrap_ResumeThread, 1);
    expect_any(wrap_WaitForSingleObject, hMutex);
    expect_any(wrap_WaitForSingleObject, value);
    will_return(wrap_WaitForSingleObject, WAIT_TIMEOUT);
    expect_function_call(wrap_TerminateProcess);
    will_return(wrap_TerminateProcess, TRUE);
    expect_any(wrap_CloseHandle, hObject);
    will_return(wrap_CloseHandle, TRUE);
    expect_any(wrap_CloseHandle, hObject);
    will_return(wrap_CloseHandle, TRUE);

    assert_int_equal(WM_ERROR_TIMEOUT, wm_exec(COMMAND2, NULL, NULL, 1, NULL));
#else
    printf("not implemented yet!\n");
#endif
}

static void test_wm_exec_job_creation_fails(void ** state) {
#ifdef WIN32
    expect_any(__wrap__mdebug2, formatted_msg);
    expect_any(wrap_CreateProcessW, lpCommandLine);
    will_return(wrap_CreateProcessW, TRUE);
    expect_function_call(wrap_CreateJobObjectW);
    will_return(wrap_CreateJobObjectW, NULL);
    expect_any(__wrap__mdebug1, formatted_msg);
    expect_function_call(wrap_ResumeThread);
    will_return(wrap_ResumeThread, 1);
    expect_any(wrap_WaitForSingleObject, hMutex);
    expect_any(wrap_WaitForSingleObject, value);
    will_return(wrap_WaitForSingleObject, 0);
    expect_any(wrap_CloseHandle, hObject);
    will_return(wrap_CloseHandle, TRUE);
    expect_any(wrap_CloseHandle, hObject);
    will_return(wrap_CloseHandle, TRUE);

    assert_int_equal(0, wm_exec(COMMAND2, NULL, NULL, 0, NULL));
#else
    printf("not implemented yet!\n");
#endif
}

static void test_wm_exec_resumethread_fails(void ** state) {
#ifdef WIN32
    expect_any(__wrap__mdebug2, formatted_msg);
    expect_any(wrap_CreateProcessW, lpCommandLine);
    will_return(wrap_CreateProcessW, TRUE);
    expect_function_call(wrap_CreateJobObjectW);
    will_return(wrap_CreateJobObjectW, (HANDLE)0x10);
    expect_job_breakaway(TRUE);
    expect_value(wrap_AssignProcessToJobObject, hJob, (HANDLE)0x10);
    will_return(wrap_AssignProcessToJobObject, TRUE);
    expect_function_call(wrap_ResumeThread);
    will_return(wrap_ResumeThread, (DWORD)-1);
    expect_any(__wrap__merror, formatted_msg);
    expect_value(wrap_TerminateJobObject, hJob, (HANDLE)0x10);
    will_return(wrap_TerminateJobObject, TRUE);
    expect_value(wrap_CloseHandle, hObject, (HANDLE)0x10);
    will_return(wrap_CloseHandle, TRUE);
    expect_any(wrap_CloseHandle, hObject);
    will_return(wrap_CloseHandle, TRUE);
    expect_any(wrap_CloseHandle, hObject);
    will_return(wrap_CloseHandle, TRUE);

    assert_int_equal(-1, wm_exec(COMMAND2, NULL, NULL, 1, NULL));
#else
    printf("not implemented yet!\n");
#endif
}

#ifdef WIN32
static void test_wm_exec_job_breakaway_fails_continues(void ** state) {
    expect_any(__wrap__mdebug2, formatted_msg);
    expect_any(wrap_CreateProcessW, lpCommandLine);
    will_return(wrap_CreateProcessW, TRUE);
    expect_function_call(wrap_CreateJobObjectW);
    will_return(wrap_CreateJobObjectW, (HANDLE)0x10);
    expect_job_breakaway(FALSE);
    expect_value(wrap_AssignProcessToJobObject, hJob, (HANDLE)0x10);
    will_return(wrap_AssignProcessToJobObject, TRUE);
    expect_function_call(wrap_ResumeThread);
    will_return(wrap_ResumeThread, 1);
    expect_wait(0);
    expect_value(wrap_CloseHandle, hObject, (HANDLE)0x10);
    will_return(wrap_CloseHandle, TRUE);
    expect_any(wrap_CloseHandle, hObject);
    will_return(wrap_CloseHandle, TRUE);
    expect_any(wrap_CloseHandle, hObject);
    will_return(wrap_CloseHandle, TRUE);

    assert_int_equal(0, wm_exec(COMMAND2, NULL, NULL, 0, NULL));
}

// The reader ends by itself: the output is returned
static void test_wm_exec_output_reader_joins(void ** state) {
    char command[] = "cmd /c dir";
    char * output = NULL;

    wrap_CreateThread_run_routine(true);
    expect_spawn_with_output();
    expect_data("hel", 3);
    expect_data("lo", 2);
    expect_end_of_data();
    expect_wait(0);
    expect_wait(0);
    expect_value(wrap_CloseHandle, hObject, READ_PIPE);
    will_return(wrap_CloseHandle, TRUE);
    expect_final_close();

    assert_int_equal(0, wm_exec(command, &output, NULL, 0, NULL));
    assert_string_equal(output, "hello");

    os_free(output);
}

// Output of several reads that outgrows the initial buffer is kept whole
static void test_wm_exec_output_grows_buffer(void ** state) {
    const DWORD sizes[] = { 5000, 13000, 20000 };
    const DWORD total = 38000;
    char command[] = "cmd /c dir";
    char * output = NULL;
    char * pattern = (char *)calloc(total + 1, 1);
    DWORD offset = 0;

    for (DWORD i = 0; i < total; i++) {
        pattern[i] = 'a' + (i % 26);
    }

    wrap_CreateThread_run_routine(true);
    expect_spawn_with_output();

    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        expect_data(pattern + offset, sizes[i]);
        offset += sizes[i];
    }

    expect_end_of_data();
    expect_wait(0);
    expect_wait(0);
    expect_value(wrap_CloseHandle, hObject, READ_PIPE);
    will_return(wrap_CloseHandle, TRUE);
    expect_final_close();

    assert_int_equal(0, wm_exec(command, &output, NULL, 0, NULL));
    assert_int_equal(strlen(output), total);
    assert_string_equal(output, pattern);

    os_free(output);
    free(pattern);
}

// The command timed out while the pipe was quiet: the reader is told to stop and the output so far is returned
static void test_wm_exec_output_timeout_reader_stopped(void ** state) {
    char command[] = "cmd /c dir";
    char * output = NULL;

    wrap_CreateThread_run_routine(true);
    wrap_Sleep_set_callback(request_reader_stop);
    expect_spawn_with_output();
    expect_data("partial", 7);
    expect_idle_poll();
    expect_wait(WAIT_TIMEOUT);
    expect_value(wrap_TerminateJobObject, hJob, (HANDLE)0x10);
    will_return(wrap_TerminateJobObject, TRUE);
    expect_wait(WAIT_TIMEOUT);
    expect_wait(WAIT_OBJECT_0);
    expect_string(__wrap__mdebug1, formatted_msg, "at wm_exec(): Stopped reading the command output before its end.");
    expect_value(wrap_CloseHandle, hObject, READ_PIPE);
    will_return(wrap_CloseHandle, TRUE);
    expect_final_close();

    assert_int_equal(WM_ERROR_TIMEOUT, wm_exec(command, &output, NULL, 1, NULL));
    assert_string_equal(output, "partial");

    os_free(output);
}

// The command exited but a descendant still holds the pipe open: success, with the output read so far
static void test_wm_exec_output_exited_pipe_held_by_descendant(void ** state) {
    char command[] = "cmd /c dir";
    char * output = NULL;

    wrap_CreateThread_run_routine(true);
    wrap_Sleep_set_callback(request_reader_stop);
    expect_spawn_with_output();
    expect_data("done", 4);
    expect_idle_poll();
    expect_wait(0);
    expect_wait(WAIT_TIMEOUT);
    expect_wait(WAIT_OBJECT_0);
    expect_string(__wrap__mdebug1, formatted_msg, "at wm_exec(): Stopped reading the command output before its end.");
    expect_value(wrap_CloseHandle, hObject, READ_PIPE);
    will_return(wrap_CloseHandle, TRUE);
    expect_final_close();

    assert_int_equal(0, wm_exec(command, &output, NULL, 0, NULL));
    assert_string_equal(output, "done");

    os_free(output);
}

// Output beyond the limit is dropped and drained, and what fits is kept
static void test_wm_exec_output_reaches_limit(void ** state) {
    char command[] = "cmd /c dir";
    char last_bytes[100];
    char * output = NULL;

    memset(last_bytes, 'B', sizeof(last_bytes));
    wrap_CreateThread_run_routine(true);
    expect_spawn_with_output();
    expect_data(NULL, WM_STRING_MAX - 100);
    expect_peek(1000, TRUE);
    expect_read(last_bytes, 100);
    // Over the limit: read into the drain buffer in pieces that fit it
    expect_data(NULL, 1000);
    expect_peek(10000, TRUE);
    expect_read(NULL, 4096);
    expect_peek(5904, TRUE);
    expect_read(NULL, 4096);
    expect_peek(1808, TRUE);
    expect_read(NULL, 1808);
    expect_end_of_data();
    expect_wait(0);
    expect_wait(0);
    expect_string(__wrap__mwarn, formatted_msg, "String limit reached.");
    expect_value(wrap_CloseHandle, hObject, READ_PIPE);
    will_return(wrap_CloseHandle, TRUE);
    expect_final_close();

    assert_int_equal(0, wm_exec(command, &output, NULL, 0, NULL));
    assert_int_equal(strlen(output), WM_STRING_MAX);
    assert_int_equal(output[WM_STRING_MAX - 101], 'A');
    assert_int_equal(output[WM_STRING_MAX - 100], 'B');
    assert_int_equal(output[WM_STRING_MAX - 1], 'B');

    os_free(output);
}

// The reader is still running when the reader wait times out twice: -1 and no output
static void test_wm_exec_output_reader_never_exits(void ** state) {
    char command[] = "cmd /c dir";
    char * output = (char *)0x1;

    expect_spawn_with_output();
    expect_wait(0);
    expect_wait(WAIT_TIMEOUT);
    expect_wait(WAIT_TIMEOUT);
    expect_abandoned_warning();
    expect_final_close();

    assert_int_equal(-1, wm_exec(command, &output, NULL, 0, NULL));
    assert_null(output);

    finish_abandoned_reader();
}

// A timeout that did fire is still reported as one when the reader cannot be collected
static void test_wm_exec_output_timeout_reader_never_exits(void ** state) {
    char command[] = "cmd /c dir";
    char * output = (char *)0x1;

    expect_spawn_with_output();
    expect_wait(WAIT_TIMEOUT);
    expect_value(wrap_TerminateJobObject, hJob, (HANDLE)0x10);
    will_return(wrap_TerminateJobObject, TRUE);
    expect_wait(WAIT_TIMEOUT);
    expect_wait(WAIT_TIMEOUT);
    expect_abandoned_warning();
    expect_final_close();

    assert_int_equal(WM_ERROR_TIMEOUT, wm_exec(command, &output, NULL, 1, NULL));
    assert_null(output);

    finish_abandoned_reader();
}

// The wait for the reader fails: its own error message, -1 and no output
static void test_wm_exec_output_reader_wait_failed(void ** state) {
    char command[] = "cmd /c dir";
    char * output = (char *)0x1;

    expect_spawn_with_output();
    expect_wait(0);
    expect_wait(WAIT_FAILED);
    expect_any(__wrap__merror, formatted_msg);
    expect_abandoned_warning();
    expect_final_close();

    assert_int_equal(-1, wm_exec(command, &output, NULL, 0, NULL));
    assert_null(output);

    finish_abandoned_reader();
}

// The wait for the reader fails after it was told to stop
static void test_wm_exec_output_reader_wait_failed_after_stop(void ** state) {
    char command[] = "cmd /c dir";
    char * output = (char *)0x1;

    expect_spawn_with_output();
    expect_wait(0);
    expect_wait(WAIT_TIMEOUT);
    expect_wait(WAIT_FAILED);
    expect_any(__wrap__merror, formatted_msg);
    expect_abandoned_warning();
    expect_final_close();

    assert_int_equal(-1, wm_exec(command, &output, NULL, 0, NULL));
    assert_null(output);

    finish_abandoned_reader();
}
#endif

#ifndef TEST_WINAGENT
static void test_wm_append_sid_null_list(void ** state) {
    pid_t sid = 1234;
    wm_children_list = NULL; // NULL List

    wm_append_sid(sid);
}

static void test_wm_append_sid_fail(void ** state) {
    pid_t sid = 1234;
    wm_children_list = (OSList *)1; // NON-NULL List

    will_return(__wrap_OSList_AddData, false);
    will_return(__wrap_OSList_AddData, NULL);

    expect_string(__wrap__merror, formatted_msg, "Child process ID 1234 could not be registered in the children list.");

    wm_append_sid(sid);
}

static void test_wm_append_sid_success(void ** state) {
    pid_t sid = 1234;
    OSListNode * node;
    wm_children_list = (OSList *)1; // NON-NULL List

    will_return(__wrap_OSList_AddData, true);
    will_return(__wrap_OSList_AddData, (void *)1);

    wm_append_sid(sid);
}

static void test_wm_remove_sid_null_list(void ** state) {
    pid_t sid = 1234;
    wm_children_list = NULL; // NULL List

    wm_remove_sid(sid);
}

static void test_wm_remove_sid_not_found(void ** state) {
    pid_t sid = 1234;
    wm_children_list = (OSList *)1; // NON-NULL List

    will_return(__wrap_OSList_GetFirstNode, NULL);

    expect_string(__wrap__mwarn, formatted_msg,
                 "Child process ID 1234 could not be removed because it was "
                 "not found in the children list.");

    wm_remove_sid(sid);
}

static void test_wm_remove_sid_success(void ** state) {
    pid_t sid = 1234;
    pid_t * p_sid = NULL;
    OSListNode * node = NULL;
    wm_children_list = (OSList *)1; // NON-NULL List

    os_calloc(1, sizeof(pid_t), p_sid);
    *p_sid = sid;
    node = (OSListNode *) calloc(1, sizeof(OSListNode));
    node->data = p_sid;

    will_return(__wrap_OSList_GetFirstNode, node);
    expect_function_call(__wrap_OSList_DeleteThisNode);

    wm_remove_sid(sid);

    os_free(node);
}

static void test_wm_kill_children_fork_failed(void ** state) {
    pid_t sid = 1234;
    pid_t * p_sid = NULL;
    OSListNode * node = NULL;

    wm_children_list = OSList_Create();
    OSList_SetFreeDataPointer(wm_children_list, free);

    os_calloc(1, sizeof(pid_t), p_sid);
    *p_sid = sid;
    node = (OSListNode *) calloc(1, sizeof(OSListNode));
    node->data = p_sid;

    will_return(__wrap_OSList_GetFirstNode, node);

    pid_t pidError = -1;
    will_return(__wrap_fork, pidError);
    errno = 13;

    wm_kill_timeout = 1;

    expect_string(__wrap__merror, formatted_msg, "wm_kill_children(): Couldn't fork: (13) Permission denied.");

    test_mode = false;

    wm_kill_children(sid);

    os_free(p_sid);
    os_free(node);

    OSList_Destroy(wm_children_list);
    wm_children_list = NULL;
}

static void test_wm_kill_children_timeout_kill_child(void ** state) {
    pid_t sid = 1234;
    pid_t * p_sid = NULL;
    OSListNode * node = NULL;

    wm_children_list = OSList_Create();
    OSList_SetFreeDataPointer(wm_children_list, free);

    wm_kill_timeout = 1;

    os_calloc(1, sizeof(pid_t), p_sid);
    *p_sid = sid;
    node = (OSListNode *) calloc(1, sizeof(OSListNode));
    node->data = p_sid;

    will_return(__wrap_OSList_GetFirstNode, node);

    pid_t pidOk = 0;
    will_return(__wrap_fork, pidOk);

    expect_value(__wrap_kill,pid,sid*(-1));
    expect_value(__wrap_kill,sig,SIGTERM);
    will_return(__wrap_kill,0);

    will_return(__wrap_sleep, OS_SUCCESS);

    expect_value(__wrap_kill,pid,sid*(-1));
    expect_value(__wrap_kill,sig,0);
    will_return(__wrap_kill,-1);

    errno = 3;

    expect_function_call(__wrap_exit);

    expect_string(__wrap__merror, formatted_msg, "wm_kill_children(): Couldn't wait PID 1234: (3) No such process.");

    expect_function_call(__wrap_exit);

    expect_string(__wrap__mdebug1, formatted_msg, "Killing process group 1234");

    expect_value(__wrap_kill,pid,sid*(-1));
    expect_value(__wrap_kill,sig,SIGKILL);
    will_return(__wrap_kill,0);

    expect_function_call(__wrap_exit);

    test_mode = false;

    wm_kill_children(sid);

    os_free(p_sid);
    os_free(node);

    OSList_Destroy(wm_children_list);
    wm_children_list = NULL;
}

static void test_wm_kill_children_parent(void ** state) {
    pid_t sid = 1234;
    pid_t * p_sid = NULL;
    OSListNode * node = NULL;

    wm_children_list = OSList_Create();
    OSList_SetFreeDataPointer(wm_children_list, free);

    os_calloc(1, sizeof(pid_t), p_sid);
    *p_sid = sid;
    node = (OSListNode *) calloc(1, sizeof(OSListNode));
    node->data = p_sid;

    will_return(__wrap_OSList_GetFirstNode, node);

    expect_value(__wrap_kill,pid,sid*(-1));
    expect_value(__wrap_kill,sig,SIGKILL);
    will_return(__wrap_kill,0);

    test_mode = false;

    wm_kill_children(sid);

    os_free(p_sid);
    os_free(node);

    OSList_Destroy(wm_children_list);
    wm_children_list = NULL;
}

#ifndef WIN32
static void test_wm_exec_exit_code_normal_exit(void ** state) {
    pid_t pid = __real_fork();

    if (pid == 0) {
        _exit(3);
    }

    int status;
    waitpid(pid, &status, 0);

    assert_int_equal(wm_exec_exit_code(status), 3);
}

static void test_wm_exec_exit_code_signal(void ** state) {
    pid_t pid = __real_fork();

    if (pid == 0) {
        // SIGKILL specifically: it cannot be caught, so no handler this test binary may have
        // installed (e.g. cmocka's own crash reporting) runs in the child after the fork().
        // raise(), not kill(): this binary wraps the kill symbol for its own tests.
        raise(SIGKILL);
        _exit(123); // Should never be reached
    }

    int status;
    waitpid(pid, &status, 0);

    // A crash must be reported as a real failure (128 + signal number, the shell
    // convention), never as exit code 0 -- WEXITSTATUS() alone is unspecified on
    // a signalled process and reads as 0 on Linux, which is what this guards against.
    assert_int_equal(wm_exec_exit_code(status), 128 + SIGKILL);
}

static void test_wm_exec_output_not_held_by_concurrent_child(void ** state) {
    char command[] = "echo done";
    char * output = NULL;
    int status = -1;
    const time_t start = time(NULL);

    fork_spawns_holder = true;
    const int ret = wm_exec(command, &output, &status, 0, NULL);
    fork_spawns_holder = false;
    const time_t elapsed = time(NULL) - start;

    assert_true(holder_pid > 0);
    // A holder that already exited would not hold the pipe, and the test would prove nothing
    const bool holder_alive = waitpid(holder_pid, NULL, WNOHANG) == 0;

    if (holder_alive) {
        __real_kill(holder_pid, SIGKILL);
        waitpid(holder_pid, NULL, 0);
    }

    assert_true(holder_alive);
    assert_int_equal(ret, 0);
    assert_int_equal(status, 0);
    assert_non_null(output);
    assert_true(elapsed < 3);

    os_free(output);
}
#endif

#else
static void test_wm_append_handle_null_list(void ** state) {
    HANDLE hProcess = (HANDLE)0x00112233;
    wm_children_list = NULL; // NULL List

    wm_append_handle(hProcess);
}

static void test_wm_append_handle_fail(void ** state) {
    HANDLE hProcess = (HANDLE)0x00112233;
    wm_children_list = (OSList *)1; // NON-NULL List


    will_return(__wrap_OSList_AddData, false);
    will_return(__wrap_OSList_AddData, NULL);

    expect_string(__wrap__merror, formatted_msg,
                 "Child process handle 00112233 could not be registered in the "
                 "children list.");

    wm_append_handle(hProcess);
}

static void test_wm_append_handle_success(void ** state) {
    HANDLE hProcess = (HANDLE)0x00112233;
    OSListNode * node;
    wm_children_list = (OSList *)1; // NON-NULL List

    will_return(__wrap_OSList_AddData, true);
    will_return(__wrap_OSList_AddData, node);

    wm_append_handle(hProcess);
}

static void test_wm_remove_handle_null_list(void ** state) {
    HANDLE hProccess = (HANDLE)0x00112233;
    wm_children_list = NULL; // NULL List

    wm_remove_handle(hProccess);
}

static void test_wm_remove_handle_not_found(void ** state) {
    HANDLE hProcces = (HANDLE)0x00112233;
    wm_children_list = (OSList *)1; // NON-NULL List

    will_return(__wrap_OSList_GetFirstNode, NULL);

    expect_string(__wrap__mwarn, formatted_msg,
                 "Child process handle 00112233 could not be removed because "
                 "it was not found in the children list.");

    wm_remove_handle(hProcces);
}

static void test_wm_remove_handle_success(void ** state) {
    HANDLE hProcess = (HANDLE)0x00112233;
    HANDLE * p_hProcess = NULL;
    OSListNode * node = NULL;
    wm_children_list = (OSList *)1; // NON-NULL List

    os_calloc(1, sizeof(HANDLE), p_hProcess);
    *p_hProcess = hProcess;
    node = (OSListNode *) calloc(1, sizeof(OSListNode));
    node->data = p_hProcess;

    will_return(__wrap_OSList_GetFirstNode, node);
    expect_function_call(__wrap_OSList_DeleteThisNode);

    wm_remove_handle(hProcess);

    os_free(node);
}

static void test_wm_kill_children_with_empty_list(void ** state) {
    wm_children_list = NULL; // NULL List

    test_mode = false;

    wm_kill_children();
}

static void test_wm_kill_children_with_empty_node(void ** state) {
    OSListNode * node = NULL;

    wm_children_list = OSList_Create();
    OSList_SetFreeDataPointer(wm_children_list, free);

    node = (OSListNode *) calloc(1, sizeof(OSListNode));
    node->data = NULL;

    will_return(__wrap_OSList_GetFirstNode, node);

    test_mode = false;

    wm_kill_children();

    os_free(node);

    OSList_Destroy(wm_children_list);
    wm_children_list = NULL;
}

static void test_wm_kill_children_with_success(void ** state) {
    HANDLE hProcess = (HANDLE)10;
    HANDLE * p_hProcess = NULL;
    OSListNode * node = NULL;

    wm_children_list = OSList_Create();
    OSList_SetFreeDataPointer(wm_children_list, free);

    os_calloc(1, sizeof(HANDLE), p_hProcess);
    *p_hProcess = hProcess;
    node = (OSListNode *) calloc(1, sizeof(OSListNode));
    node->data = p_hProcess;

    will_return(__wrap_OSList_GetFirstNode, node);

    expect_function_call(wrap_TerminateProcess);
    will_return(wrap_TerminateProcess, true);

    test_mode = false;

    wm_kill_children();

    os_free(p_hProcess);
    os_free(node);

    OSList_Destroy(wm_children_list);
    wm_children_list = NULL;
}

#endif

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_wm_exec_accented_command),
        cmocka_unit_test(test_wm_exec_not_accented_command),
        cmocka_unit_test(test_wm_exec_createprocess_fails_with_output),
        cmocka_unit_test(test_wm_exec_sethandleinformation_fails),
        cmocka_unit_test(test_wm_exec_timeout_terminates_job),
        cmocka_unit_test(test_wm_exec_job_assignment_fails_terminates_process),
        cmocka_unit_test(test_wm_exec_job_creation_fails),
        cmocka_unit_test(test_wm_exec_resumethread_fails),
#ifdef WIN32
        cmocka_unit_test(test_wm_exec_job_breakaway_fails_continues),
        cmocka_unit_test_setup_teardown(test_wm_exec_output_reader_joins, setup_reader_thread, teardown_reader_thread),
        cmocka_unit_test_setup_teardown(test_wm_exec_output_grows_buffer, setup_reader_thread, teardown_reader_thread),
        cmocka_unit_test_setup_teardown(test_wm_exec_output_timeout_reader_stopped, setup_reader_thread, teardown_reader_thread),
        cmocka_unit_test_setup_teardown(test_wm_exec_output_exited_pipe_held_by_descendant, setup_reader_thread, teardown_reader_thread),
        cmocka_unit_test_setup_teardown(test_wm_exec_output_reaches_limit, setup_reader_thread, teardown_reader_thread),
        cmocka_unit_test_setup_teardown(test_wm_exec_output_reader_never_exits, setup_reader_thread, teardown_reader_thread),
        cmocka_unit_test_setup_teardown(test_wm_exec_output_timeout_reader_never_exits, setup_reader_thread, teardown_reader_thread),
        cmocka_unit_test_setup_teardown(test_wm_exec_output_reader_wait_failed, setup_reader_thread, teardown_reader_thread),
        cmocka_unit_test_setup_teardown(test_wm_exec_output_reader_wait_failed_after_stop, setup_reader_thread, teardown_reader_thread),
#endif
#ifndef TEST_WINAGENT
        cmocka_unit_test_setup_teardown(test_wm_append_sid_null_list, NULL, NULL),
        cmocka_unit_test_setup_teardown(test_wm_append_sid_fail, setup_modules, teardown_modules),
        cmocka_unit_test_setup_teardown(test_wm_append_sid_success, setup_modules, teardown_modules),
        cmocka_unit_test_setup_teardown(test_wm_remove_sid_null_list, NULL, NULL),
        cmocka_unit_test_setup_teardown(test_wm_remove_sid_not_found, setup_modules, teardown_modules),
        cmocka_unit_test_setup_teardown(test_wm_remove_sid_success, setup_modules, teardown_modules),
        cmocka_unit_test_setup_teardown(test_wm_kill_children_fork_failed, setup_modules, NULL),
        cmocka_unit_test_setup_teardown(test_wm_kill_children_timeout_kill_child, setup_modules, NULL),
        cmocka_unit_test_setup_teardown(test_wm_kill_children_parent, setup_modules, NULL),
#ifndef WIN32
        cmocka_unit_test(test_wm_exec_exit_code_normal_exit),
        cmocka_unit_test(test_wm_exec_exit_code_signal),
        cmocka_unit_test_setup_teardown(test_wm_exec_output_not_held_by_concurrent_child, setup_modules, teardown_modules)
#endif
#else
        cmocka_unit_test_setup_teardown(test_wm_append_handle_null_list, NULL, NULL),
        cmocka_unit_test_setup_teardown(test_wm_append_handle_fail, setup_modules, teardown_modules),
        cmocka_unit_test_setup_teardown(test_wm_append_handle_success, setup_modules, teardown_modules),
        cmocka_unit_test_setup_teardown(test_wm_remove_handle_null_list, NULL, NULL),
        cmocka_unit_test_setup_teardown(test_wm_remove_handle_not_found, setup_modules, teardown_modules),
        cmocka_unit_test_setup_teardown(test_wm_remove_handle_success, setup_modules, teardown_modules),
        cmocka_unit_test_setup_teardown(test_wm_kill_children_with_empty_list, setup_modules, NULL),
        cmocka_unit_test_setup_teardown(test_wm_kill_children_with_empty_node, setup_modules, NULL),
        cmocka_unit_test_setup_teardown(test_wm_kill_children_with_success, setup_modules, NULL)
#endif
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
