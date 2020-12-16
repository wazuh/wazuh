#ifndef __TEST_FIM_H
#define __TEST_FIM_H

#include "syscheck.h"
#include "syscheck-config.h"

#include "wrappers/wazuh/shared/debug_op_wrappers.h"
#include "wrappers/wazuh/shared/mq_op_wrappers.h"

/**********************************************************************************************************************\
 * Auxiliar expect functions
\**********************************************************************************************************************/
void expect_fim_send_msg(char mq, const char *location, const char *msg, int retval);
void expect_send_syscheck_msg(const char *msg);

void expect_fim_diff_delete_compress_folder(struct dirent *dir);

#endif // __TEST_FIM_H
