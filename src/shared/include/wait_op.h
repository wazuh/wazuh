/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef WAIT_OP_H
#define WAIT_OP_H

void os_setwait(void);
void os_delwait(void);
void os_wait(void);
void os_wait_predicate(bool (*fn_ptr)());

/**
 * @brief Check whether the agent wait mark is on (manager is disconnected)
 *
 * @retval true The agent is blocked.
 * @retval false The agent is not blocked.
 */
bool os_iswait();

#endif /* WAIT_OP_H */
