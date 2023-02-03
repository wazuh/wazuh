#ifndef _CMD_DETAILS_KBHIT_HPP
#define _CMD_DETAILS_KBHIT_HPP

#include <sstream>
#include <string>
#include <unistd.h>
#include <vector>

namespace cmd::details
{
// Check if stdin has data available to read
inline int kbhit()
{
    // timeout structure passed into select
    struct timeval tv;
    // fd_set passed into select
    fd_set fds;
    // Set up the timeout.  here we can wait for 1 second
    tv.tv_sec = 0;
    tv.tv_usec = 0;

    // Zero out the fd_set - make sure it's pristine
    FD_ZERO(&fds);
    // Set the FD that we want to read
    FD_SET(STDIN_FILENO, &fds); // STDIN_FILENO is 0
    // select takes the last file descriptor value + 1 in the fdset to check,
    // the fdset for reads, writes, and errors.  We are only passing in reads.
    // the last parameter is the timeout.  select will return if an FD is ready or
    // the timeout has occurred
    select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv);
    // return 0 if STDIN is not ready to be read.
    return FD_ISSET(STDIN_FILENO, &fds);
}
} // namespace cmd::details

#endif // _CMD_DETAILS_KBHIT_HPP
