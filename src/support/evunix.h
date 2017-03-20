// Copyright (c) 2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_EVUNIX_H
#define BITCOIN_EVUNIX_H

/** Libevent<->UNIX socket bridge functions */

#include <boost/filesystem/path.hpp>

struct event_base;
struct bufferevent;

// All these functions come in a plain (high-level) and _fd (low-level)
// variant. The plain version takes/yields a libevent bufferevent*, the _fd
// functions file descriptor.

/** Bind on a UNIX socket.
 * Returns a bufferevent that can be used to send or receive data on the socket, or NULL
 * on failure.
 */
struct bufferevent *evunix_bind(const boost::filesystem::path &path);

/** Bind on a UNIX socket, return fd.
 * Return a file descriptor ready to pass to evhttp_accept_socket_with_handle, or -1
 * on failure.
 */
int evunix_bind_fd(const boost::filesystem::path &path);

/** Connect to a UNIX socket.
 * Returns a bufferevent that can be used to send or receive data on the socket, or NULL
 * on failure.
 */
struct bufferevent *evunix_connect(struct event_base *base, const boost::filesystem::path &path);

/** Connect to a UNIX socket, return fd.
 * Return a file descriptor ready to use, or -1 on failure.
 */
int evunix_connect_fd(const boost::filesystem::path &path);

/* Remove only sockets, not other files that happen to have
 * the same name.
 */
bool evunix_remove_socket(const boost::filesystem::path &path);

/** Return whether incoming connection fd came in on a UNIX socket.
 */
bool evunix_is_conn_from_unix_fd(int fd);

/** Return whether incoming connection bev came in on a UNIX socket.
 * This is a hack because evhttp won't let us know what bound socket a connection
 * came in on.
 */
bool evunix_is_conn_from_unix(struct bufferevent *bev);

#endif
