#ifndef BFD_CLI_H
#define BFD_CLI_H

// Initialize CLI Unix socket and register with epoll
int bfd_cli_init(int epfd);

// Process a single CLI client connection
void bfd_cli_handle(int fd, int epfd, int cli_listen_fd);

#endif
