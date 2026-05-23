typedef uint32_t fileport_t;

int fileport_makeport(int fd, fileport_t *port);
int fileport_makefd(fileport_t port);