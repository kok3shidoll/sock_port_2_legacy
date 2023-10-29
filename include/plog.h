#ifndef PLOG_H
#define PLOG_H

#include <stdio.h>
#include <stdbool.h>

#ifdef APP

/* APP */
extern bool enable_sp_devlog;
extern void (*LOG)(const char *text, ...);

# define LOG_(x, ...) \
  do { \
    LOG("[sp2:log] "x"", ##__VA_ARGS__); \
  } while(0)

# define ERR(x, ...) \
  do { \
    LOG("[sp2:error] "x"", ##__VA_ARGS__); \
  } while(0)

# define DEVLOG(x, ...) \
  do { \
    if(enable_sp_devlog) \
      LOG("[sp2:debug] "x"", ##__VA_ARGS__); \
  } while(0)

# define DEVLOG2(x, ...)

#else

/* non APP */
# define LOG(x, ...) \
  do { \
    printf("[sockport2:log] "x"\n", ##__VA_ARGS__); \
  } while(0)

# define LOG_ LOG

# define ERR(x, ...) \
  do { \
    printf("[sockport2:error] "x"\n", ##__VA_ARGS__); \
  } while(0)

# define FATAL(x, ...) \
  do { \
    printf("[sockport2:error] FATAL "x"\n", ##__VA_ARGS__); \
  } while(0)

# ifdef DEVBUILD
#  define DEVLOG(x, ...) \
   do { \
     printf("[sockport2:debug] "x"\n", ##__VA_ARGS__); \
   } while(0)
#  define DEVLOG2(x, ...) \
   do { \
     printf("[sockport2:debug2] "x"\n", ##__VA_ARGS__); \
   } while(0)
# else
#  define DEVLOG(x, ...)
#  define DEVLOG2(x, ...)
# endif

#endif /* APP */
#endif /* PLOG_H */
