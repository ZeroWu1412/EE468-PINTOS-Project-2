#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
struct process *get_child_process (struct thread *, tid_t);
void update_parent (struct thread *child);
void update_parent_load_status (struct thread *child, enum load_status status);
struct process *process_create (tid_t);
void free_processes (struct thread *t);
void extract_file_name (const char *, char *);
bool move_esp (void **, size_t);
bool add_args_to_stack (void **, const char *);
bool setup_argv (void **, void **, int *);
bool setup_args (void **, const char *);
#endif /* userprog/process.h */
