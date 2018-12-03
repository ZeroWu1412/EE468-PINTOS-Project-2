#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "devices/input.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

#define ARG_CODE 0
#define ARG_0    4
#define ARG_1    8
#define ARG_2    12

#define EXIT_ERROR -1

// for splitting up large buffers when writing to stdout
#define MAX_BUF 512

// stdin = 0, stdout = 1
// stderr is normally 2, but isn't implemented
#define MIN_FD 2

/* Maps file descriptors to their associated file structure. */
struct file_map
  {
    struct list_elem elem;      /* List element for the owning thread. */
    int fd;                     /* File descriptor. */
    struct file *file;          /* File structure. */
  };

/* Used to ensure only one thread can operate on a file at any given time. */
static struct semaphore file_sema;

static void syscall_handler (struct intr_frame *f);

static uint32_t load_stack (struct intr_frame *f, int);
bool is_valid_ptr (void *);
bool is_valid_buffer (void *buffer, size_t length);
bool is_valid_string (const char *str);

void sys_halt (void);
void sys_exit (int status);
pid_t sys_exec (const char *cmd_line);
int sys_wait (pid_t pid);
bool sys_create (const char *name, unsigned int initial_size);
bool sys_remove (const char *file);
int sys_open (const char *file);
int sys_filesize (int fd);
int sys_read (int fd, void *buffer, unsigned length);
int sys_write (int fd, const void *buffer, unsigned int length);
void sys_seek (int fd, unsigned position);
unsigned sys_tell (int fd);
void sys_close (int fd);

struct file_map *get_file (int fd);

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  if ((uint32_t) uaddr >= (uint32_t) PHYS_BASE)
    return -1;

  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));

  return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  if ((uint32_t) udst < (uint32_t) PHYS_BASE)
    return false;

  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}


void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

  // setup file access semaphore
  sema_init (&file_sema, 1);
}

static void
syscall_handler (struct intr_frame *f)
{
  int code = (int) load_stack (f, ARG_CODE);

  switch (code)
    {
      case SYS_HALT:
        sys_halt();
        break;

      case SYS_EXIT:
        sys_exit ((int) load_stack (f, ARG_0));
        break;

      case SYS_EXEC:
        f->eax = sys_exec ((const char *) load_stack (f, ARG_0));
        break;

      case SYS_WAIT:
        f->eax = sys_wait ((pid_t) load_stack (f, ARG_0));
        break;

      case SYS_CREATE:
        f->eax = sys_create ((const char *) load_stack (f, ARG_0),
          (unsigned int) load_stack (f, ARG_1));
        break;

      case SYS_REMOVE:
        f->eax = sys_remove ((const char *) load_stack (f, ARG_0));
        break;

      case SYS_OPEN:
        f->eax = sys_open ((const char *) load_stack (f, ARG_0));
        break;

      case SYS_FILESIZE:
        f->eax = sys_filesize ((int) load_stack (f, ARG_0));
        break;

      case SYS_READ:
        f->eax = sys_read ((int) load_stack (f, ARG_0),
            (void *) load_stack (f, ARG_1),
            (unsigned int) load_stack (f, ARG_2));
        break;

      case SYS_WRITE:
        f->eax = sys_write ((int) load_stack (f, ARG_0),
            (const void *) load_stack (f, ARG_1),
            (unsigned int) load_stack (f, ARG_2));
        break;

      case SYS_SEEK:
        sys_seek ((int) load_stack (f, ARG_0),
          (unsigned) load_stack (f, ARG_1));
        break;

      case SYS_TELL:
        f->eax = sys_tell ((int) load_stack (f, ARG_0));
        break;

      case SYS_CLOSE:
        sys_close ((int) load_stack (f, ARG_0));
        break;

      default:
        // unrecognised system call
        sys_exit (EXIT_ERROR);
        break;
    }
}

/* Validates the stack pointer and dereferences it */
static uint32_t
load_stack (struct intr_frame *f, int offset)
{
  if (!is_valid_ptr (f->esp + offset))
    sys_exit (EXIT_ERROR);

  return *((uint32_t *) (f->esp + offset));
}

/* For validating a user pointer. */
bool
is_valid_ptr (void *vaddr)
{
  if (get_user ((uint8_t *) vaddr) == -1)
    return false;

  return true;
}

/* For validating a string of known length. */
bool
is_valid_buffer (void *buffer, size_t length)
{
  size_t i;
  char *buf = (char *) buffer;

  for (i = 0; i < length; i++)
    {
      if (!is_valid_ptr (buf + i))
        return false;
    }

  return true;
}

/* For validating a string of unknown length. */
bool
is_valid_string (const char *str)
{
  int c;
  size_t i = 0;

  while (1)
    {
      c = get_user ((uint8_t *) (str + i));

      if (c == -1)
        return false;

      if (c == '\0')
        return true;

      i++;
    }
}

/* Terminates pintos immediately */
void
sys_halt (void)
{
  shutdown_power_off ();
}

/* Terminates the user process and with the given `status`. */
void
sys_exit (int status)
{
  // store the exit status in the thread
  // which will be accessed in `process_exit`
  struct thread *cur = thread_current ();
  cur->exit_status = status;

  thread_exit ();
}

/* Runs the executable given in `cmd_line` with any given argument
   and returns the process' id */
pid_t
sys_exec (const char *cmd_line)
{
  if (!is_valid_string (cmd_line))
    sys_exit (EXIT_ERROR);

  return process_execute (cmd_line);
}

/* Waits for the process identified by `pid` to terminate. */
int
sys_wait (pid_t pid)
{
  return process_wait (pid);
}

/* Creates a new file of name `name` and size `initial_size`. */
bool
sys_create (const char *name, unsigned int initial_size)
{
  if (!is_valid_string(name))
    sys_exit (EXIT_ERROR);

  bool success;

  sema_down (&file_sema);
  success = filesys_create (name, initial_size);
  sema_up (&file_sema);

  return success;
}

/* Removes a file with the name `file`. */
bool
sys_remove (const char *file)
{
  if (!is_valid_string (file))
    sys_exit (EXIT_ERROR);

  bool success;

  sema_down (&file_sema);
  success = filesys_remove (file);
  sema_up (&file_sema);

  return success;
}

/* Opens a file of name `file`. */
int
sys_open (const char *file)
{
  if (!is_valid_string (file))
    sys_exit (EXIT_ERROR);

  int fd = MIN_FD;
  struct file_map *fm;
  struct thread *cur = thread_current ();

  // try to find an unused file descriptor
  while (fd >= MIN_FD && get_file (fd) != NULL)
    fd++;

  // happens if the file descriptor has wrapped
  if (fd < MIN_FD)
    sys_exit (EXIT_ERROR);

  fm = malloc (sizeof (struct file_map));

  if (fm == NULL)
    return -1;

  fm->fd = fd;

  sema_down (&file_sema);
  fm->file = filesys_open (file);
  sema_up (&file_sema);

  if (fm->file == NULL)
    {
      free (fm);
      return -1;
    }

  // add to files opened by current thread
  list_push_back (&cur->files, &fm->elem);

  return fm->fd;
}

/* Get the size of a file identified by it's file descriptor. */
int
sys_filesize (int fd)
{
  struct file_map *fm = get_file (fd);
  int size;

  if (fm == NULL)
    return -1;

  sema_down (&file_sema);
  size = file_length (fm->file);
  sema_up (&file_sema);

  return size;
}

/* Read the contents of a file into `buffer`. */
int
sys_read (int fd, void *buffer, unsigned length)
{
  size_t i = 0;
  struct file_map *fm;
  int ret;

  // handle reading from stdin separately
  if (fd == STDIN_FILENO)
    {
      while (i++ < length)
        if (!put_user (((uint8_t *) buffer + i), (uint8_t) input_getc ()))
          sys_exit (EXIT_ERROR);

      return i;
    }

  if (!is_valid_buffer (buffer, length))
    sys_exit (EXIT_ERROR);

  fm = get_file (fd);

  if (fm == NULL)
    sys_exit (EXIT_ERROR);

  sema_down (&file_sema);
  ret = file_read (fm->file, buffer, length);
  sema_up (&file_sema);

  return ret;
}

/* Write the contents of `buffer` to a file. */
int
sys_write (int fd, const void *buffer, unsigned int length)
{
  struct file_map *fm;
  unsigned int len;
  char *buf;
  int ret;

  if (!is_valid_buffer ((void *) buffer, length))
    sys_exit (EXIT_ERROR);

  // handle stdout separately
  if (fd == STDOUT_FILENO)
    {
      len = length;
      buf = (char *) buffer;

      // break up large buffers
      while (len > MAX_BUF) {
        putbuf ((const char *) buf, MAX_BUF);
        len -= MAX_BUF;
        buf += MAX_BUF;
      }

      putbuf ((const char *) buf, len);
      return length;
    }

  fm = get_file (fd);

  if (fm == NULL)
    sys_exit (EXIT_ERROR);

  sema_down (&file_sema);
  ret = file_write (fm->file, buffer, length);
  sema_up (&file_sema);

  return ret;
}

/* Move to a specified position in a file. */
void
sys_seek (int fd, unsigned position)
{
  struct file_map *fm = get_file (fd);

  if (fm == NULL)
    return;

  sema_down (&file_sema);
  file_seek (fm->file, position);
  sema_up (&file_sema);
}

/* Get the current position within a file. */
unsigned
sys_tell (int fd)
{
  struct file_map *fm = get_file (fd);
  unsigned int ret;

  if (fm == NULL)
    return 0;

  sema_down (&file_sema);
  ret = file_tell (fm->file);
  sema_up (&file_sema);

  return ret;
}

/* close a file. */
void
sys_close (int fd)
{
  struct file_map *fm = get_file (fd);

  if (fm == NULL)
    return;

  // close the file
  sema_down (&file_sema);
  file_close (fm->file);
  sema_up (&file_sema);

  // remove it from the thread's list
  list_remove (&fm->elem);

  // deallocate the memory
  free (fm);
}

/* Attempt to file a valid file_map structure for the given file descriptor. */
struct file_map *
get_file(int fd)
{
  struct thread *cur = thread_current ();
  struct list_elem *e;
  struct file_map *fm;

  for (e = list_begin (&cur->files); e != list_end (&cur->files);
    e = list_next (e))
    {
      fm = list_entry (e, struct file_map, elem);

      if (fm->fd == fd)
        return fm;
    }

  return NULL;
}

/* Close all files.
   Called when the process exits. */
void
close_all_files (struct thread *t)
{
  struct list_elem *e;
  struct file_map *fm;

  e = list_begin (&t->files);

  while (e != list_end (&t->files))
    {
      fm = list_entry (e, struct file_map, elem);
      // move to the next element to stop the loop getting confused
      e = list_next (e);

      // close the file
      sema_down (&file_sema);
      file_close (fm->file);
      sema_up (&file_sema);

      //  remove it from the list
      list_remove (&fm->elem);
      // deallocate the memory
      free (fm);
    }
}
