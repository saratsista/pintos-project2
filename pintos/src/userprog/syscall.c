#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include <string.h>
#include <ctype.h>
#include <devices/shutdown.h>
#include <devices/input.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include <kernel/console.h>
#include <filesys/filesys.h>
#include <filesys/file.h>

#define MAX_ARGS 3

struct lock filesys_lock;

static void syscall_handler (struct intr_frame *);
void validate_pointer (void *ptr);
void get_arguments (int *esp, int *args, int count);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  int args[MAX_ARGS];
  lock_init (&filesys_lock);
  validate_pointer (f->esp);
  int *sp = (int *)f->esp;

  switch (*sp)
  {
   case SYS_HALT:
      shutdown_power_off ();

   case SYS_EXIT:
      get_arguments (sp, &args[0], 1); 
      exit ((int)args[0]);
      break;

   case SYS_EXEC:
      get_arguments (sp, &args[0], 1);
      f->eax = exec ((const char *)args[0]);
      break;

   case SYS_WAIT:
      get_arguments (sp, &args[0], 1);
      f->eax = wait ((pid_t)args[0]);
      break;
    
   case SYS_WRITE:
      get_arguments (sp, &args[0], 3);
      f->eax = write ((int)args[0], (void *)args[1], (unsigned)args[2]);
      break;
    
   case SYS_READ:
      get_arguments (sp, &args[0], 3);
      f->eax = read ((int)args[0], (void *)args[1], (unsigned)args[2]);
      break;

   case SYS_CREATE:
      get_arguments (sp, &args[0], 2);
      f->eax = create ((char *)args[0], (unsigned) args[1]);
      break;

    case SYS_REMOVE:
       get_arguments (sp, &args[0], 1);
       char *file_to_close = (char *)args[0];
       f->eax = filesys_remove (file_to_close);
       break;

    case SYS_OPEN:
       get_arguments (sp, &args[0], 1);
       f->eax = open ((char *)args[0]);
       break; 
  
    case SYS_FILESIZE:
       get_arguments (sp, &args[0], 1);
       f->eax = filesize ((int)args[0]);
       break;

    case SYS_CLOSE:
       get_arguments (sp, &args[0], 1);
       close ((int)args[0]);
       break;       

    case SYS_TELL:
       get_arguments (sp, &args[0], 1);
       f->eax = tell ((int)args[0]);
       break;

    case SYS_SEEK:
       get_arguments (sp, &args[0], 1);
       seek ((int)args[0], (unsigned)args[1]);
       break; 
  }
}

void
get_arguments (int *esp, int *args, int count)
{
  int i;
  for (i = 0; i < count; i++)
  {
    int *next = ((esp + i) + 1);
    validate_pointer (next);
    args[i] = *next;
  }
}

void
validate_pointer (void *ptr)
{
  if (!is_user_vaddr (ptr))
    exit (-1);
  if  ((pagedir_get_page (thread_current ()->pagedir, ptr) == NULL))
    exit (-1);
}

void
exit (int status)
{
  struct thread *cur = thread_current ();
  cur->md->exit_status = status;
  sema_up (&cur->md->completed);
  printf ("%s: exit(%d)\n", cur->name, status);
  thread_exit ();
}

bool
create (const char *file_name, unsigned size)
{
  int return_value;
  if (file_name == NULL)
    exit (-1);    
  lock_acquire (&filesys_lock);
  return_value = filesys_create (file_name, size);
  lock_release (&filesys_lock);
  return return_value;
}
int
open (const char *file)
{
  if (file == NULL)
    exit (-1);
  if (strcmp (file, "") == 0)
    return -1;
  lock_acquire (&filesys_lock);
  struct file *open_file = filesys_open (file); 
  lock_release (&filesys_lock);
  struct file **fd_array = thread_current ()->fd;
  int k;
  for (k = 2; k < MAX_FD; k++)
  { 
    if (fd_array[k] == NULL)
    {
     fd_array[k] = open_file;
     break;
    }
  }
   return k;
}  

int
read (int fd, void *_buffer, unsigned size)
{
  char *buffer = (char *)_buffer;
  validate_pointer (buffer);
  int retval = -1;
  if (fd < 0 || fd > MAX_FD)
    exit (-1); 
  if (fd == 0)
  {
    char c;
    unsigned i = 0;
    while ((c = input_getc ())!= '\n')
    {
      buffer[i] = c; 
      i++;
      if (i == size-1) break;
    }
  }
  else {
    lock_acquire (&filesys_lock);
    struct file *file = thread_current ()->fd[fd];
    retval = file_read (file, buffer, size);
    thread_current ()->fd[fd] = file;
    lock_release (&filesys_lock);
  }
  return retval;
}

int
write (int file_desc, const void *_buffer, unsigned size)
{
  char *buffer = (char *)_buffer;
  int retval;
  if (file_desc == 1) {
    putbuf (buffer, size);
    retval = size;
  }
  else
  {
    lock_acquire (&filesys_lock);
    struct file *file_to_write = thread_current ()->fd[file_desc];
    retval = file_write (file_to_write, buffer, size);
    thread_current ()->fd[file_desc] = file_to_write;
    lock_release (&filesys_lock);
  }
  return retval;
}

void
close (int fd)
{
  lock_acquire (&filesys_lock);
  struct file *file = thread_current ()->fd[fd];
  file_close (file);
  thread_current ()->fd[fd] = NULL;
  lock_release (&filesys_lock);
}

int
filesize (int fd)
{
  struct file *file = thread_current ()->fd[fd];
  return file_length (file);
}

unsigned
tell (int fd)
{
  struct file *file = thread_current ()->fd[fd];
  return file_tell (file);
} 

void
seek (int fd, unsigned position)
{
  struct file *file = thread_current ()->fd[fd];
  file_seek (file, position);
}

pid_t
exec (const char *file)
{
  tid_t child_tid = process_execute (file);
  return (pid_t)child_tid;
}

int
wait (pid_t pid)
{
  return process_wait((tid_t)pid);
}


