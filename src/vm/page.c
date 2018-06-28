#include "page.h"
#include <string.h>
#include "kernel/hash.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "debug.h"

static unsigned vm_hash_func (const struct hash_elem *e, void *aux UNUSED);
static bool vm_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
static void vm_destroy_func (struct hash_elem *e, void *aux);

/* Data Structure for vm_entry */
void
vm_init (struct hash *vm)
{
  hash_init (vm, &vm_hash_func, &vm_less_func, NULL);
}

void
vm_destroy (struct hash *vm)
{
  hash_destroy (vm, vm_destroy_func);
}

static unsigned
vm_hash_func (const struct hash_elem *e, void *aux UNUSED)
{
	struct vm_entry *vme = hash_entry (e, struct vm_entry, elem);
	return hash_int ((int)vme->vaddr);
}

static bool
vm_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  struct vm_entry *va = hash_entry(a, struct vm_entry, elem);
  struct vm_entry *vb = hash_entry(b, struct vm_entry, elem);

  return va->vaddr < vb->vaddr;
}

static void
vm_destroy_func (struct hash_elem *e, void *aux UNUSED)
{
  hash_delete (&thread_current()->vm, e);
  struct vm_entry *vme = hash_entry (e, struct vm_entry, elem);
  free (vme);
}

bool
insert_vme (struct hash *vm, struct vm_entry *vme)
{
	if (hash_insert (vm, &vme->elem) == NULL)
		return true;
	return false;
}

bool
delete_vme (struct hash *vm, struct vm_entry *vme)
{
  if (hash_delete (vm, &vme->elem) != NULL)
    return true;
  return false;
}

struct vm_entry *
find_vme (void *vaddr)
{
	struct vm_entry vme;
	struct hash_elem *e;

	vme.vaddr = pg_round_down (vaddr);
	e = hash_find (&thread_current ()->vm, &vme.elem);

	if (e == NULL)
		return NULL;

	return hash_entry (e, struct vm_entry, elem);
}

/*  Demand paging */
bool load_file (void* kaddr, struct vm_entry *vme)
{
  off_t size = file_read_at (vme->file, kaddr, vme->read_bytes, vme->offset);
  // size_t i;
  //
  // if (size > 0)
  // {
  //   for (i = 0; i < vme->zero_bytes; i++)
  //     *(char *)(kaddr + size + i) = 0;
  //   success = true;
  // }

  if (size > 0)
    memset (kaddr + vme->read_bytes, 0, vme->zero_bytes);

  if ((int) size != (int) vme->read_bytes)
    return false;
  return true;
}

