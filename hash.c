/*
 * Copyright 2011 Serghei Samsi <sscdvp@gmail.com>
 */

/*
 * HASH routines
 */

#include "dhcp_module.h"

#define HASH_TABLE_MAX_SIZE 2097152 // need to be primary number
#define HASH_TABLE_INIT_UNITS 1
#define HASH_TABLE_GROW_STEP 2

unsigned long hash (char *name, unsigned long hash_table_size)
{
    /* Dan J. Bernstein HASH algoritm
     * See http://cr.yp.to for details
     */
    unsigned long h = 5381;
    unsigned int keylen;
    unsigned char *key;
    
    key = name;
    keylen = strlen (key);
    while (keylen) {
	h = (h << 5) + h;
	h ^= (unsigned char) *key;
	key++;
	keylen--;
    }
#ifdef _LP64
    h >>= 4;
#else
    h >>= 2;
#endif
    h &= hash_table_size - 1;
    return h;
}

int hash_rehash_at_index (hash_table *table, unsigned long old_h, int wait)
{
    hash_entry pt;
    hash_entry *ptemp = &pt, *ntemp;
    hash_entry *p, *pn, *c, *cn;
    unsigned long h;
    int found;
    int allocated;

    if ((table == NULL) || (table -> hash == NULL))
	return 0;

    p = &table -> hash[old_h];

    if (p == NULL)
	return 0;

    ptemp -> is_allocated = 0;
    ptemp -> allocated = 0;

    while (p != NULL) {
	pn = p -> next;

	if (p -> name != NULL) {
		h = hash (p -> name, table -> buckets);
		if (h == old_h) {
			p = pn;
			continue;
		}

		ptemp -> name = p -> name;
		p -> name = NULL;

		ptemp -> name_len = p -> name_len;
		p -> name_len = 0;

		ptemp -> val = p -> val;
		p -> val = NULL;

		ptemp -> next = NULL;

		found = 0;
		if (ptemp -> name != NULL) {
			c = NULL;
			for (c = &table -> hash[h]; c; c = c -> next) {
				if ((c -> name != NULL) && !strcmp (c -> name, ptemp -> name)) {
					found = 1;
					break;
				}
			}
			if (found) {
				if (ptemp -> name != NULL) {
					kmem_free (ptemp -> name, ptemp -> name_len);
					ptemp -> name = NULL;
					ptemp -> name_len = 0;

					if (table -> values > 0)
						table -> values--;
				}

				ptemp -> val = NULL;

			} else {
				c = NULL;
				for (c = &table -> hash[h]; c; c = c -> next) {
					if (c -> name == NULL)
						break;
				}
				if (c != NULL) {
					c -> name = ptemp -> name;
					ptemp -> name = NULL;

					c -> name_len = ptemp -> name_len;
					ptemp -> name_len = 0;

					c -> val = ptemp -> val;
					ptemp -> val = NULL;
				} else {
					allocated = sizeof (hash_entry);
					ntemp = (hash_entry *) kmem_alloc (allocated, wait);

					if (ntemp == NULL) {
						cmn_err (CE_WARN,
    							"hash_rehash_at_index: unable to allocate for new HASH entry");

						if (ptemp -> name != NULL) {
							kmem_free (ptemp -> name, ptemp -> name_len);
							ptemp -> name = NULL;
							ptemp -> name_len = 0;

							if (table -> values > 0)
								table -> values--;
						}

						ptemp -> val = NULL;
					} else {
						bzero (ntemp, allocated);
						ntemp -> allocated = allocated;
						ntemp -> is_allocated = 1;

						ntemp -> name = ptemp -> name;
						ptemp -> name = NULL;

						ntemp -> name_len = ptemp -> name_len;
						ptemp -> name_len = 0;

						ntemp -> val = ptemp -> val;
						ptemp -> val = NULL;

						ntemp -> next = NULL;

						cn = NULL;
						for (cn = &table -> hash[h]; cn; cn = cn -> next)
							if (cn -> next == NULL)
								break;

						if (cn == NULL) {
							cmn_err (CE_WARN,
    								"hash_rehash_at_index: unable to find last HASH entry in the bucket");
							if (ntemp -> name != NULL) {
								kmem_free (ntemp -> name, ntemp -> name_len);
								ntemp -> name = NULL;
								ntemp -> name_len = 0;

								if (table -> values > 0)
									table -> values--;
							}
							ntemp -> val = NULL;

							kmem_free (ntemp, ntemp -> allocated);
							ntemp = NULL;

						} else {
							cn -> next = ntemp;
						}

						ntemp = NULL;
					}
				}
			}
		}
	}

	if (p -> is_allocated) {
	    cn = NULL;
	    for (cn = &table -> hash[old_h]; cn && cn -> next; cn = cn -> next)
		if (cn -> next == p)
		    break;
	    cn -> next = pn;

	    kmem_free (p, p -> allocated);
	    p = NULL;
	
	    p = pn;
	    continue;
	}

	p = pn;
    }

    return 1;
}

int hash_rehash (hash_table *table, unsigned long old_size, int wait)
{
    unsigned long i;

    for (i = 0; i < old_size; i++) {
	    hash_rehash_at_index (table, i, wait);
    }
    return 0;
}

hash_entry *hash_new_item (hash_entry *exist_hash, char *name, uint16_t name_len, void *value, int wait)
{
    hash_entry *new_hash = NULL;
    int was_allocated = 0;
    int allocated;

    if ((name == NULL) || (name_len == 0)) {
	cmn_err (CE_WARN,
		"hash_new_item: invalid parameters");
	return NULL;
    }

    if (exist_hash == NULL) {
	allocated = sizeof (hash_entry);
	new_hash = (hash_entry *) kmem_alloc (allocated, wait);
	if (new_hash == NULL) {
	    cmn_err (CE_WARN,
		    "hash_new_item: unable to allocate for new HASH entry");
	    return NULL;
	}
	bzero (new_hash, allocated);

	was_allocated = 1;
	new_hash -> is_allocated = 1;
	new_hash -> allocated = allocated;
	new_hash -> next = NULL;
	new_hash -> val = NULL;
	new_hash -> name = NULL;
	new_hash -> name_len = 0;

    } else {
	new_hash = exist_hash;
    }

    allocated = name_len + 1;
    new_hash -> name = (char *) kmem_alloc (allocated, wait);
    if (new_hash -> name == NULL) {
	cmn_err (CE_WARN,
		"hash_new_item: unable to allocate for new HASH string");

	if (was_allocated) {
	    kmem_free (new_hash, new_hash -> allocated);
	    new_hash = NULL;
	}
	return NULL;
    }
    bzero (new_hash -> name, allocated);
    new_hash -> name_len = allocated;
    bcopy (name, new_hash -> name, name_len);

    new_hash -> val = value;

    return new_hash;
}

int hash_delete_at_index (hash_table *table, unsigned long ind)
{
    hash_entry *next, *curr;

    next = NULL;
    curr = NULL;

    if ((table == NULL) || (table -> hash == NULL))
	return 0;

    curr = &table -> hash[ind];

    if (curr == NULL)
	return 0;

    while (curr != NULL) {
        next = curr -> next;

	if (curr -> name != NULL) {
	    kmem_free (curr -> name, curr -> name_len);
	    curr -> name = NULL;
	    curr -> name_len = 0;

	    if (table -> values > 0)
		table -> values--;
	}
	curr -> val = NULL;
	curr -> next = NULL;

	if (curr -> is_allocated) {
	    kmem_free (curr, curr -> allocated);
	    curr = NULL;
	}
	curr = next;
    }

    return 1;
}

int hash_add_item (hash_table **table, char *name, uint16_t name_len, void *value, int wait)
{
    hash_entry *n, *p, *c;
    hash_table *t;
    int allocated;
    unsigned long h, i, buckets_until_rehash;

    if ((table == NULL) || (name == NULL) || (name_len == 0)) {
	cmn_err (CE_WARN,
		"hash_add_item: invalid parameters");
	return 0;
    }
    
    if (*table == NULL) {
	allocated = sizeof (hash_table);
	t = (hash_table *) kmem_alloc (allocated, wait);
	if (t == NULL) {
	    cmn_err (CE_WARN,
		    "hash_add_item: unable to allocate for new HASH table");
	    return 0;
	}
	bzero (t, allocated);
	t -> allocated = allocated;

	allocated = sizeof (hash_entry);
	n = (hash_entry *) kmem_alloc (allocated, wait);
	if (n == NULL) {
	    kmem_free (t, t -> allocated);
	    t = NULL;
	    return 0;
	}
	bzero (n, allocated);
	n -> allocated = allocated;
	n -> is_allocated  = 0;

	n -> val = NULL;
	n -> name = NULL;
	n -> name_len = 0;
	n -> next = NULL;

	if (hash_new_item (n, name, name_len, value, wait) == NULL) {
	    kmem_free (n, n -> allocated);
	    n = NULL;
	    kmem_free (t, t -> allocated);
	    t = NULL;
	    return 0;
	}

	t -> hash = n;
	n = NULL;
	t -> values = 1;
	t -> buckets = 1;
	
	*table = t;
	t = NULL;

	return 1;
    } else {
	t = *table;
	if ((t -> values >= t -> buckets) &&
	    (HASH_TABLE_GROW_STEP * t -> buckets <= HASH_TABLE_MAX_SIZE)) {
	    allocated = (HASH_TABLE_GROW_STEP * t -> buckets) * sizeof (hash_entry);
	    n = (hash_entry *) kmem_alloc (allocated, wait);
	    if (n == NULL) {
		cmn_err (CE_WARN,
			"hash_add_item: unable to reallocate for new HASH entries");
		return 0;
	    }
	    bzero (n, allocated);
	    for (i = 0; i < t -> buckets; i++) {
		n[i].allocated = 0;
		n[i].is_allocated = 0;
		n[i].val = t -> hash[i].val;
		n[i].name = t -> hash[i].name;
		n[i].name_len = t -> hash[i].name_len;
		n[i].next = t -> hash[i].next;
	    }
	    n[0].allocated = allocated;

	    kmem_free (t -> hash, t -> hash -> allocated);
	    t -> hash = n;
	    n = NULL;

	    for (i = t -> buckets; i < t -> buckets * HASH_TABLE_GROW_STEP; i++) {
		t -> hash[i].allocated = 0;
		t -> hash[i].is_allocated = 0;
		t -> hash[i].val = NULL;
		t -> hash[i].name = NULL;
		t -> hash[i].name_len = 0;
		t -> hash[i].next = NULL;
	    }
	    buckets_until_rehash = t -> buckets;

	    t -> buckets *= HASH_TABLE_GROW_STEP;

	    cmn_err (CE_NOTE,
		    "Rearranging HASH table of %lu entries up to %lu buckets", t -> values, t -> buckets);
	    hash_rehash (t, buckets_until_rehash, wait);
	}
    }
    
    h = hash (name, t -> buckets);

    n = NULL;
    for (n = &t -> hash[h]; n; n = n -> next) {
	if ((n -> name != NULL) && !strcmp (n -> name, name)) {
	    return 0;
	}
    }
    
    n = NULL;
    p = NULL;
    for (n = &t -> hash[h]; n; n = n -> next) {
	if (n -> name == NULL) {
	    break;
	}
	p = n;
    }

    if ((n != NULL) && (n -> name == NULL)) {
	if (hash_new_item (n, name, name_len, value, wait) == NULL)
	    return 0;
    } else {
	if (p == NULL)
	    return 0;
	c = hash_new_item ((hash_entry *)0, name, name_len, value, wait);
	if (c == NULL)
	    return 0;
	p -> next = c;
	c = NULL;
    }
    t -> values++;

    return 1;
}

hash_entry *hash_lookup (hash_table *table, char *name, uint16_t name_len)
{
    hash_entry *p;
    unsigned long h;

    if ((table == NULL) || (table -> hash == NULL) ||
	(name == NULL) || (name_len == 0))
	return NULL;

    h = hash (name, table -> buckets);

    for (p = &table -> hash[h]; p; p = p -> next) {
	if ((p -> name != NULL) && !strcmp (p -> name,name))
	    return p;
    }
    return NULL;
}

int hash_remove_item (hash_table *table, char *name)
{
    hash_entry *next, *curr;
    unsigned long h;
    int found = 0;

    next = NULL;
    curr = NULL;

    if ((table == NULL) || (table -> hash == NULL) || (name == NULL))
	return 0;

    h = hash (name, table -> buckets);

    curr = &table -> hash[h];

    if (curr == NULL)
	return 0;

    while (curr != NULL) {
        next = curr -> next;

	if (curr -> name != NULL) {
	    if (!strcmp (curr -> name, name)) {
		kmem_free (curr -> name, curr -> name_len);
		curr -> name = NULL;
		curr -> name_len = 0;

		curr -> val = NULL;

		if (table -> values > 0)
		    table -> values--;

		found = 1;
		break;
	    }
	}

	curr = next;
    }

    return (found == 1);
}

int hash_free_table (hash_table **table, unsigned long *result_allocated, unsigned long *result_values)
{
    hash_table *t;
    unsigned long i;
    unsigned long buckets_until_rehash, old_values, last_values, last_allocated;

    if ((table == NULL) || (*table == NULL))
	return 0;

    t = *table;

    buckets_until_rehash = t -> buckets;
    old_values = t -> values;

    if (t -> hash != NULL) {
	for (i = 0; i < t -> buckets; i++) {
	    hash_delete_at_index (t, i);
	}
	kmem_free (t -> hash, t -> hash -> allocated);
	t -> hash = NULL;
	t -> buckets = 0;
    }

    last_values = t -> values;
    last_allocated = t -> buckets;
    
    kmem_free (t, t -> allocated);
    t = NULL;

    *table = NULL;

    if (result_allocated != NULL)
	    *result_allocated = last_allocated;

    if (result_values != NULL)
	    *result_values = last_values;

    return 1;
}
