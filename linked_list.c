struct node_t
{
	void *item;
	struct node* prev;
	struct node* next;
};
typedef struct node_t* node_ptr;
typedef struct data_t* data_ptr;
node_ptr head = (node_ptr)malloc(sizeof(struct node_t));
node_ptr curr = head;
for (int i = 0; i < count; ++i)
{
	pdata data = (data_ptr)malloc(sizeof(struct data_t));
	if (!data) {/* memory error */}
	curr->next = (node_ptr)malloc(sizeof(struct node_t));
	if (!curr->next) {/* memory error */}
	curr->next->item = pdata;
	curr->next->prev = curr;
	curr = curr->next;
}
curr->next = head; // make it a circular list


// include/types.h
struct list_head {
	struct list_head *next, *prev;
};

struct kernel_list
{
	...... // as many data fields as you want
	struct list_head entry;
	...... // as many data fields as you want
	/* as many lists as you want */
	struct list_head another_entry
	...... // as many data fields as you want
};
typedef struct kernel_list klist;
klist head;
INIT_LIST_HEAD(&(head.entry));
// LIST_HEAD(head);
klist* curr;
for (int i = 0; i < count; ++i)
{	
	curr = (klist *)malloc(sizeof(klist));
	/* init data values in curr */
	......
	/* stack style insertion */
	list_add(&(curr->entry), &(head.entry));
	/* queue style insertion */
	list_add_tail(&(curr->entry), &(head.entry));
}

list_head* pos;
klist* curr;
/* iterate over a list */
list_for_each(pos, &(head.entry))
{
	curr = list_entry(pos, struct kernel_list, entry);
	/* read operations on curr */
	......
}

klist* curr;
/* iterate over a list */
list_for_each_entry(curr, &(head.entry), entry)
{
	/* read operations on curr directly*/
}

list_head* pos;
list_head* tmp;
struct kernel_list* curr;
/* iterate safe against removal of item */
list_for_each_safe(pos, tmp, &(head.entry))
{
	curr = list_entry(pos, struct kernel_list, entry);
	list_del(pos);
	free(curr)
}

/**
 * list_entry - get the struct for this entry
 * @ptr:	the &struct list_head pointer.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_struct within the struct.
 */
#define list_entry(ptr, type, member) container_of(ptr, type, member)

// include/linux/kernel.h
/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:	the pointer to the member.
 * @type:	the type of the container struct this is embedded in.
 * @member:	the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})

#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

list_head* pos;
list_head* tmp;
klist* curr;
curr = list_entry(pos, klist, entry) =>
curr = ({
	const typeof(((struct kernel_list *)0)->entry) 
										*__mptr = (pos);
	(type *)((char *)__mptr - 
		offsetof(struct kernel_list *, entry));
})








