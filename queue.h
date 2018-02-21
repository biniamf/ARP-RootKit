#ifndef QUEUE_H

struct pid_list_node {
	pid_t nr;
	struct task_struct *task;
	struct pid_list_node *next;
};

struct read_queue {
	pid_t pid;
	char *ubuf;
	off_t from, to;
	struct read_queue *next;
};

struct fid_list_node {
	id_t fake, real;
	struct fid_list_node *next;
};

extern void fid_list_create(void);
extern void fid_list_destroy(void);
extern void fid_list_add(id_t fake, id_t real);
extern void fid_list_del(id_t fake, id_t real);
extern void fid_list_del_real(id_t real);
extern id_t fid_list_real_to_fake(id_t real);
extern id_t fid_list_fake_to_real(id_t fake);

extern void pid_list_create(void);
extern void pid_list_destroy(void);
extern void pid_list_push(pid_t nr);
extern pid_t pid_list_pop(pid_t nr);
extern struct pid_list_node *pid_list_find(pid_t nr);
extern void pid_list_test(void);

extern void create_read_list(void);
extern void destroy_read_list(void);
extern void create_read_queue(pid_t pid, char *ubuf, off_t from, off_t to);
extern struct read_queue *get_read_queue(pid_t pid);
extern void update_read_queue(pid_t pid, char *ubuf, off_t from, off_t to);
extern void destroy_read_queue(pid_t pid);

extern struct read_queue *read_list_head;
extern struct read_queue *read_list_tail;
extern struct pid_list_node *pid_list_head;
extern struct pid_list_node *pid_list_tail;
extern struct fid_list_node *fid_list_head;
extern struct fid_list_node *fid_list_tail;

#define QUEUE_H
#endif
