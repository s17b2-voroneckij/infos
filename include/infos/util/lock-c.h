struct mutex {
    volatile unsigned long _locked;
	void *_owner;
};

void mutex_lock(struct mutex*);
void mutex_unlock(struct mutex*);
