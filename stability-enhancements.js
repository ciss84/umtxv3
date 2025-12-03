// @ts-check
// ============================================
// STABILITY-ENHANCEMENTS.JS
// Améliorations de stabilité pour PS5 Exploit
// À charger AVANT umtx2.js et main.js
// ============================================

(function() {
    'use strict';

    // ============================================
    // 1. GESTIONNAIRE DE MÉMOIRE OPTIMISÉ
    // ============================================
    
    class MemoryStabilizer {
        constructor() {
            this.allocations = new Map();
            this.gcPrevention = [];
            this.stats = {
                totalAllocated: 0,
                activeAllocations: 0,
                peakMemory: 0
            };
        }

        /**
         * Alloue de la mémoire et garde une référence pour éviter le GC
         */
        allocStable(size, keepAlive = true) {
            const buffer = new ArrayBuffer(size);
            const id = `alloc_${Date.now()}_${Math.random()}`;
            
            this.allocations.set(id, {
                buffer,
                size,
                timestamp: Date.now()
            });
            
            if (keepAlive) {
                this.gcPrevention.push(buffer);
            }
            
            this.stats.totalAllocated += size;
            this.stats.activeAllocations++;
            this.stats.peakMemory = Math.max(this.stats.peakMemory, this.stats.totalAllocated);
            
            return { id, buffer };
        }

        /**
         * Libère une allocation
         */
        free(id) {
            const alloc = this.allocations.get(id);
            if (alloc) {
                this.stats.totalAllocated -= alloc.size;
                this.stats.activeAllocations--;
                this.allocations.delete(id);
                
                // Retirer de gcPrevention
                const idx = this.gcPrevention.indexOf(alloc.buffer);
                if (idx !== -1) {
                    this.gcPrevention.splice(idx, 1);
                }
                return true;
            }
            return false;
        }

        /**
         * Force un nettoyage léger
         */
        cleanup() {
            // Garder seulement les allocations récentes (< 30 secondes)
            const now = Date.now();
            const oldAllocs = [];
            
            for (const [id, alloc] of this.allocations) {
                if (now - alloc.timestamp > 30000) {
                    oldAllocs.push(id);
                }
            }
            
            oldAllocs.forEach(id => this.free(id));
        }

        getStats() {
            return { ...this.stats };
        }
    }

    window.memoryStabilizer = new MemoryStabilizer();

    // ============================================
    // 2. DÉTECTEUR DE TIMING ET RACE CONDITIONS
    // ============================================
    
    class TimingOptimizer {
        constructor() {
            this.measurements = [];
            this.optimalDelays = {
                raceSetup: 5,
                threadSync: 1,
                memoryAccess: 10,
                kstackReclaim: 15
            };
        }

        /**
         * Mesure le temps d'une opération et ajuste les délais
         */
        async measure(name, fn) {
            const start = performance.now();
            try {
                const result = await fn();
                const duration = performance.now() - start;
                
                this.measurements.push({
                    name,
                    duration,
                    success: true,
                    timestamp: Date.now()
                });
                
                // Ajuster les délais basés sur les mesures
                this._adjustDelays(name, duration);
                
                return result;
            } catch (error) {
                const duration = performance.now() - start;
                this.measurements.push({
                    name,
                    duration,
                    success: false,
                    error: error.message,
                    timestamp: Date.now()
                });
                throw error;
            }
        }

        _adjustDelays(name, duration) {
            // Si l'opération prend plus de temps, augmenter les délais
            if (name in this.optimalDelays) {
                const currentDelay = this.optimalDelays[name];
                if (duration > 50) { // Si > 50ms, augmenter
                    this.optimalDelays[name] = Math.min(currentDelay + 2, 50);
                } else if (duration < 10) { // Si < 10ms, diminuer
                    this.optimalDelays[name] = Math.max(currentDelay - 1, 1);
                }
            }
        }

        getOptimalDelay(operation) {
            return this.optimalDelays[operation] || 10;
        }

        getStats() {
            const successRate = this.measurements.filter(m => m.success).length / 
                              Math.max(this.measurements.length, 1);
            
            return {
                totalMeasurements: this.measurements.length,
                successRate: (successRate * 100).toFixed(2) + '%',
                optimalDelays: { ...this.optimalDelays }
            };
        }
    }

    window.timingOptimizer = new TimingOptimizer();

    // ============================================
    // 3. GESTIONNAIRE DE THREADS SÉCURISÉ
    // ============================================
    
    class ThreadSafetyManager {
        constructor() {
            this.activeThreads = new Set();
            this.threadStates = new Map();
            this.locks = new Map();
        }

        /**
         * Enregistre un thread
         */
        registerThread(name, priority = 0) {
            this.activeThreads.add(name);
            this.threadStates.set(name, {
                state: 'ready',
                priority,
                startTime: Date.now(),
                operations: 0
            });
        }

        /**
         * Met à jour l'état d'un thread
         */
        updateThreadState(name, state) {
            const thread = this.threadStates.get(name);
            if (thread) {
                thread.state = state;
                thread.operations++;
            }
        }

        /**
         * Vérifie si tous les threads sont dans un état attendu
         */
        async waitForThreadStates(expectedStates, timeout = 5000) {
            const start = Date.now();
            
            while (Date.now() - start < timeout) {
                let allMatch = true;
                
                for (const [name, thread] of this.threadStates) {
                    if (!expectedStates.includes(thread.state)) {
                        allMatch = false;
                        break;
                    }
                }
                
                if (allMatch) return true;
                
                await new Promise(resolve => setTimeout(resolve, 1));
            }
            
            throw new Error(`Timeout waiting for thread states: ${expectedStates}`);
        }

        /**
         * Acquiert un lock simple
         */
        async acquireLock(lockName, timeout = 5000) {
            const start = Date.now();
            
            while (this.locks.get(lockName)) {
                if (Date.now() - start > timeout) {
                    throw new Error(`Lock timeout: ${lockName}`);
                }
                await new Promise(resolve => setTimeout(resolve, 1));
            }
            
            this.locks.set(lockName, true);
        }

        /**
         * Libère un lock
         */
        releaseLock(lockName) {
            this.locks.delete(lockName);
        }

        cleanup() {
            this.activeThreads.clear();
            this.threadStates.clear();
            this.locks.clear();
        }
    }

    window.threadSafetyManager = new ThreadSafetyManager();

    // ============================================
    // 4. VÉRIFICATEUR D'ÉTAT SYSTÈME
    // ============================================
    
    class SystemHealthChecker {
        constructor() {
            this.checks = [];
            this.isHealthy = true;
        }

        /**
         * Vérifie l'état de la mémoire
         */
        checkMemory() {
            try {
                // Test d'allocation simple
                const test = new Uint8Array(1024 * 1024); // 1MB
                test[0] = 0x42;
                return test[0] === 0x42;
            } catch (e) {
                return false;
            }
        }

        /**
         * Vérifie l'état du worker
         */
        async checkWorker() {
            try {
                if (typeof Worker !== 'undefined') {
                    // Le worker existe
                    return true;
                }
                return false;
            } catch (e) {
                return false;
            }
        }

        /**
         * Exécute tous les checks
         */
        async runHealthCheck() {
            const results = {
                memory: this.checkMemory(),
                worker: await this.checkWorker(),
                timestamp: new Date().toISOString()
            };

            this.checks.push(results);
            this.isHealthy = results.memory && results.worker;

            return {
                healthy: this.isHealthy,
                results
            };
        }

        getHistory() {
            return [...this.checks];
        }
    }

    window.systemHealthChecker = new SystemHealthChecker();

    // ============================================
    // 5. STABILISATEUR DE RACE CONDITIONS
    // ============================================
    
    class RaceStabilizer {
        constructor() {
            this.raceAttempts = [];
            this.successRate = 0;
            this.optimalTiming = {
                setupDelay: 5,
                syncDelay: 1,
                retryDelay: 10
            };
        }

        /**
         * Enregistre une tentative de race
         */
        recordAttempt(success, duration, metadata = {}) {
            this.raceAttempts.push({
                success,
                duration,
                metadata,
                timestamp: Date.now()
            });

            // Calculer le taux de réussite
            const recentAttempts = this.raceAttempts.slice(-20); // 20 dernières
            const successes = recentAttempts.filter(a => a.success).length;
            this.successRate = successes / recentAttempts.length;

            // Ajuster les timings si taux de réussite < 50%
            if (this.successRate < 0.5 && this.raceAttempts.length > 10) {
                this.optimalTiming.setupDelay += 2;
                this.optimalTiming.syncDelay += 1;
            }
        }

        /**
         * Obtient le délai optimal pour la prochaine tentative
         */
        getOptimalSetupDelay() {
            return this.optimalTiming.setupDelay;
        }

        getOptimalSyncDelay() {
            return this.optimalTiming.syncDelay;
        }

        /**
         * Réinitialise après succès
         */
        reset() {
            // Garder les timings optimaux mais vider l'historique
            this.raceAttempts = [];
            this.successRate = 0;
        }

        getStats() {
            return {
                totalAttempts: this.raceAttempts.length,
                successRate: (this.successRate * 100).toFixed(2) + '%',
                optimalTiming: { ...this.optimalTiming },
                recentAttempts: this.raceAttempts.slice(-10)
            };
        }
    }

    window.raceStabilizer = new RaceStabilizer();

    // ============================================
    // 6. UTILITAIRES DE STABILITÉ
    // ============================================
    
    const StabilityUtils = {
        /**
         * Sleep avec timing précis
         */
        async preciseSleep(ms) {
            const start = performance.now();
            
            // Utiliser setTimeout pour la majorité du temps
            if (ms > 5) {
                await new Promise(resolve => setTimeout(resolve, ms - 5));
            }
            
            // Busy-wait pour les dernières ms pour plus de précision
            while (performance.now() - start < ms) {
                // Busy wait
            }
        },

        /**
         * Yield CPU de manière optimisée
         */
        async optimizedYield() {
            // Yield court pour éviter de perdre trop de temps CPU
            await new Promise(resolve => setTimeout(resolve, 0));
        },

        /**
         * Attend avec condition et timeout
         */
        async waitForCondition(checkFn, timeout = 5000, interval = 1) {
            const start = Date.now();
            
            while (Date.now() - start < timeout) {
                if (await checkFn()) {
                    return true;
                }
                await this.optimizedYield();
                if (interval > 0) {
                    await new Promise(resolve => setTimeout(resolve, interval));
                }
            }
            
            throw new Error('Condition timeout');
        },

        /**
         * Exécute avec retry et backoff
         */
        async retryWithBackoff(fn, maxAttempts = 3, initialDelay = 100) {
            let lastError;
            
            for (let i = 0; i < maxAttempts; i++) {
                try {
                    return await fn();
                } catch (error) {
                    lastError = error;
                    if (i < maxAttempts - 1) {
                        const delay = initialDelay * Math.pow(2, i);
                        await new Promise(resolve => setTimeout(resolve, delay));
                    }
                }
            }
            
            throw lastError;
        }
    };

    window.StabilityUtils = StabilityUtils;

    // ============================================
    // 7. MONITEUR GLOBAL DE STABILITÉ
    // ============================================
    
    class StabilityMonitor {
        constructor() {
            this.startTime = Date.now();
            this.events = [];
            this.alerts = [];
        }

        logEvent(type, message, data = {}) {
            const event = {
                type,
                message,
                data,
                timestamp: Date.now(),
                elapsed: Date.now() - this.startTime
            };
            
            this.events.push(event);
            
            // Limiter l'historique
            if (this.events.length > 1000) {
                this.events.shift();
            }
        }

        addAlert(severity, message) {
            this.alerts.push({
                severity, // 'low', 'medium', 'high', 'critical'
                message,
                timestamp: Date.now()
            });
        }

        getReport() {
            const now = Date.now();
            const uptime = now - this.startTime;
            
            return {
                uptime: uptime,
                uptimeFormatted: this._formatTime(uptime),
                totalEvents: this.events.length,
                alerts: this.alerts.length,
                criticalAlerts: this.alerts.filter(a => a.severity === 'critical').length,
                recentEvents: this.events.slice(-20),
                memoryStats: window.memoryStabilizer?.getStats(),
                timingStats: window.timingOptimizer?.getStats(),
                raceStats: window.raceStabilizer?.getStats()
            };
        }

        _formatTime(ms) {
            const seconds = Math.floor(ms / 1000);
            const minutes = Math.floor(seconds / 60);
            const hours = Math.floor(minutes / 60);
            
            if (hours > 0) return `${hours}h ${minutes % 60}m`;
            if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
            return `${seconds}s`;
        }

        clear() {
            this.events = [];
            this.alerts = [];
        }
    }

    window.stabilityMonitor = new StabilityMonitor();

    // ============================================
    // 8. AUTO-INITIALISATION
    // ============================================
    
    console.log('[Stability] Enhancements loaded successfully');
    
    // Effectuer un health check initial
    window.systemHealthChecker.runHealthCheck().then(result => {
        if (result.healthy) {
            console.log('[Stability] System health check: OK');
        } else {
            console.warn('[Stability] System health check: WARNING', result.results);
        }
    });

})();